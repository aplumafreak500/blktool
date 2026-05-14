/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

/* ENCR (hkrpg) */
/* May also be used by other mhy and non-mhy Unity games */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "lz4.h"
#include "lz4hc.h"
#include "encr.h"

/*
Structure: (__attribute__((packed)); big endian)
	0	uint8_t[5]	Magic b"ENCR\x00"
	5	uint64_t	File size
	d	uint32_t	Compressed header size
	11	uint32_t	Decompressed header size
	15	uint32_t	Flags & compression type
	19	uint8_t[]	Compressed header data
	..	uint8_t[]	Compressed block data

Flags:
	0x3f	Compression Type
		0	Store
		1	lzma
		2	lz4
			OR Uncompressed with mr0k encryption (Extension of blktool)
		3	lz4hc
		4	lzham (modified lzha?)
		5	lz4mr0k (lz4/lz4hc with mr0k encryption)
			OR zstd
		6	"Oodle" (early HSR variant?)
		7	"Oodle" with mr0k encryption
		8	(Unknown)
		9	"Oodle" (unencrypted?)
	0x40	Block and cab info are stored together
	0x80	Block info is at EOF
	0x100	"Old Web Plugin Compatibility"?
	0x200	"Block info needs padding at the start"?
	0x400	UnityCN encrypted (hm?)
	0x1000	UnityCN encrypted (hm?) (variant 2?)
*/

/* big endian */
typedef struct {
	uint32_t block_dec_size;
	uint32_t block_cmp_size;
	uint16_t block_flags;
} encr_blk_ent_t;

typedef struct {
	uint64_t cab_offset;
	uint64_t cab_size;
	uint32_t cab_flags;
	char cab_name[];
} encr_cab_ent_t;

typedef struct {
	char name[256];
	uint64_t blk_off;
	uint64_t blk_sz;
	uint32_t flags;
} __attribute__((packed)) encr_cab_serialized_t;

typedef struct {
	uint32_t cab_count;
	uint32_t flags;
} __attribute__((packed)) encr_pack_serialized_t;

int extract_encr(const uint8_t* buf, const char* filename, const uint8_t** _next_encr) {
	if (buf == NULL || filename == NULL) {
		return -1;
	}
	FILE* file;
	static char filenameBuf[1024];
	uint64_t magic = ((uint64_t) be32toh(((uint32_t*) buf)[0]) << 8) | ((uint8_t*) buf)[4];
	int ret;
	if (magic != 0x454e435200) {
		fprintf(stderr, "Bad magic 0x%08lx (expected 0x%08lx)\n", magic, 0x454e435200);
		return -1;
	}
	const uint8_t* buf_cpos = buf + 5;
	uint64_t size = be64toh(((uint64_t*) buf_cpos)[0]);
	uint32_t hdr_size_cmp = be32toh(((uint32_t*) buf_cpos)[2]);
	uint32_t hdr_size_dec = be32toh(((uint32_t*) buf_cpos)[3]);
	uint32_t flags = be32toh(((uint32_t*) buf_cpos)[4]);
	if (!(((flags & 0x3f) == 0) || ((flags & 0x3f) == 2) || ((flags & 0x3f) == 3))) {
		fprintf(stderr, "Error: Only ENCR files compressed with lz4 or lz4hc, or uncompressed, are supported at the moment. (ctype = %d)\n", flags & 0x3f);
		return -1;
	}
	const uint8_t* next_encr = buf + size;
	if (_next_encr != NULL) *_next_encr = next_encr;
	buf_cpos += 20;
	// TODO: flag 0x80 set means header is at the end, after the compressed blocks
	uint8_t* hdr_buf;
	if ((flags & 0x3f) == 0) {
		/* TODO: malloc it anyways and then memcpy it there to make cleanup code cleaner? */
		hdr_buf = (uint8_t*) buf_cpos;
	}
	else {
		hdr_buf = malloc(hdr_size_dec);
		if (hdr_buf == NULL) {
			fprintf(stderr, "Can't allocate decompression buffer (header)\n");
			return -1;
		}
		ret = LZ4_decompress_safe((const char*) buf_cpos, (char*) hdr_buf, hdr_size_cmp, hdr_size_dec);
		if (ret < 0) {
			fprintf(stderr, "LZ4 decompress error %d when decoding header\n", -ret);
			free(hdr_buf);
			return ret;
		}
	}
#if 1
	snprintf(filenameBuf, 1024, "%s.hdr_decomp", filename);
	file = fopen(filenameBuf, "wb");
	if (file == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	fwrite(hdr_buf, hdr_size_dec, 1, file);
	fclose(file);
	file = NULL;
#endif
	uint8_t* hdr_buf_cpos = hdr_buf;
	uint32_t block_count = be32toh(((uint32_t*) hdr_buf_cpos)[0]);
	// TODO: flag 0x40 clear means this is located elsewhere
	hdr_buf_cpos += (block_count * 10) + 4;
	uint32_t cab_count = be32toh(((uint32_t*) hdr_buf_cpos)[0]);
	encr_pack_serialized_t pack_meta;
	pack_meta.cab_count = ((uint32_t*) hdr_buf_cpos)[0];
	pack_meta.flags = ((uint32_t*) buf_cpos)[4];
	snprintf(filenameBuf, 1024, "%s.hdr", filename);
	file = fopen(filenameBuf, "wb");
	if (file == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	fwrite(&pack_meta, sizeof(encr_pack_serialized_t), 1, file);
	fclose(file);
	file = NULL;
	encr_cab_ent_t* cur_cab = (encr_cab_ent_t*)(hdr_buf_cpos + 4);
	encr_cab_serialized_t cab_meta[cab_count];
	uint8_t* cur_cab_off = (uint8_t*) cur_cab;
	unsigned int i;
	size_t dec_block_size = 0;
	for (i = 0; i < cab_count; i++) {
#ifndef NDEBUG
		memset(cab_meta[i].name, 0, 256);
#endif
		strncpy(cab_meta[i].name, cur_cab->cab_name, 256);
		cab_meta[i].blk_off = be64toh(cur_cab->cab_offset);
		cab_meta[i].blk_sz = be64toh(cur_cab->cab_size);
		cab_meta[i].flags = cur_cab->cab_flags;
		fprintf(stderr, "cab%d name: %s offset 0x%08lx blk_offset 0x%08lx blk_size: 0x%08lx flag 0x%08x\n", i, cab_meta[i].name, (unsigned long) cur_cab, cab_meta[i].blk_off, cab_meta[i].blk_sz, be32toh(cab_meta[i].flags));
		dec_block_size += cab_meta[i].blk_sz;
		snprintf(filenameBuf, 1024, "%s.cab%d.hdr", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(hdr_buf);
			return -1;
		}
		fwrite(&(cab_meta[i]), sizeof(encr_cab_serialized_t), 1, file);
		fclose(file);
		file = NULL;
		cur_cab_off = (uint8_t*) cur_cab + strlen(cur_cab->cab_name) + 21;
		cur_cab = (encr_cab_ent_t*) cur_cab_off;
	}
	uint8_t* blk_data_buf = malloc(dec_block_size);
	if (blk_data_buf == NULL) {
		fprintf(stderr, "Can't allocate decompression buffer (blocks)\n");
		free(hdr_buf);
		return -1;
	}
	uint64_t data_off = hdr_size_cmp + 25;
	uint64_t dec_data_off = 0;
	size_t total_sz = 0;
	encr_blk_ent_t* cur_block = (encr_blk_ent_t*)(hdr_buf + 4);
	uint32_t blk_cmp_sz, blk_dec_sz;
	for (i = 0; i < block_count; i++) {
		blk_dec_sz = be32toh(cur_block->block_dec_size);
		blk_cmp_sz = be32toh(cur_block->block_cmp_size);
		flags = be16toh(cur_block->block_flags);
		fprintf(stderr, "blk %d offset 0x%08lx cmpSz 0x%08x decSz 0x%08x flags 0x%x\n", i, (unsigned long) cur_block, blk_cmp_sz, blk_dec_sz, flags);
#if 1
		snprintf(filenameBuf, 1024, "%s.blk%d", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(blk_data_buf);
			return -1;
		}
		fwrite((buf + data_off), blk_cmp_sz, 1, file);
		fclose(file);
		file = NULL;
#endif
#if 0
		if (!(((flags & 0x3f) == 0) || ((flags & 0x3f) == 2) || ((flags & 0x3f) == 3))) {
			fprintf(stderr, "Error: Only ENCR files compressed with lz4 or lz4hc, or uncompressed, are supported at the moment. (ctype = %d)\n", flags & 0x3f);
			free(hdr_buf);
			free(blk_data_buf);
			return -1;
		}
		uint32_t mr0k_magic = be32toh(*(uint32_t*)(buf + data_off));
		if (mr0k_magic == 0x6d72306b) {
			fprintf(stderr, "Error: mr0k-encrypted blocks are unsupported for now.\n");
			free(hdr_buf);
			free(blk_data_buf);
			return -1;
		}
#endif
		if (1/*(flags & 0x3f) == 0*/) {
			memcpy((blk_data_buf + dec_data_off), (buf + data_off), blk_cmp_sz);
		}
		else {
			ret = LZ4_decompress_safe((const char*) (buf + data_off), (char*) (blk_data_buf + dec_data_off), blk_cmp_sz, blk_dec_sz);
			if (ret < 0) {
				fprintf(stderr, "LZ4 decompress error %d when decoding data (blk %d)\n", -ret, i);
				free(hdr_buf);
				free(blk_data_buf);
				return -1;
			}
		}
		data_off += blk_cmp_sz;
		dec_data_off += blk_dec_sz;
		total_sz += blk_cmp_sz;
		cur_block = (encr_blk_ent_t*)((uint8_t*) cur_block + 10);
	}
	free(hdr_buf);
	FILE* outfp;
	for (i = 0; i < cab_count; i++) {
		snprintf(filenameBuf, 1024, "%s.cab%d", filename, i);
		outfp = fopen(filenameBuf, "wb");
		if (outfp == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(blk_data_buf);
			return -1;
		}
		fwrite(blk_data_buf + cab_meta[i].blk_off, cab_meta[i].blk_sz, 1, outfp);
		fclose(outfp);
	}
	fprintf(stderr, "total size of this encr 0x%08lx\n", total_sz);
	fprintf(stderr, "if present, the next one should be at 0x%08lx\n", (unsigned long) next_encr);
	free(blk_data_buf);
	return 0;
}
