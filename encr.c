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
#include <sys/random.h>
#include "lz4.h"
#include "lz4hc.h"
#include "mr0k.h"
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
	if (!(((flags & 0x3f) == 0) || ((flags & 0x3f) == 2) || ((flags & 0x3f) == 3) || ((flags & 0x3f) == 5))) {
		fprintf(stderr, "Error: Only ENCR files compressed with lz4 or lz4hc, or uncompressed, are supported at the moment. (ctype = %d)\n", flags & 0x3f);
		return -1;
	}
	const uint8_t* next_encr = buf + size;
	if (_next_encr != NULL) *_next_encr = next_encr;
	buf_cpos += 20;
	// TODO: flag 0x80 set means header is at the end, after the compressed blocks
	uint8_t* hdr_buf;
	uint32_t mr0k_magic = be32toh(*(uint32_t*) buf_cpos);
	if (mr0k_magic == 0x6d72306b) {
		mr0k_decrypt((uint8_t*) buf_cpos, hdr_size_cmp, 1);
		buf_cpos += 0x14;
		hdr_size_cmp -= 0x14;
	}
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
#if 0
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
	pack_meta.cab_count = htobe32(cab_count);
	pack_meta.flags = htobe32(flags);
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
	uint32_t blk_cmp_sz, blk_dec_sz, cmpr_data_sz, cmpr_data_off;
	for (i = 0; i < block_count; i++) {
		blk_dec_sz = be32toh(cur_block->block_dec_size);
		blk_cmp_sz = be32toh(cur_block->block_cmp_size);
		flags = be16toh(cur_block->block_flags);
		fprintf(stderr, "blk %d offset 0x%08lx cmpSz 0x%08x decSz 0x%08x flags 0x%x\n", i, (unsigned long) cur_block, blk_cmp_sz, blk_dec_sz, flags);
		snprintf(filenameBuf, 1024, "%s.blk%d.key", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(hdr_buf);
			return -1;
		}
		fwrite(&(cur_block->block_flags), 2, 1, file);
		if (!(((flags & 0x3f) == 0) || ((flags & 0x3f) == 2) || ((flags & 0x3f) == 3) || ((flags & 0x3f) == 5))) {
			fprintf(stderr, "Error: Only ENCR files compressed with lz4 or lz4hc, or uncompressed, are supported at the moment. (ctype = %d)\n", flags & 0x3f);
			free(hdr_buf);
			free(blk_data_buf);
			return -1;
		}
		cmpr_data_sz = blk_cmp_sz;
		cmpr_data_off = data_off;
		mr0k_magic = be32toh(*(uint32_t*)(buf + data_off));
		if (mr0k_magic == 0x6d72306b) {
			mr0k_decrypt((uint8_t*) (buf + data_off), blk_cmp_sz, 1);
			cmpr_data_off += 0x14;
			cmpr_data_sz -= 0x14;
			fwrite((buf + data_off + 4), 16, 1, file);
		}
		fclose(file);
		file = NULL;
		if ((flags & 0x3f) == 0) {
			memcpy((blk_data_buf + dec_data_off), (buf + cmpr_data_off), cmpr_data_sz);
		}
		else {
			ret = LZ4_decompress_safe((const char*) (buf + cmpr_data_off), (char*) (blk_data_buf + dec_data_off), cmpr_data_sz, blk_dec_sz);
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

int pack_encr(const char* in_filename, FILE* out_fp) {
	if (in_filename == NULL || out_fp == NULL) {
		return -1;
	}
	FILE* in_fp2;
	static char filenameBuf[1024];
	uint32_t cab_cnt, cab_blk_cnt, hdr_flags;
	uint32_t blk_cnt = 0;
	uint64_t cab_blk_off = 0;
	uint64_t cab_blk_sz, blk_sz, cmp_buf_off;
	size_t cmp_buf_sz;
	uint32_t header[2];
	snprintf(filenameBuf, 1024, "%s.hdr", in_filename);
	in_fp2 = fopen(filenameBuf, "rb");
	if (in_fp2 == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
#if 0
		return -1;
#else
		fprintf(stderr, "Assuming 1 cab file present, lz4hc compressed header\n");
		cab_cnt = 1;
		hdr_flags = 0x43;
#endif
	}
	else {
		fread(header, sizeof(uint32_t), 2, in_fp2);
		fclose(in_fp2);
		in_fp2 = NULL;
		cab_cnt = be32toh(header[0]);
		hdr_flags = be32toh(header[1]);
	}
	if (cab_cnt >= 256) cab_cnt = 256;
	encr_cab_serialized_t s_cab[cab_cnt];
	FILE* in_fp[cab_cnt];
	unsigned int i;
	for (i = 0; i < cab_cnt; i++) {
		snprintf(filenameBuf, 1024, "%s.cab%d", in_filename, i);
		in_fp[i] = fopen(filenameBuf, "rb");
		if (in_fp[i] == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			return -1;
		}
		fseek(in_fp[i], 0, SEEK_END);
		cab_blk_sz = ftell(in_fp[i]);
		fseek(in_fp[i], 0, SEEK_SET);
		// TODO start move outside the loop
		cab_blk_cnt = cab_blk_sz / 0x20000;
		if ((cab_blk_sz % 0x20000) != 0) {
			cab_blk_cnt++;
		}
		blk_cnt += cab_blk_cnt;
		// end
		snprintf(filenameBuf, 1024, "%s.cab%d.hdr", in_filename, i);
		in_fp2 = fopen(filenameBuf, "rb");
		if (in_fp2 != NULL) {
			fread(&s_cab[i], sizeof(encr_cab_serialized_t), 1, in_fp2);
			in_fp2 = NULL;
		}
		else {
#ifndef NDEBUG
			memset(&s_cab[i], 0, sizeof(s_cab[i]));
#endif
			uint64_t cab_name_buf[2];
			// TODO actually random, or an MD2/4/5 sum (and if so, of what)?
			getrandom(cab_name_buf, sizeof(uint64_t) * 2, 0);
			snprintf(s_cab[i].name, 256, "CAB-%016llx%016llx", (unsigned long long) htobe64(cab_name_buf[0]), (unsigned long long) htobe64(cab_name_buf[1]));
			s_cab[i].flags = 0;
		}
		s_cab[i].blk_off = cab_blk_off;
		s_cab[i].blk_sz = cab_blk_sz;
	}
	FILE* tmp_blk_fp;
	snprintf(filenameBuf, 1024, "%s.blocks", in_filename);
	tmp_blk_fp = fopen(filenameBuf, "wb+");
	if (tmp_blk_fp == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	uint8_t* dec_buf = malloc(0x20000);
	if (dec_buf == NULL) {
		fprintf(stderr, "Can't allocate block buffer\n");
		return -1;
	}
	uint8_t* cmp_buf = malloc(0x50000);
	if (cmp_buf == NULL) {
		fprintf(stderr, "Can't allocate block compression buffer\n");
		free(dec_buf);
		return -1;
	}
	ssize_t written = 0;
	uint8_t blk_key_buf[18];
	uint16_t blk_flags;
	const uint8_t* blk_key = (const uint8_t*) (&blk_key_buf[2]);
	ssize_t read;
	unsigned int j = 0;
	uint32_t blocks[blk_cnt][3]; // compressed, then decompressed sizes, then flags, for each block
	for (i = 0; i < blk_cnt; i++) {
		snprintf(filenameBuf, 1024, "%s.blk%d.key", in_filename, i);
		in_fp2 = fopen(filenameBuf, "rb");
		if (in_fp2 != NULL) {
			read = fread(blk_key_buf, 18, 1, in_fp2);
			fclose(in_fp2);
			in_fp2 = NULL;
			//blk_flags = *(uint16_t*) blk_key_buf;
			blk_flags = 0x3;
		}
		else {
			blk_flags = 0x3;
			read = 2;
		}
		if (s_cab[j].blk_sz <= 0x20000) {
			cab_blk_off = 0;
			blk_sz = s_cab[j].blk_sz;
		}
		else if (cab_blk_off + 0x20000 >= s_cab[j].blk_sz) {
			cab_blk_off = 0;
			blk_sz = s_cab[j].blk_sz % 0x20000;
		}
		else {
			blk_sz = 0x20000;
			cab_blk_off += blk_sz;
		}
		blocks[i][1] = blk_sz;
		fread(dec_buf, 1, 0x20000, in_fp[j]);
		//read = LZ4_compress_default((const char*) dec_buf, (char*) (cmp_buf + 12), blk_sz, 0x4fff4);
		read = LZ4_compress_HC((const char*) dec_buf, (char*) cmp_buf, blk_sz, 0x50000, 12);
		if (read < 0) {
			fprintf(stderr, "Can't compress block %d\n", i);
			return -1;
		}
		blocks[i][0] = read;
		blocks[i][2] = blk_flags;
		//mhy0_encrypt(cmp_buf, 0);
		written += fwrite(cmp_buf, 1, read, tmp_blk_fp);
		if (cab_blk_off == 0) {
			fclose(in_fp[j]);
			in_fp[j] = NULL;
			j++;
		}
	}
	fflush(tmp_blk_fp);
	fseek(tmp_blk_fp, 0, SEEK_SET);
	free(cmp_buf);
	uint8_t* hdr_buf = malloc((10 * blk_cnt) + (278 * cab_cnt));
		if (hdr_buf == NULL) {
		fprintf(stderr, "Can't allocate header buffer\n");
		return -1;
	}
	*(uint32_t*) hdr_buf = htobe32(blk_cnt);
	uint32_t cab_off = 4;
	unsigned int hdr_sz = 4;
	size_t cab_name_sz;
	for (i = 0; i < blk_cnt; i++) {
		*(uint32_t*)(hdr_buf + cab_off) = htobe32(blocks[i][1]);
		*(uint32_t*)(hdr_buf + cab_off + 4) = htobe32(blocks[i][0]);
		*(uint16_t*)(hdr_buf + cab_off + 8) = htobe16(blocks[i][2]);
		cab_off += 10;
		hdr_sz += 10;
	}
	*(uint32_t*)(hdr_buf + cab_off) = htobe32(cab_cnt);
	hdr_sz += 4;
	cab_off += 4;
	for (i = 0; i < cab_cnt; i++) {
		*(uint64_t*)(hdr_buf + cab_off) = htobe64(s_cab[i].blk_off);
		*(uint64_t*)(hdr_buf + cab_off + 8) = htobe64(s_cab[i].blk_sz);
		*(uint32_t*)(hdr_buf + cab_off + 16) = htobe32(s_cab[i].flags);
		cab_name_sz = strnlen(s_cab[i].name, 256) + 1;
		strncpy((char*)(hdr_buf + cab_off + 20), s_cab[i].name, cab_name_sz);
		hdr_sz += 20 + cab_name_sz;
		cab_off += 20 + cab_name_sz;
	}
	unsigned int cmp_sz = hdr_sz * 25 / 10;
	cmp_buf = malloc(cmp_sz);
	if (cmp_buf == NULL) {
		fprintf(stderr, "Can't allocate compressed header buffer\n");
		free(hdr_buf);
		return -1;
	}
	//ret = LZ4_compress_default((const char*) hdr_buf, (char*) (cmp_buf + 0x19), hdr_sz, cmp_sz - 0x19);
	ssize_t ret = LZ4_compress_HC((const char*) hdr_buf, (char*) (cmp_buf + 0x19), hdr_sz, cmp_sz - 0x19, 12);
	if (ret < 0) {
		fprintf(stderr, "Can't compress header\n");
		return -1;
	}
	free(hdr_buf);
	*(uint32_t*) cmp_buf = htobe32(0x454e4352);
	*(uint8_t*)(cmp_buf + 4) = 0;
	*(uint64_t*)(cmp_buf + 5) = htobe64(ret + written + 0x19);
	*(uint32_t*)(cmp_buf + 13) = htobe32(ret);
	*(uint32_t*)(cmp_buf + 17) = htobe32(hdr_sz);
	*(uint32_t*)(cmp_buf + 21) = htobe32(hdr_flags);
	//mhy0_encrypt(cmp_buf + 8, 1);
	ssize_t out_sz = fwrite(cmp_buf, 1, ret + 0x19, out_fp);
	ssize_t in_sz;
	while (written > 0) {
		in_sz = fread(dec_buf, 1, 0x20000, tmp_blk_fp);
		out_sz += fwrite(dec_buf, 1, in_sz, out_fp);
		written -= in_sz;
	}
	fclose(tmp_blk_fp);
	// TODO unlink
//	i = 0;
//	if ((out_sz & 3) != 0) {
//		fwrite(&i, 4 - (out_sz & 3), 1, out_fp);
//	}
	fflush(out_fp);
	return 0;
}
