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
		3	lz4hc
		4	lzham (modified lzha?)
		5	lz4mr0k (lz4 with mr0k encryption)
			OR zstd
		6	"Oodle" (early HSR variant?)
		7	"Oodle" with mr0k encryption
		8	(Unknown)
		9	"Oodle" (unencrypted)
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

int extract_encr(const uint8_t* buf, const char* filename, const uint8_t** _next_encr) {
	if (buf == NULL || filename == NULL) {
		return -1;
	}
	FILE* file;
	static char filenameBuf[1024];
	const uint8_t* next_encr = buf;
	uint64_t magic = ((uint64_t) be32toh(((uint32_t*) buf)[0]) << 8) | ((uint8_t*) buf)[4];
	int ret;
	if (magic != 0x454e435200) {
		fprintf(stderr, "Bad magic 0x%08llx (expected 0x%08llx)\n", magic, 0x454e435200);
		return -1;
	}
	const uint8_t* buf_cpos = buf + 5;
	uint64_t size = be32toh(((uint64_t*) buf_cpos)[0]);
	uint32_t hdr_size_cmp = be32toh(((uint32_t*) buf_cpos)[2]);
	uint32_t hdr_size_dec = be32toh(((uint32_t*) buf_cpos)[3]);
	uint32_t flags = be32toh(((uint32_t*) buf_cpos)[4]);
	if (!(((flags & 0x3f) == 0) || ((flags & 0x3f) == 2) || ((flags & 0x3f) == 3))) {
		fprintf(stderr, "Error: Only ENCR files compressed with lz4 or lz4hc, or uncompressed, are supported at the moment. (ctype = %d)\n", flags & 0x3f);
		return -1;
	}
	next_encr += size;
	if (_next_encr != NULL) *_next_encr = next_encr;
	buf_cpos += 20;
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
	encr_blk_ent_t* blocks = (encr_blk_ent_t*)(hdr_buf_cpos + 4);
	hdr_buf_cpos += (block_count * 10) + 4;
	encr_cab_ent_t* cabs = (encr_cab_ent_t*)(hdr_buf_cpos + 4);
	encr_cab_ent_t* cur_cab = cabs;
	return -100;
}
