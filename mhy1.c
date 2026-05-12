/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

/* TODO This is a straight copy of mhy0.c and can/should be merged with it (with some runtime conditionals to select the format) */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <endian.h>
#include <errno.h>
#include <assert.h>
#include <sys/random.h>
#include "lz4.h"
#include "lz4hc.h"
#include "mhycrypt.h"
#include "mhy1.h"

static const uint8_t gf256exp[256] = {
	0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
	0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
	0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
	0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
	0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
	0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
	0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
	0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
	0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
	0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
	0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
	0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
	0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
	0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
	0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
	0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01
};

static const uint8_t gf256log[256] = {
	0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1a, 0xc6, 0x4b, 0xc7, 0x1b, 0x68, 0x33, 0xee, 0xdf, 0x03,
	0x64, 0x04, 0xe0, 0x0e, 0x34, 0x8d, 0x81, 0xef, 0x4c, 0x71, 0x08, 0xc8, 0xf8, 0x69, 0x1c, 0xc1,
	0x7d, 0xc2, 0x1d, 0xb5, 0xf9, 0xb9, 0x27, 0x6a, 0x4d, 0xe4, 0xa6, 0x72, 0x9a, 0xc9, 0x09, 0x78,
	0x65, 0x2f, 0x8a, 0x05, 0x21, 0x0f, 0xe1, 0x24, 0x12, 0xf0, 0x82, 0x45, 0x35, 0x93, 0xda, 0x8e,
	0x96, 0x8f, 0xdb, 0xbd, 0x36, 0xd0, 0xce, 0x94, 0x13, 0x5c, 0xd2, 0xf1, 0x40, 0x46, 0x83, 0x38,
	0x66, 0xdd, 0xfd, 0x30, 0xbf, 0x06, 0x8b, 0x62, 0xb3, 0x25, 0xe2, 0x98, 0x22, 0x88, 0x91, 0x10,
	0x7e, 0x6e, 0x48, 0xc3, 0xa3, 0xb6, 0x1e, 0x42, 0x3a, 0x6b, 0x28, 0x54, 0xfa, 0x85, 0x3d, 0xba,
	0x2b, 0x79, 0x0a, 0x15, 0x9b, 0x9f, 0x5e, 0xca, 0x4e, 0xd4, 0xac, 0xe5, 0xf3, 0x73, 0xa7, 0x57,
	0xaf, 0x58, 0xa8, 0x50, 0xf4, 0xea, 0xd6, 0x74, 0x4f, 0xae, 0xe9, 0xd5, 0xe7, 0xe6, 0xad, 0xe8,
	0x2c, 0xd7, 0x75, 0x7a, 0xeb, 0x16, 0x0b, 0xf5, 0x59, 0xcb, 0x5f, 0xb0, 0x9c, 0xa9, 0x51, 0xa0,
	0x7f, 0x0c, 0xf6, 0x6f, 0x17, 0xc4, 0x49, 0xec, 0xd8, 0x43, 0x1f, 0x2d, 0xa4, 0x76, 0x7b, 0xb7,
	0xcc, 0xbb, 0x3e, 0x5a, 0xfb, 0x60, 0xb1, 0x86, 0x3b, 0x52, 0xa1, 0x6c, 0xaa, 0x55, 0x29, 0x9d,
	0x97, 0xb2, 0x87, 0x90, 0x61, 0xbe, 0xdc, 0xfc, 0xbc, 0x95, 0xcf, 0xcd, 0x37, 0x3f, 0x5b, 0xd1,
	0x53, 0x39, 0x84, 0x3c, 0x41, 0xa2, 0x6d, 0x47, 0x14, 0x2a, 0x9e, 0x5d, 0x56, 0xf2, 0xd3, 0xab,
	0x44, 0x11, 0x92, 0xd9, 0x23, 0x20, 0x2e, 0x89, 0xb4, 0x7c, 0xb8, 0x26, 0x77, 0x99, 0xe3, 0xa5,
	0x67, 0x4a, 0xed, 0xde, 0xc5, 0x31, 0xfe, 0x18, 0x0d, 0x63, 0x8c, 0x80, 0xc0, 0xf7, 0x70, 0x07
};

static uint8_t gf256mul(uint8_t a, uint8_t b) {
	if (a == 0 || b == 0) return 0;
	return gf256exp[(gf256log[a] + gf256log[b]) % 255];
}

static uint8_t gf256div(uint8_t a, uint8_t b) {
	assert(b != 0);
	if (a == 0) return 0;
	return gf256exp[(255 + gf256log[a] - gf256log[b]) % 255];
}

static int32_t unshuffleInt(const uint8_t* buf) {
	return (buf[2]) | (buf[4] << 8) | (buf[0] << 16) | (buf[5] << 24);
}

static uint32_t unshuffleUint(const uint8_t* buf) {
	return (buf[1]) | (buf[6] << 8) | (buf[3] << 16) | (buf[2] << 24);
}

static void shuffleInt(uint8_t* buf, int32_t i) {
	buf[2] = i & 0xff;
	buf[4] = (i >> 8) & 0xff;
	buf[0] = (i >> 16) & 0xff;
	buf[5] = (i >> 24) & 0xff;
}

static void shuffleUint(uint8_t* buf, uint32_t i) {
	buf[1] = i & 0xff;
	buf[6] = (i >> 8) & 0xff;
	buf[3] = (i >> 16) & 0xff;
	buf[2] = (i >> 24) & 0xff;
}

static const uint8_t lut[3][16] = {
	{0xb, 0x2, 0x8, 0xc, 0x1, 0x5, 0x0, 0xf, 0x6, 0x7, 0x9, 0x3, 0xd, 0x4, 0xe, 0xa},
	{0x4, 0x5, 0x7, 0xa, 0x2, 0xf, 0xb, 0x8, 0xe, 0xd, 0x9, 0x6, 0xc, 0x3, 0x0, 0x1},
	{0x8, 0x0, 0xc, 0x6, 0x4, 0xb, 0x7, 0x9, 0x5, 0x3, 0xf, 0x1, 0xd, 0xa, 0x2, 0xe}
};
static const uint8_t key[8] = {0x48, 0x14, 0x36, 0xed, 0x8e, 0x44, 0x5b, 0xb6};
static const uint8_t gf_idx[8] = {0xa7, 0x99, 0x66, 0x50, 0xb9, 0x2d, 0xf0, 0x78};
extern const uint8_t blkScrambleTbl[0x400];

static uint8_t mhy1AesRoundKeys[11][16];

static int mhy1_encrypt(uint8_t* in, size_t _size, int isHeader) {
	if (in == NULL) {
		return -1;
	}
	size_t size = _size < 0x80 ? _size : 0x80;
	size_t chunkSize = isHeader ? 0x1c : 0x8;
	size_t roundSize = (chunkSize + 15) & ~15;
	assert(size >= (roundSize + 20)); /* TODO: Properly handle this case */
	size_t j, k, l;
	uint8_t v, q, keyIdx;
	unsigned int blkScrambleTblIdx;
	uint8_t t[16];
	rc4_dec_mhy(in + 20, 8, in + 20 + roundSize, size - roundSize - 20, in + 28, 8);
	uint8_t* aesKey = in;
	uint8_t* data = in + 20;
	*(uint32_t*) in ^= *(uint32_t*) data;
	aesGetRoundKeys(aesKey, mhy1AesRoundKeys);
	aesUnscrambleKey(data, mhy1AesRoundKeys);
	uint8_t* in2 = in + 4;
	for (j = 0; j < 3; j++) {
		for (k = 0; k < 16; k++) {
			v = lut[j][k];
			keyIdx = k % 8;
			q = key[keyIdx] ^ in2[k];
			for (l = 0; l < 256; l++) {
				blkScrambleTblIdx = blkScrambleTbl[((k & 3) << 8) | l];
				if (blkScrambleTblIdx == q) {
					break;
				}
			}
			t[v] = gf256div(l, gf_idx[keyIdx]);
		}
		memcpy(in2, t, 16);
	}
	in2 = in + 20;
	for (j = 0; j < 3; j++) {
		for (k = 0; k < 16; k++) {
			v = lut[j][k];
			keyIdx = k % 8;
			q = key[keyIdx] ^ in2[k];
			for (l = 0; l < 256; l++) {
				blkScrambleTblIdx = blkScrambleTbl[((k & 3) << 8) | l];
				if (blkScrambleTblIdx == q) {
					break;
				}
			}
			t[v] = gf256div(l, gf_idx[keyIdx]);
		}
		memcpy(in2, t, 16);
	}
	return 0;
}

static int mhy1_decrypt(uint8_t* in, size_t _size, int isHeader) {
	if (in == NULL) {
		return -1;
	}
	size_t size = _size < 0x80 ? _size : 0x80;
	size_t chunkSize = isHeader ? 0x1c : 0x8;
	size_t roundSize = (chunkSize + 15) & ~15;
	assert(size >= (roundSize + 20)); /* TODO: Properly handle this case */
	size_t j, k;
	uint8_t v, keyIdx;
	unsigned int blkScrambleTblIdx;
	uint8_t t[16];
	uint8_t* in2 = in + 4;
	for (j = 0; j < 3; j++) {
		for (k = 0; k < 16; k++) {
			v = lut[2 - j][k];
			keyIdx = k % 8;
			blkScrambleTblIdx = ((k & 3) << 8);
			blkScrambleTblIdx |= gf256mul(gf_idx[keyIdx], in2[v]);
			t[k] = blkScrambleTbl[blkScrambleTblIdx] ^ key[keyIdx];
		}
		memcpy(in2, t, 16);
	}
	in2 = in + 20;
	for (j = 0; j < 3; j++) {
		for (k = 0; k < 16; k++) {
			v = lut[2 - j][k];
			keyIdx = k % 8;
			blkScrambleTblIdx = ((k & 3) << 8);
			blkScrambleTblIdx |= gf256mul(gf_idx[keyIdx], in2[v]);
			t[k] = blkScrambleTbl[blkScrambleTblIdx] ^ key[keyIdx];
		}
		memcpy(in2, t, 16);
	}
	uint8_t* aesKey = in;
	uint8_t* data = in + 20;
	aesGetRoundKeys(aesKey, mhy1AesRoundKeys);
	aesScrambleKey(data, mhy1AesRoundKeys);
	*(uint32_t*) in ^= *(uint32_t*) data;
	rc4_mhy(in + 20, 8, in + 20 + roundSize, size - roundSize - 20, in + 28, 8);
	return 0;
}

typedef struct {
	char name[0x104];
	uint32_t blk_off;
	uint32_t blk_sz;
	uint8_t flag;
	uint8_t extra[5];
} __attribute__((packed)) cab_serialized_t;

typedef struct {
	uint32_t key;
	uint32_t cab_cnt;
	uint8_t rc4_key[16];
	uint8_t extra[19];
} __attribute__((packed)) pack_serialized_t;

/* TODO: `nap` client version 2.0 and onwards don't use LZ4 anymore and will error out here. */
int extract_mhy1(uint8_t* in_buf, const char* filename, uint8_t** _next_mhy1) {
	if (in_buf == NULL || filename == NULL) {
		return -1;
	}
	FILE* outfp;
	FILE* file;
	static char filenameBuf[1024];
	uint8_t* next_mhy1 = NULL;
	uint32_t magic = be32toh(((const uint32_t*) in_buf)[0]);
	if (magic != 0x6d687931) {
		fprintf(stderr, "Bad magic 0x%08x (expected 0x%08x)\n", magic, 0x6d687931);
		return -1;
	}
	uint32_t hdr_sz = le32toh(((const uint32_t*) in_buf)[1]);
	int ret = mhy1_decrypt(in_buf + 8, hdr_sz, 1);
	if (ret) {
		fprintf(stderr, "Decryption error (header)\n");
		return ret;
	}
#if 0
	snprintf(filenameBuf, 1024, "%s.hdr_decrypt", filename);
	file = fopen(filenameBuf, "wb");
	if (file == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	fwrite(in_buf, hdr_sz + 8, 1, file);
	fclose(file);
	file = NULL;
#endif
	uint32_t hdr_sz_dec = unshuffleUint(in_buf + 0x38);
	uint8_t* hdr_buf = malloc(hdr_sz_dec);
	if (hdr_buf == NULL) {
		fprintf(stderr, "Can't allocate decompression buffer (header)\n");
		return -1;
	}
	ret = LZ4_decompress_safe((const char*) (in_buf + 0x3f), (char*) hdr_buf, hdr_sz - 0x37, hdr_sz_dec);
	if (ret < 0) {
		fprintf(stderr, "LZ4 decompress error %d when decoding header\n", -ret);
		free(hdr_buf);
		return ret;
	}
#if 0
	snprintf(filenameBuf, 1024, "%s.hdr_decomp", filename);
	file = fopen(filenameBuf, "wb");
	if (file == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	fwrite(hdr_buf, hdr_sz_dec, 1, file);
	fclose(file);
	file = NULL;
#endif
	uint32_t cab_cnt = unshuffleInt(hdr_buf);
	pack_serialized_t s_pack;
	s_pack.key = ((uint32_t*) in_buf)[2];
	s_pack.cab_cnt = cab_cnt;
	memcpy(s_pack.rc4_key, in_buf + 0x1c, 16);
	memcpy(s_pack.extra, in_buf + 0x2c, 12);
	s_pack.extra[12] = in_buf[0x38];
	s_pack.extra[13] = in_buf[0x3c];
	s_pack.extra[14] = in_buf[0x3d];
	s_pack.extra[15] = hdr_buf[1];
	s_pack.extra[16] = hdr_buf[3];
	uint32_t blk_cnt = unshuffleInt(hdr_buf + 6 + (0x113 * cab_cnt));
	s_pack.extra[17] = hdr_buf[7 + (0x113 * cab_cnt)];
	s_pack.extra[18] = hdr_buf[9 + (0x113 * cab_cnt)];
	snprintf(filenameBuf, 1024, "%s.hdr", filename);
	file = fopen(filenameBuf, "wb");
	if (file == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	fwrite(&s_pack, sizeof(s_pack), 1, file);
	fclose(file);
	file = NULL;
	uint32_t cab_off = 6;
	int cab_flag;
	uint32_t cab_blk_off, cab_blk_sz, blk_off, blk_dec_sz, blk_cmp_sz;
	uint32_t data_off = 8 + hdr_sz;
	uint32_t blk_data_off = 0;
	size_t total_sz = data_off;
	size_t blk_sz = 0;
	const char* cab_name;
	unsigned int i;
	cab_serialized_t s_cab[cab_cnt];
	uint8_t* data_buf;
	for (i = 0; i < cab_cnt; i++) {
		cab_name = (const char*) (hdr_buf + cab_off);
		cab_flag = hdr_buf[cab_off + 0x105];
		cab_blk_off = unshuffleInt(hdr_buf + cab_off + 0x106);
		cab_blk_sz = unshuffleUint(hdr_buf + cab_off + 0x10c);
		blk_sz += cab_blk_sz;
		fprintf(stderr, "cab%d name: %s offset 0x%08x blk_offset 0x%08x blk_size: 0x%08x flag %d\n", i, cab_name, cab_off, cab_blk_off, cab_blk_sz, cab_flag);
		memcpy(s_cab[i].name, cab_name, 0x104);
		s_cab[i].flag = cab_flag;
		s_cab[i].blk_off = cab_blk_off;
		s_cab[i].blk_sz = cab_blk_sz;
		s_cab[i].extra[0] = hdr_buf[cab_off + 0x107];
		s_cab[i].extra[1] = hdr_buf[cab_off + 0x109];
		s_cab[i].extra[2] = hdr_buf[cab_off + 0x10c];
		s_cab[i].extra[3] = hdr_buf[cab_off + 0x110];
		s_cab[i].extra[4] = hdr_buf[cab_off + 0x111];
		snprintf(filenameBuf, 1024, "%s.cab%d.hdr", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(hdr_buf);
			return -1;
		}
		fwrite(&(s_cab[i]), sizeof(cab_serialized_t), 1, file);
		fclose(file);
		file = NULL;
		cab_off += 0x113;
	}
	data_buf = malloc(blk_sz);
	if (data_buf == NULL) {
		fprintf(stderr, "Can't allocate decompression buffer (blocks)\n");
		free(hdr_buf);
		return -1;
	}
	blk_off = (0x113 * cab_cnt) + 12;
	blk_data_off = 0;
	uint8_t blk_key_buf[17];
	for (i = 0; i < blk_cnt; i++) {
		blk_cmp_sz = unshuffleInt(hdr_buf + blk_off);
		blk_dec_sz = unshuffleUint(hdr_buf + blk_off + 6);
		fprintf(stderr, "blk %d cmpSz 0x%08x decSz 0x%08x\n", i, blk_cmp_sz, blk_dec_sz);
		ret = mhy1_decrypt(in_buf + data_off, blk_cmp_sz, 0);
		if (ret) {
			fprintf(stderr, "Decryption error (blk %d)\n", i);
			free(hdr_buf);
			return -1;
		}
#if 0
		snprintf(filenameBuf, 1024, "%s.blk%d.decrypt", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(hdr_buf);
			return -1;
		}
		fwrite(in_buf + data_off, blk_cmp_sz, 1, file);
		fclose(file);
		file = NULL;
#endif
		snprintf(filenameBuf, 1024, "%s.blk%d.key", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(hdr_buf);
			return -1;
		}
		memcpy(blk_key_buf, in_buf + data_off, 4);
		memcpy(blk_key_buf + 4, in_buf + data_off + 20, 8);
		blk_key_buf[12] = hdr_buf[blk_off + 1];
		blk_key_buf[13] = hdr_buf[blk_off + 3];
		blk_key_buf[14] = hdr_buf[blk_off + 6];
		blk_key_buf[15] = hdr_buf[blk_off + 10];
		blk_key_buf[16] = hdr_buf[blk_off + 11];
		fwrite(blk_key_buf, 17, 1, file);
		fclose(file);
		file = NULL;
		ret = LZ4_decompress_safe((const char*) (in_buf + data_off + 28), (char*) data_buf + blk_data_off, blk_cmp_sz - 28, blk_dec_sz);
		if (ret < 0) {
			fprintf(stderr, "LZ4 decompress error %d when decoding data (blk %d)\n", -ret, i);
			free(hdr_buf);
			free(data_buf);
			return -1;
		}
		blk_off += 13;
		data_off += blk_cmp_sz;
		blk_data_off += blk_dec_sz;
		total_sz += blk_cmp_sz;
	}
	for (i = 0; i < cab_cnt; i++) {
		cab_blk_off = s_cab[i].blk_off;
		cab_blk_sz = s_cab[i].blk_sz;
		snprintf(filenameBuf, 1024, "%s.cab%d", filename, i);
		outfp = fopen(filenameBuf, "wb");
		if (outfp == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(hdr_buf);
			return -1;
		}
		fwrite(data_buf + cab_blk_off, cab_blk_sz, 1, outfp);
		fclose(outfp);
	}
	fprintf(stderr, "total size of this mhy1 0x%08lx\n", total_sz);
	next_mhy1 = in_buf + total_sz; /* + ((total_sz + 3) & ~3)*/
	fprintf(stderr, "if present, the next one should be at 0x%08lx\n", (unsigned long) next_mhy1);
	if (_next_mhy1 != NULL) *_next_mhy1 = next_mhy1;
	free(hdr_buf);
	return 0;
}

typedef struct {
	uint32_t cmp_sz;
	uint32_t dec_sz;
	uint8_t extra[5];
} block_mem_t;

/* TODO: `nap` client version 2.0 and onwards don't use LZ4 anymore and will likely not accept files made by this tool. */
int pack_mhy1(const char* in_filename, FILE* out_fp) {
	if (in_filename == NULL || out_fp == NULL) {
		return -1;
	}
	FILE* infp2;
	unsigned int i, j;
	int ret;
	uint8_t* cmp_buf;
	uint8_t* hdr_buf;
	uint32_t cmp_sz, cab_cnt, blk_sz;
	uint32_t blk_cnt = 0;
	uint32_t cab_blk_cnt;
	uint32_t cab_blk_off = 0;
	size_t cab_blk_sz, hdr_sz;
	static char filenameBuf[1024];
	uint8_t* dec_buf = malloc(0x20000);
	if (dec_buf == NULL) {
		return -1;
	}
	pack_serialized_t s_pack;
	snprintf(filenameBuf, 1024, "%s.hdr", in_filename);
	infp2 = fopen(filenameBuf, "rb");
	if (infp2 == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
#if 0
		free(dec_buf);
		return -1;
#else
		fprintf(stderr, "Assuming 1 cab file present\n");
		// TODO true for all mhy1 files?
		s_pack.key = htole32(0xdadadad9);
		s_pack.cab_cnt = 1;
		getrandom(s_pack.rc4_key, 8, 0);
		memset(s_pack.rc4_key + 8, 0, 8);
		memset(s_pack.extra, 0, 19);
#endif
	}
	else {
		fread(&s_pack, sizeof(s_pack), 1, infp2);
		fclose(infp2);
		infp2 = NULL;
	}
	cab_cnt = s_pack.cab_cnt;
	if (cab_cnt >= 256) cab_cnt = 256;
	cab_serialized_t s_cab[cab_cnt];
	FILE* infp[cab_cnt];
	for (i = 0; i < cab_cnt; i++) {
		snprintf(filenameBuf, 1024, "%s.cab%d", in_filename, i);
		infp[i] = fopen(filenameBuf, "rb");
		if (infp[i] == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(dec_buf);
			return -1;
		}
		fseek(infp[i], 0, SEEK_END);
		cab_blk_sz = ftell(infp[i]);
		fseek(infp[i], 0, SEEK_SET);
		// TODO start move outside the loop
		cab_blk_cnt = cab_blk_sz / 0x20000;
		if ((cab_blk_sz % 0x20000) != 0) {
			cab_blk_cnt++;
		}
		blk_cnt += cab_blk_cnt;
		// end
		snprintf(filenameBuf, 1024, "%s.cab%d.hdr", in_filename, i);
		infp2 = fopen(filenameBuf, "rb");
		if (infp2 != NULL) {
			fread(&s_cab[i], sizeof(cab_serialized_t), 1, infp2);
			fclose(infp2);
			infp2 = NULL;
		}
		else {
#ifndef NDEBUG
			memset(&s_cab[i], 0, sizeof(s_cab[i]));
#endif
			uint64_t cab_name_buf[2];
			// TODO actually random, or an MD2/4/5 sum (and if so, of what)?
			getrandom(cab_name_buf, sizeof(uint64_t) * 2, 0);
			snprintf(s_cab[i].name, 0x104, "CAB-%016llx%016llx", (unsigned long long) htobe64(cab_name_buf[0]), (unsigned long long) htobe64(cab_name_buf[1]));
			s_cab[i].flag = 0;
			memset(s_cab[i].extra, 0, 5);
		}
		s_cab[i].blk_off = cab_blk_off;
		s_cab[i].blk_sz = cab_blk_sz;
		cab_blk_off += cab_blk_sz;
	}
	FILE* tmp_blk_fp;
	snprintf(filenameBuf, 1024, "%s.blocks", in_filename);
	tmp_blk_fp = fopen(filenameBuf, "wb+");
	if (tmp_blk_fp == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	cmp_buf = malloc(0x50000);
	if (cmp_buf == NULL) {
		fprintf(stderr, "Can't allocate block compression buffer\n");
		return -1;
	}
	block_mem_t blocks[blk_cnt];
	cab_blk_off = 0;
	j = 0;
	ssize_t written = 0;
	uint8_t blk_key_buf[17];
	for (i = 0; i < blk_cnt; i++) {
		snprintf(filenameBuf, 1024, "%s.blk%d.key", in_filename, i);
		infp2 = fopen(filenameBuf, "rb");
		if (infp2 != NULL) {
			fread(blk_key_buf, 17, 1, infp2);
			fclose(infp2);
			infp2 = NULL;
		}
		else {
			getrandom(blk_key_buf + 4, 8, 0);
			// TODO true for all blocks?
			// TODO is the number allowed to carry or does only the lower byte wrap around?
			*(uint32_t*) (&blk_key_buf[0]) = htole32(0xdadadada + i);
			memset(blk_key_buf + 12, 0, 5);
		}
		memcpy(cmp_buf, blk_key_buf, 4);
		((uint32_t*) cmp_buf)[1] = htobe32(0x6d68796e);
		((uint32_t*) cmp_buf)[2] = htobe32(0x65776563);
		((uint32_t*) cmp_buf)[3] = htole32(1);
		((uint32_t*) cmp_buf)[4] = htole32(~0);
		memcpy(cmp_buf + 20, blk_key_buf + 4, 8);
		memcpy(blocks[i].extra, blk_key_buf + 12, 5);
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
		blocks[i].dec_sz = blk_sz;
		fread(dec_buf, 0x20000, 1, infp[j]);
		//ret = LZ4_compress_default((const char*) dec_buf, (char*) (cmp_buf + 12), blk_sz, 0x4fff4);
		ret = LZ4_compress_HC((const char*) dec_buf, (char*) (cmp_buf + 28), blk_sz, 0x4ffe4, 28);
		if (ret < 0) {
			fprintf(stderr, "Can't compress block %d\n", i);
			return -1;
		}
		blocks[i].cmp_sz = ret + 28;
		mhy1_encrypt(cmp_buf, ret + 28, 0);
		written += fwrite(cmp_buf, 1, ret + 28, tmp_blk_fp);
		if (cab_blk_off == 0) {
			fclose(infp[j]);
			j++;
		}
	}
	fflush(tmp_blk_fp);
	fseek(tmp_blk_fp, 0, SEEK_SET);
	free(cmp_buf);
	hdr_sz = (0x113 * cab_cnt) + (blk_cnt * 13) + 12;
	cmp_sz = ((hdr_sz * 25) / 10) + 0x3f;
	hdr_buf = malloc(hdr_sz);
	if (hdr_buf == NULL) {
		fprintf(stderr, "Can't allocate header buffer\n");
		return -1;
	}
	cmp_buf = malloc(cmp_sz);
	if (hdr_buf == NULL) {
		fprintf(stderr, "Can't allocate compressed header buffer\n");
		free(hdr_buf);
		return -1;
	}
#ifndef NDEBUG
	memset(hdr_buf, 0, hdr_sz);
	memset(cmp_buf, 0, cmp_sz);
#endif
	shuffleInt(hdr_buf, cab_cnt);
	hdr_buf[1] = s_pack.extra[15];
	hdr_buf[3] = s_pack.extra[16];
	uint32_t cab_off = 6;
	for (i = 0; i < cab_cnt; i++) {
		memcpy(hdr_buf + cab_off, s_cab[i].name, 0x104);
		hdr_buf[cab_off + 0x105] = s_cab[i].flag;
		shuffleInt(hdr_buf + cab_off + 0x106, s_cab[i].blk_off);
		shuffleUint(hdr_buf + cab_off + 0x10c, s_cab[i].blk_sz);
		hdr_buf[cab_off + 0x107] = s_cab[i].extra[0];
		hdr_buf[cab_off + 0x109] = s_cab[i].extra[1];
		hdr_buf[cab_off + 0x10c] = s_cab[i].extra[2];
		hdr_buf[cab_off + 0x110] = s_cab[i].extra[3];
		hdr_buf[cab_off + 0x111] = s_cab[i].extra[4];
		cab_off += 0x113;
	}
	shuffleInt(hdr_buf + 6 + (0x113 * cab_cnt), blk_cnt);
	hdr_buf[7 + (0x113 * cab_cnt)] = s_pack.extra[17];
	hdr_buf[9 + (0x113 * cab_cnt)] = s_pack.extra[18];
	uint32_t blk_off = (0x113 * cab_cnt) + 12;
	for (i = 0; i < blk_cnt; i++) {
		shuffleInt(hdr_buf + blk_off, blocks[i].cmp_sz);
		shuffleUint(hdr_buf + blk_off + 6, blocks[i].dec_sz);
		hdr_buf[blk_off + 1] = blocks[i].extra[0];
		hdr_buf[blk_off + 3] = blocks[i].extra[1];
		hdr_buf[blk_off + 6] = blocks[i].extra[2];
		hdr_buf[blk_off + 10] = blocks[i].extra[3];
		hdr_buf[blk_off + 11] = blocks[i].extra[4];
		blk_off += 13;
	}
	//ret = LZ4_compress_default((const char*) hdr_buf, (char*) (cmp_buf + 0x2f), hdr_sz, cmp_sz - 0x2f);
	ret = LZ4_compress_HC((const char*) hdr_buf, (char*) (cmp_buf + 0x3f), hdr_sz, cmp_sz - 0x3f, 12);
	if (ret < 0) {
		fprintf(stderr, "Can't compress header\n");
		return -1;
	}
	free(hdr_buf);
	((uint32_t*) cmp_buf)[0] = htobe32(0x6d687931);
	((uint32_t*) cmp_buf)[1] = htole32(ret + 0x37);
	((uint32_t*) cmp_buf)[2] = s_pack.key;
	((uint32_t*) cmp_buf)[3] = htobe32(0x6d68796e);
	((uint32_t*) cmp_buf)[4] = htobe32(0x65776563);
	((uint32_t*) cmp_buf)[5] = htole32(1);
	((uint32_t*) cmp_buf)[6] = htole32(~0);
	memcpy(cmp_buf + 28, s_pack.rc4_key, 16);
	memcpy(cmp_buf + 44, s_pack.extra, 12);
	cmp_buf[0x38] = s_pack.extra[12];
	cmp_buf[0x3c] = s_pack.extra[13];
	cmp_buf[0x3d] = s_pack.extra[14];
	shuffleUint(cmp_buf + 0x38, hdr_sz);
	mhy1_encrypt(cmp_buf + 8, ret + 0x37, 1);
	ssize_t out_sz = fwrite(cmp_buf, 1, ret + 0x3f, out_fp);
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
