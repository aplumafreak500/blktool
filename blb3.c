/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <endian.h>
#include <sys/random.h>
#include "mhycrypt.h"
#include "lz4hc.h"
#include "blb3.h"

/* located in mhy0.c */
uint8_t gf256mul(uint8_t a, uint8_t b);
uint8_t gf256div(uint8_t a, uint8_t b);
int32_t unshuffleInt(const uint8_t* buf);
uint32_t unshuffleUint(const uint8_t* buf);
void shuffleInt(uint8_t* buf, int32_t i);
void shuffleUint(uint8_t* buf, uint32_t i);

static uint8_t blb3AesRoundKeys[11][16];

static const uint8_t blb3ScrambleTbl[1024] = {
	0xd0, 0x20, 0x41, 0x4a, 0xa2, 0x7a, 0xce, 0x66, 0x21, 0x7c, 0x8e, 0x45, 0xf4, 0x87, 0x31, 0xdd,
	0xd8, 0x35, 0xc2, 0x09, 0xea, 0x60, 0x38, 0xd2, 0xb4, 0xbe, 0x10, 0x76, 0x7f, 0xb7, 0x0f, 0xfd,
	0xcb, 0x02, 0x0e, 0x5b, 0x2e, 0x9b, 0xb1, 0xe1, 0xf5, 0x5e, 0x40, 0x4d, 0x88, 0x98, 0x6f, 0x37,
	0xab, 0xee, 0x53, 0x79, 0x70, 0x24, 0x6c, 0x67, 0xe6, 0x3c, 0x49, 0x06, 0x59, 0xba, 0xcf, 0x08,
	0x8a, 0xac, 0xa0, 0x8b, 0x3d, 0xbf, 0x13, 0x73, 0x43, 0x91, 0x00, 0x2b, 0xa1, 0x22, 0x93, 0x3a,
	0xcc, 0x4c, 0x44, 0x14, 0x28, 0xf7, 0xed, 0x36, 0x4f, 0xe4, 0xfc, 0x90, 0x0a, 0x9e, 0xd6, 0x77,
	0x05, 0xbd, 0x57, 0x3f, 0x96, 0x5f, 0x4b, 0xbc, 0x8d, 0x3e, 0x72, 0xfe, 0x4e, 0xa7, 0xc3, 0xa9,
	0x3b, 0x07, 0x89, 0x2f, 0xb8, 0xff, 0x1d, 0xb6, 0x65, 0x6d, 0xc4, 0x61, 0x39, 0x6a, 0xa3, 0x64,
	0xc1, 0xae, 0xb2, 0x97, 0x29, 0x9f, 0xf2, 0x32, 0x34, 0x1a, 0x58, 0x27, 0x51, 0x71, 0x15, 0x03,
	0xec, 0x47, 0x1e, 0x5c, 0xb3, 0x18, 0x7d, 0xe9, 0x48, 0x6e, 0x55, 0x19, 0x2a, 0xda, 0x25, 0x80,
	0x11, 0xf1, 0x95, 0xe5, 0xe2, 0x83, 0xa5, 0x82, 0x1c, 0x5a, 0xcd, 0xd4, 0x74, 0x9d, 0x33, 0xb5,
	0xd5, 0xca, 0x16, 0xe3, 0x23, 0x84, 0x2c, 0xde, 0x1b, 0x94, 0xe8, 0x52, 0x01, 0x12, 0x7b, 0x63,
	0x50, 0x9a, 0x68, 0xf6, 0xd7, 0x8c, 0x62, 0xe0, 0x17, 0xdb, 0x8f, 0x0c, 0xc0, 0x0d, 0x46, 0xdf,
	0xf8, 0x04, 0xeb, 0x75, 0xa6, 0xd1, 0xa4, 0xfb, 0x5d, 0xc8, 0x1f, 0xf3, 0xdc, 0xb0, 0x78, 0xaa,
	0x2d, 0xc9, 0x56, 0x9c, 0x86, 0xf9, 0xc6, 0xe7, 0x81, 0x92, 0xa8, 0xef, 0x54, 0x6b, 0x7e, 0x99,
	0xc5, 0xd9, 0xc7, 0xfa, 0xd3, 0x26, 0x30, 0xb9, 0xf0, 0x0b, 0x42, 0xad, 0x85, 0x69, 0xbb, 0xaf,
	0x0b, 0xe2, 0xc2, 0x29, 0xff, 0xdd, 0xe6, 0x2a, 0xd9, 0x97, 0x30, 0x5e, 0x73, 0x95, 0x48, 0x05,
	0x56, 0x26, 0x0f, 0xd2, 0xa2, 0x9a, 0x3c, 0xae, 0x14, 0xbd, 0xf9, 0x92, 0x23, 0x61, 0x74, 0x31,
	0xe1, 0xc3, 0x7a, 0xe5, 0xf0, 0x8a, 0x32, 0xaa, 0x91, 0x1b, 0x79, 0xe7, 0x54, 0x0c, 0x81, 0xd0,
	0xd5, 0x08, 0x0e, 0x98, 0x9f, 0x6c, 0xbf, 0xac, 0x59, 0xed, 0x18, 0x87, 0xdc, 0x85, 0x69, 0xf6,
	0x82, 0x01, 0xa7, 0x83, 0x20, 0xd7, 0x10, 0xb9, 0x21, 0x1e, 0x42, 0xd8, 0xb1, 0x4a, 0xa1, 0x66,
	0x9d, 0x0d, 0x71, 0x5b, 0x1a, 0xb7, 0x2d, 0xa4, 0x07, 0x65, 0x33, 0x06, 0xf5, 0x67, 0xcf, 0xa8,
	0x12, 0xde, 0x5f, 0x3f, 0x35, 0x13, 0x6f, 0x02, 0x6b, 0xd1, 0xa6, 0x1d, 0xc7, 0x5a, 0x40, 0xb3,
	0xf8, 0x90, 0xa5, 0x9b, 0x94, 0xa0, 0x00, 0x60, 0x68, 0x50, 0xda, 0x43, 0x38, 0x7b, 0x37, 0x4f,
	0xf4, 0x58, 0xc5, 0x64, 0x22, 0x3d, 0xc9, 0xfc, 0x0a, 0x3a, 0xba, 0x78, 0x6a, 0xfa, 0x5c, 0x8c,
	0xe0, 0x77, 0x88, 0x41, 0xcd, 0x51, 0x9e, 0xa3, 0x4c, 0x1f, 0xca, 0x16, 0x6e, 0x28, 0xf1, 0xfe,
	0x8e, 0x99, 0xc8, 0xfb, 0x19, 0x7e, 0x7f, 0x45, 0x4d, 0xe4, 0xdf, 0x75, 0x57, 0x6d, 0x2f, 0xbb,
	0x46, 0xe3, 0xea, 0xdb, 0x53, 0x34, 0x36, 0x80, 0xef, 0xf7, 0x7c, 0x1c, 0xb0, 0x9c, 0x47, 0x62,
	0xb2, 0xb5, 0x89, 0x17, 0x09, 0xce, 0xc6, 0xc1, 0x44, 0xcb, 0x63, 0x8b, 0xd6, 0x84, 0xb4, 0xee,
	0xf3, 0x55, 0x8f, 0xd4, 0x49, 0x3e, 0x2b, 0x96, 0xe8, 0xfd, 0x04, 0x8d, 0x52, 0xbc, 0x93, 0x70,
	0xab, 0xe9, 0x4e, 0xeb, 0x2e, 0x76, 0xa9, 0x86, 0xcc, 0xd3, 0xc4, 0xaf, 0x39, 0x2c, 0xf2, 0x4b,
	0xad, 0x72, 0x5d, 0xbe, 0xec, 0x27, 0xc0, 0x15, 0x03, 0x24, 0xb6, 0x7d, 0x3b, 0x11, 0xb8, 0x25,
	0xdd, 0x2f, 0xfb, 0x06, 0xb1, 0x5b, 0xf2, 0xa5, 0x8c, 0xc9, 0xca, 0xc7, 0x15, 0xb3, 0xfc, 0x7c,
	0xeb, 0xdc, 0x50, 0x91, 0x83, 0x80, 0x82, 0x53, 0xd3, 0xe4, 0xd9, 0x73, 0x64, 0x27, 0xc2, 0xa0,
	0x67, 0xee, 0x54, 0x0d, 0xaa, 0x77, 0x97, 0x85, 0xc5, 0x75, 0x23, 0xa7, 0x37, 0x01, 0x19, 0xd1,
	0x79, 0xf8, 0x51, 0xa9, 0x49, 0x3a, 0xe9, 0xf7, 0xf0, 0x5c, 0xd4, 0x74, 0x1a, 0xb9, 0x1d, 0x94,
	0x28, 0x13, 0xf4, 0x0a, 0x90, 0x6c, 0xfa, 0x95, 0x70, 0x3b, 0x9f, 0xe3, 0xe2, 0x4e, 0x04, 0xbc,
	0xa3, 0x21, 0xd2, 0x5e, 0xdb, 0x30, 0x44, 0x2c, 0x76, 0xe1, 0x3c, 0x69, 0x1c, 0xc0, 0x4f, 0x4b,
	0x0b, 0x9a, 0xfd, 0x6f, 0xd8, 0x66, 0xb7, 0x7e, 0x17, 0x25, 0xc3, 0xc8, 0xf3, 0xde, 0x96, 0x3e,
	0x62, 0xff, 0xdf, 0x4c, 0x2d, 0x10, 0xe8, 0x46, 0xf6, 0xcd, 0x24, 0xe6, 0xc1, 0x61, 0x8f, 0x4a,
	0x8b, 0x5f, 0x7a, 0xea, 0x65, 0x86, 0x31, 0x20, 0xd5, 0x71, 0xf1, 0x48, 0xbe, 0x40, 0x0e, 0x39,
	0x43, 0x07, 0x9b, 0x68, 0xcc, 0x3f, 0x60, 0x2a, 0xbd, 0x36, 0xb5, 0x56, 0x42, 0xce, 0x72, 0x41,
	0x45, 0x7f, 0x7b, 0x9e, 0x03, 0x09, 0x98, 0x9d, 0x00, 0xd6, 0x99, 0x1b, 0xb0, 0x5d, 0x6d, 0x63,
	0xc6, 0xc4, 0x1e, 0x84, 0xb6, 0x0f, 0x11, 0xac, 0xe5, 0xaf, 0xb8, 0xbf, 0x3d, 0xae, 0x55, 0xa4,
	0xb4, 0x18, 0x32, 0x1f, 0xf9, 0x93, 0x81, 0x2e, 0xef, 0x05, 0x22, 0x14, 0x26, 0x87, 0xed, 0xfe,
	0x8d, 0xec, 0xb2, 0xcf, 0x35, 0xcb, 0xe7, 0x6e, 0x5a, 0x7d, 0x29, 0x08, 0x12, 0x52, 0xa1, 0x59,
	0x58, 0x9c, 0xd0, 0x2b, 0xa2, 0xbb, 0x4d, 0xa6, 0x88, 0xab, 0x6a, 0x33, 0xa8, 0x8a, 0x02, 0xad,
	0x8e, 0x16, 0x89, 0xd7, 0x34, 0xe0, 0xba, 0xf5, 0x38, 0xda, 0x92, 0x78, 0x6b, 0x47, 0x57, 0x0c,
	0x75, 0xbd, 0x5c, 0xfb, 0xc1, 0xab, 0x47, 0x48, 0x72, 0x0f, 0x46, 0x10, 0x3c, 0xea, 0xcd, 0x2e,
	0xc0, 0x92, 0x02, 0x1d, 0x6f, 0xa0, 0xcc, 0xac, 0x50, 0x52, 0xd5, 0x0b, 0xdd, 0x06, 0x21, 0xd0,
	0x3b, 0xbb, 0xc3, 0xb5, 0xe5, 0x89, 0xb8, 0x1b, 0x1a, 0xdc, 0x3f, 0x6e, 0xde, 0x9f, 0x39, 0x68,
	0xb2, 0x7c, 0x24, 0xa8, 0x64, 0xfe, 0x4f, 0xce, 0xcf, 0xf1, 0x5d, 0x28, 0xf6, 0xf3, 0xfd, 0x29,
	0xb6, 0xa7, 0x8c, 0xa5, 0x49, 0xeb, 0x9c, 0xee, 0x1c, 0xc4, 0xba, 0xd7, 0x6a, 0x65, 0x43, 0x6d,
	0xc6, 0x8f, 0x7a, 0xd8, 0x7f, 0x96, 0x63, 0x36, 0xf2, 0xdf, 0x62, 0xb0, 0xaa, 0xe1, 0x69, 0x7b,
	0x6c, 0x45, 0x3d, 0xb4, 0x51, 0x22, 0x7d, 0x58, 0xd9, 0x60, 0x56, 0xc2, 0x5f, 0x41, 0x01, 0xff,
	0x54, 0x07, 0xa6, 0xed, 0x20, 0x34, 0x26, 0xc8, 0x94, 0x13, 0x4c, 0xd4, 0x12, 0x25, 0x9e, 0x80,
	0xb7, 0x66, 0x31, 0x30, 0x0c, 0x40, 0x08, 0xc9, 0xe6, 0xf4, 0x8e, 0xc5, 0x82, 0x71, 0x76, 0x7e,
	0x55, 0xef, 0xe9, 0xec, 0x19, 0x98, 0x09, 0xd6, 0xb1, 0xda, 0x5e, 0xbc, 0xd2, 0x03, 0x74, 0x86,
	0x0a, 0x5b, 0x17, 0x53, 0x79, 0x2c, 0xdb, 0x0e, 0x78, 0x04, 0x5a, 0xf9, 0x9d, 0x85, 0x8b, 0x83,
	0xd1, 0x4d, 0xa2, 0x27, 0xb3, 0x14, 0x84, 0xad, 0x61, 0xae, 0x15, 0x90, 0x95, 0x1e, 0xaf, 0x6b,
	0x23, 0xe4, 0x16, 0x91, 0x2f, 0x99, 0xfa, 0x00, 0x1f, 0x33, 0xca, 0xe2, 0x97, 0x2a, 0x67, 0xa9,
	0x0d, 0xe7, 0x2b, 0x4a, 0x44, 0x87, 0x2d, 0x42, 0x9b, 0x32, 0x8a, 0x3e, 0xf5, 0xd3, 0x8d, 0x93,
	0x18, 0x81, 0x37, 0x88, 0xfc, 0x70, 0xf7, 0xc7, 0xa1, 0x38, 0xcb, 0x4e, 0xa4, 0xa3, 0x57, 0x11,
	0xb9, 0x35, 0x73, 0xe8, 0xe0, 0xe3, 0x59, 0x3a, 0x77, 0xbe, 0xf0, 0x05, 0x4b, 0xbf, 0x9a, 0xf8
};

static const uint8_t lut[3][16] = {
	{0x5, 0xa, 0x3, 0x8, 0xf, 0x2, 0x7, 0x9, 0x0, 0x6, 0xe, 0xb, 0xc, 0x1, 0x4, 0xd},
	{0x5, 0xe, 0x8, 0x6, 0x1, 0xc, 0x7, 0x9, 0x0, 0xf, 0x3, 0xb, 0x4, 0xd, 0x2, 0xa},
	{0x4, 0xf, 0xd, 0x5, 0xc, 0x8, 0x2, 0x9, 0xb, 0x1, 0x7, 0x3, 0xa, 0x0, 0x6, 0xe}
};

static const uint8_t key[8] = {0xa9, 0x85, 0x57, 0x4d, 0x8b, 0xf9, 0x81, 0x33};
static const uint8_t gf_idx[8] = {0xc8, 0x73, 0xbf, 0x25, 0xd9, 0x9c, 0x7e, 0x6c};

static int blb3_decrypt(uint8_t* in, size_t _size, const uint8_t* xor_key) {
	unsigned int blb3ScrambleTblIdx;
	uint8_t v, keyIdx;
	size_t j, k;
	if (in == NULL) {
		return -1;
	}
	size_t size = _size < 128 ? _size : 128;
	xorCrypt(in, size > 16 ? 16 : size, xor_key, 16);
	// The next step is only done if the remaining part of the buffer is 16 bytes or more. It's yet another modified AES-128-ECB scrambling routine.
	if (size - 0x10 >= 16) {
		aesGetRoundKeysBlb3(xor_key, blb3AesRoundKeys);
		aesScrambleKeyBlb3(in, blb3AesRoundKeys);
		if (size > 16) {
			// The next step is only done if the buffer is more than 16 bytes. This time, it's modified RC4
			rc4_blb3(in, 8, in + 0x10, size - 0x10, in + 0x8, 8);
		}
		// And finally, it runs the ususal gf256 descrambling routine over the AES data, with a different scrambling table and lookup table than blk/mhy0/mhy1
		uint8_t t[16];
		for (j = 0; j < 3; j++) {
			for (k = 0; k < 16; k++) {
				v = lut[2 - j][k];
				keyIdx = k % 8;
				blb3ScrambleTblIdx = ((k & 3) << 8);
				blb3ScrambleTblIdx |= gf256mul(gf_idx[keyIdx], in[v]);
				t[k] = blb3ScrambleTbl[blb3ScrambleTblIdx] ^ key[keyIdx];
			}
			memcpy(in, t, 16);
		}
	}
	return 0;
}

static int blb3_encrypt(uint8_t* in, size_t _size, const uint8_t* xor_key) {
	unsigned int blb3ScrambleTblIdx;
	uint8_t q, v, keyIdx;
	size_t j, k, l;
	if (in == NULL) {
		return -1;
	}
	size_t size = _size < 128 ? _size : 128;
	uint8_t t[16];
	if (size - 0x10 >= 16) {
		// First step: gf256 scrambling, only if the size is 16 or more
		for (j = 0; j < 3; j++) {
			for (k = 0; k < 16; k++) {
				v = lut[j][k];
				keyIdx = k % 8;
				q = key[keyIdx] ^ in[k];
				for (l = 0; l < 256; l++) {
					blb3ScrambleTblIdx = blb3ScrambleTbl[((k & 3) << 8) | l];
					if (blb3ScrambleTblIdx == q) {
						break;
					}
				}
				t[v] = gf256div(l, gf_idx[keyIdx]);
			}
			memcpy(in, t, 16);
		}
		// Next step: RC4, if the buffer exceeds 16 bytes
		if (size > 16) {
			rc4_dec_blb3(in, 8, in + 16, size - 16, in + 8, 8);
		}
		// Next step: AES-128-ECB
		aesGetRoundKeysBlb3(xor_key, blb3AesRoundKeys);
		aesUnscrambleKeyBlb3(in, blb3AesRoundKeys);
	}
	// And the final touch: XOR
	xorCrypt(in, size > 16 ? 16 : size, xor_key, 16);
	return 0;
}

typedef struct {
	char name[256];
	uint32_t blk_off;
	uint32_t blk_sz;
	uint8_t flag;
} __attribute__((packed)) blb3_cab_serialized_t;

typedef struct {
	uint8_t key[16];
	uint32_t cab_count;
	uint32_t unk0x8;
	uint8_t cmpr_type;
	uint8_t block_sz_shift;
} __attribute__((packed)) blb3_pack_serialized_t;

int extract_blb3(uint8_t* in_buf, const char* filename, uint8_t** _next_blb3) {
	if (in_buf == NULL || filename == NULL) {
		return -1;
	}
	FILE* outfp;
	FILE* file;
	static char filenameBuf[1024];
	uint32_t magic = be32toh(((const uint32_t*) in_buf)[0]);
	if (magic != 0x426c6203) {
		fprintf(stderr, "Bad magic 0x%08x (expected 0x%08x)\n", magic, 0x426c6203);
		return -1;
	}
	uint32_t hdr_sz = le32toh(((const uint32_t*) in_buf)[1]);
	// first 16 bytes are actually an xor/aes key, then the actual encrypted/compressed header
	int ret = blb3_decrypt(in_buf + 0x1c, hdr_sz, in_buf + 12);
	if (ret) {
		fprintf(stderr, "Decryption error (header)\n");
		return ret;
	}
#if 1
	snprintf(filenameBuf, 1024, "%s.hdr_decrypt", filename);
	file = fopen(filenameBuf, "wb");
	if (file == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	fwrite(in_buf, hdr_sz + 0x1c, 1, file);
	fclose(file);
	file = NULL;
#endif
	uint32_t unk_08 = le32toh(((uint32_t*) in_buf)[2]);
	uint32_t filesize = le32toh(((uint32_t*) in_buf)[7]);
	uint8_t* next_blb3 = in_buf + filesize;
	if (_next_blb3 != NULL) *_next_blb3 = next_blb3;
	uint32_t lastBlockDecSz = le32toh(((uint32_t*) in_buf)[8]);
	int32_t blob_off = le32toh(((int32_t*) in_buf)[10]);
	uint32_t blob_sz = le32toh(((uint32_t*) in_buf)[11]);
	uint8_t cmpr_type = in_buf[0x30];
	uint8_t blockDecSzShift = in_buf[0x31];
	uint32_t blockDecSz = 1 << blockDecSzShift;
	uint32_t blockCount = le32toh(((uint32_t*) in_buf)[13]);
	uint32_t nodeCount = le32toh(((uint32_t*) in_buf)[14]);
	int64_t blockTableOff = le64toh(*(int64_t*)(in_buf + 0x3c)) + 0x3c;
	int64_t nodeTableOff = le64toh(*(int64_t*)(in_buf + 0x44)) + 0x44;
	int64_t flagOff = le64toh(*(int64_t*)(in_buf + 0x4c)) + 0x4c;
	fprintf(stderr, "sz 0x%x lastBlockDecSz 0x%x blobOff 0x%x blobSz 0x%x cmprType %d blockDecSz 0x%x blockCnt %d nodeCnt %d blockInfoOff 0x%lx nodeInfoOff 0x%lx flagOff 0x%lx\n", filesize, lastBlockDecSz, blob_off, blob_sz, cmpr_type, blockDecSz, blockCount, nodeCount, blockTableOff, nodeTableOff, flagOff);
	/* These seem to be the same as in ENCR files */
#if 1
	if (!((cmpr_type == 0) || (cmpr_type == 2) || (cmpr_type == 3) || (cmpr_type == 5))) {
		fprintf(stderr, "Error: Only blb3 files compressed with lz4 or lz4hc, or uncompressed, are supported at the moment. (ctype = %d)\n", cmpr_type);
		return -1;
	}
#endif
	blb3_pack_serialized_t pack_meta;
	pack_meta.cab_count = htobe32(nodeCount);
	pack_meta.unk0x8 = htobe32(unk_08);
	pack_meta.cmpr_type = cmpr_type;
	pack_meta.block_sz_shift = blockDecSzShift;
	memcpy(pack_meta.key, in_buf + 12, 16);
	snprintf(filenameBuf, 1024, "%s.hdr", filename);
	file = fopen(filenameBuf, "wb");
	if (file == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	fwrite(&pack_meta, sizeof(blb3_pack_serialized_t), 1, file);
	fclose(file);
	file = NULL;
	blb3_cab_serialized_t cab_meta[nodeCount];
	unsigned int i;
	uint32_t cmprSize;
	uint32_t decSize;
	int32_t nodeOff;
	int64_t nameOff;
	uint32_t flag;
	const char* name;
	size_t dec_block_size = 0;
	for (i = 0; i < nodeCount; i++) {
		nodeOff = le32toh(*(int32_t*)(in_buf + nodeTableOff + (i * 16)));
		decSize = le32toh(*(uint32_t*)(in_buf + nodeTableOff + (i * 16) + 4));
		nameOff = le32toh(*(int64_t*)(in_buf + nodeTableOff + (i * 16) + 8));
		dec_block_size += decSize;
		name = (const char*) (in_buf + nodeTableOff + (i * 16) + 8 + nameOff);
		flag = (le32toh(*(uint32_t*)(in_buf + flagOff + (i >> 5))) >> i) & 1;
		fprintf(stderr, "node %d: name %s off 0x%x size 0x%x flag 0x%x\n", i, name, nodeOff, decSize, flag);
		strncpy(cab_meta[i].name, name, 256);
		cab_meta[i].blk_off = htobe32(nodeOff);
		cab_meta[i].blk_sz = htobe32(decSize);
		cab_meta[i].flag = flag;
		snprintf(filenameBuf, 1024, "%s.cab%d.hdr", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			return -1;
		}
		fwrite(&(cab_meta[i]), sizeof(blb3_cab_serialized_t), 1, file);
		fclose(file);
		file = NULL;
	}
	uint8_t* blk_data_buf = malloc(dec_block_size);
	if (blk_data_buf == NULL) {
		fprintf(stderr, "Can't allocate decompression buffer (blocks)\n");
		return -1;
	}
	uint64_t data_off = hdr_sz + 0x1c;
	uint64_t dec_data_off = 0;
	size_t total_sz = 0;
	for (i = 0; i < blockCount; i++) {
		cmprSize = le32toh(*(uint32_t*)(in_buf + blockTableOff + (i * 4))) - total_sz;
		decSize = (i + 1) == blockCount ? lastBlockDecSz : blockDecSz;
		fprintf(stderr, "block %d: off 0x%lx cmprSize 0x%x uncmpSize 0x%x\n", i, data_off, cmprSize, decSize);
		ret = blb3_decrypt(in_buf + data_off, cmprSize, in_buf + 12);
		if (ret) {
			fprintf(stderr, "Decryption error (blocks)\n");
			return ret;
		}
#if 0
		snprintf(filenameBuf, 1024, "%s.blk%d.decrypt", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(blk_data_buf);
			return -1;
		}
		fwrite(in_buf + data_off, cmprSize, 1, file);
		fclose(file);
		file = NULL;
#endif
		if (cmpr_type == 0) {
			memcpy((blk_data_buf + dec_data_off), (in_buf + data_off), cmprSize);
		}
		else {
			ret = LZ4_decompress_safe((const char*) (in_buf + data_off), (char*) (blk_data_buf + dec_data_off), cmprSize, decSize);
			if (ret < 0) {
				fprintf(stderr, "LZ4 decompress error %d when decoding data (blk %d)\n", -ret, i);
				free(blk_data_buf);
				return -1;
			}
		}
		data_off += cmprSize;
		dec_data_off += decSize;
		total_sz += cmprSize;
	}
	for (i = 0; i < nodeCount; i++) {
		snprintf(filenameBuf, 1024, "%s.cab%d", filename, i);
		outfp = fopen(filenameBuf, "wb");
		if (outfp == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(blk_data_buf);
			return -1;
		}
		fwrite(blk_data_buf + be32toh(cab_meta[i].blk_off), be32toh(cab_meta[i].blk_sz), 1, outfp);
		fclose(outfp);
	}
	fprintf(stderr, "total size of this blb3 0x%08lx\n", total_sz);
	fprintf(stderr, "if present, the next one should be at 0x%08lx\n", (unsigned long) next_blb3);
	free(blk_data_buf);
	return 0;
}

// TODO: Block size shouldn't be hardcoded here; it's a header field we can read from s_pack.block_sz_shift
int pack_blb3(const char* in_filename, FILE* out_fp) {
	if (in_filename == NULL || out_fp == NULL) {
		return -1;
	}
	FILE* in_fp2;
	static char filenameBuf[1024];
	uint32_t cab_cnt, cab_blk_cnt;
	uint32_t blk_cnt = 0;
	uint64_t cab_blk_off = 0;
	uint64_t cab_blk_sz, blk_sz;
	uint32_t block_sz_full = 0x20000;
	blb3_pack_serialized_t s_pack;
	snprintf(filenameBuf, 1024, "%s.hdr", in_filename);
	in_fp2 = fopen(filenameBuf, "rb");
	if (in_fp2 == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
#if 0
		return -1;
#else
		fprintf(stderr, "Assuming 1 cab file present, lz4hc compression, 128k block size\n");
		s_pack.cab_count = htobe32(1);
		s_pack.unk0x8 = htobe32(5);
		s_pack.block_sz_shift = htobe32(17);
		s_pack.cmpr_type = htobe32(3);
		getrandom(s_pack.key, 16, 0);
		//block_sz_full = 0x20000;
#endif
	}
	else {
		fread(&s_pack, 1, sizeof(blb3_pack_serialized_t), in_fp2);
		fclose(in_fp2);
		in_fp2 = NULL;
		//block_sz_full = 1 << s_pack.block_sz_shift;
	}
	cab_cnt = be32toh(s_pack.cab_count);
	if (cab_cnt >= 256) cab_cnt = 256;
	blb3_cab_serialized_t s_cab[cab_cnt];
	FILE* in_fp[cab_cnt];
	unsigned int i;
	uint32_t total_blk_sz = 0;
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
		total_blk_sz += cab_blk_sz;
		snprintf(filenameBuf, 1024, "%s.cab%d.hdr", in_filename, i);
		in_fp2 = fopen(filenameBuf, "rb");
		if (in_fp2 != NULL) {
			fread(&s_cab[i], sizeof(blb3_cab_serialized_t), 1, in_fp2);
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
			s_cab[i].flag = 0;
		}
		s_cab[i].blk_off = cab_blk_off;
		s_cab[i].blk_sz = cab_blk_sz;
		cab_blk_off += cab_blk_sz;
	}
	cab_blk_cnt = total_blk_sz / block_sz_full;
	if ((total_blk_sz % block_sz_full) != 0) {
		cab_blk_cnt++;
	}
	blk_cnt = cab_blk_cnt;
	FILE* tmp_blk_fp;
	snprintf(filenameBuf, 1024, "%s.blocks", in_filename);
	tmp_blk_fp = fopen(filenameBuf, "wb+");
	if (tmp_blk_fp == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		return -1;
	}
	uint8_t* dec_buf = malloc(block_sz_full);
	if (dec_buf == NULL) {
		fprintf(stderr, "Can't allocate block buffer\n");
		return -1;
	}
	uint8_t* cmp_buf = malloc(block_sz_full * 25 / 10);
	if (cmp_buf == NULL) {
		fprintf(stderr, "Can't allocate block compression buffer\n");
		free(dec_buf);
		return -1;
	}
	ssize_t written = 0;
	ssize_t read;
	unsigned int j = 0;
	uint32_t blocks[blk_cnt][2]; // compressed, then decompressed sizes for each block
	uint32_t remaining_sz = block_sz_full;
	uint32_t read_sz = 0;
	uint32_t read_off = 0;
	blk_sz = 0;
	cab_blk_off = 0;
	for (i = 0; i < blk_cnt;) {
		if (remaining_sz <= 0 || remaining_sz >= block_sz_full) {
			remaining_sz = block_sz_full;
			blk_sz = 0;
		}
		if (s_cab[j].blk_sz - cab_blk_off <= remaining_sz) {
			blk_sz += s_cab[j].blk_sz - cab_blk_off;
			remaining_sz -= s_cab[j].blk_sz - cab_blk_off;
			read_sz = s_cab[j].blk_sz - cab_blk_off;
			cab_blk_off = 0;
		}
		else if (remaining_sz > 0 && remaining_sz < block_sz_full && s_cab[j].blk_sz - cab_blk_off > remaining_sz) {
			cab_blk_off += remaining_sz;
			blk_sz += remaining_sz;
			read_sz = remaining_sz;
			remaining_sz = 0;
		}
		else {
			blk_sz += remaining_sz;
			cab_blk_off += blk_sz;
			remaining_sz = 0;
			read_sz = block_sz_full;
		}
		fread(dec_buf + read_off, 1, read_sz, in_fp[j]);
		if (cab_blk_off <= 0) {
			fclose(in_fp[j]);
			j++;
		}
		if (!(j >= cab_cnt)) {
			if (remaining_sz > 0 && remaining_sz < block_sz_full) {
				read_off += read_sz;
				continue;
			}
		}
		//read = LZ4_compress_default((const char*) dec_buf, (char*) (cmp_buf + 12), blk_sz, 0x4fff4);
		read = LZ4_compress_HC((const char*) dec_buf, (char*) cmp_buf, blk_sz, block_sz_full * 25 / 10, 12);
		if (read < 0) {
			fprintf(stderr, "Can't compress block %d\n", i);
			return -1;
		}
		blocks[i][0] = read;
		blocks[i][1] = blk_sz;
		blb3_encrypt(cmp_buf, read, s_pack.key);
		written += fwrite(cmp_buf, 1, read, tmp_blk_fp);
		read_off = 0;
		i++;
	}
	fflush(tmp_blk_fp);
	fseek(tmp_blk_fp, 0, SEEK_SET);
	free(cmp_buf);
	unsigned int hdr_sz = 60 + (blk_cnt * 4) + (cab_cnt * 16);
	uint8_t* hdr_buf = malloc(hdr_sz + 0x1c + (256 * cab_cnt));
		if (hdr_buf == NULL) {
		fprintf(stderr, "Can't allocate header buffer\n");
		return -1;
	}
	*(uint32_t*) hdr_buf = htobe32(0x426c6203);
	*(uint32_t*)(hdr_buf + 0x8) = htobe32(s_pack.unk0x8);
	memcpy(hdr_buf + 0xc, s_pack.key, 16);
	*(uint32_t*)(hdr_buf + 0x24) = htole32(0); // Unknown, probably reserved (maybe lower 32 bits of blob offset actually)
	*(int32_t*)(hdr_buf + 0x28) = htole32(0); // TODO Blob offset (could actually be the upper 32 bits)
	*(uint32_t*)(hdr_buf + 0x2c) = htole32(0); // TODO Blob size
	*(uint32_t*)(hdr_buf + 0x30) = htole32((17/*s_pack.block_sz_shift*/ << 8) | 3/*s_pack.cmpr_type*/);
	*(uint32_t*)(hdr_buf + 0x34) = htole32(blk_cnt);
	*(uint32_t*)(hdr_buf + 0x38) = htole32(cab_cnt);
	*(int64_t*)(hdr_buf + 0x3c) = htole64(0x18); // 0x54 - 0x3c
	*(int64_t*)(hdr_buf + 0x44) = htole64((blk_cnt * 4) + 0x14); // 0x58 - 0x44
	uint32_t flag_size = cab_cnt / 32;
	if (cab_cnt % 32 != 0) flag_size++;
	uint32_t flag_vals[flag_size];
	memset(flag_vals, 0, sizeof(uint32_t) * flag_size);
	for (i = 0; i < cab_cnt; i++) {
		flag_vals[i / 32] |= (s_cab[i].flag ? 1 : 0) << i;
	}
	if (blk_cnt == flag_vals[0]) {
		flag_size = 0;
		*(int64_t*)(hdr_buf + 0x4c) = htole64(-0x18); // 0x34 - 0x4c
	}
	else if (cab_cnt == flag_vals[0]) {
		flag_size = 0;
		*(int64_t*)(hdr_buf + 0x4c) = htole64(-0x14); // 0x38 - 0x4c
	}
	else {
		*(int64_t*)(hdr_buf + 0x4c) = htole64((blk_cnt * 4) + (cab_cnt * 16) + 0xc); // 0x58 - 0x4c (TODO We store these before the cab names. Hoyo's packer stores them after.)
		memcpy(hdr_buf + 0x58 + (blk_cnt * 4) + (cab_cnt * 16), flag_vals, sizeof(uint32_t) * flag_size);
	}
	hdr_sz += sizeof(uint32_t) * flag_size;
	total_blk_sz = 0;
	for (i = 0; i < blk_cnt; i++) {
		*(uint32_t*)(hdr_buf + 0x54 + (i * 4)) = htole32(blocks[i][0] + total_blk_sz);
		total_blk_sz += blocks[i][0];
		if (i + 1 == blk_cnt) {
			*(uint32_t*)(hdr_buf + 0x20) = htole32(blocks[i][1]);
		}
	}
	int64_t name_off = 0x58 + (4 * blk_cnt) + (16 * cab_cnt) + (4 * flag_size);
	size_t cab_name_sz;
	*(uint32_t*)(hdr_buf + 0x54 + (4 * blk_cnt)) = 0;
	for (i = 0; i < cab_cnt; i++) {
		*(uint32_t*)(hdr_buf + 0x58 + (4 * blk_cnt) + (i * 16)) = htole32(s_cab[i].blk_off);
		*(uint32_t*)(hdr_buf + 0x5c + (4 * blk_cnt) + (i * 16)) = htole32(s_cab[i].blk_sz);
		*(int64_t*)(hdr_buf + 0x60 + (4 * blk_cnt) + (i * 16)) = htole64(name_off - (0x60 + (4 * blk_cnt) + (i * 16)));
		cab_name_sz = strnlen(s_cab[i].name, 256) + 1;
		strncpy((char*)(hdr_buf + name_off), s_cab[i].name, cab_name_sz);
		hdr_sz += cab_name_sz;
		name_off += cab_name_sz;
	}
	uint32_t file_size = hdr_sz + written + 0x1c;
	*(uint32_t*)(hdr_buf + 0x4) = htole32(hdr_sz);
	*(uint32_t*)(hdr_buf + 0x1c) = htole32(file_size);
	blb3_encrypt(hdr_buf + 0x1c, hdr_sz, s_pack.key);
	ssize_t out_sz = fwrite(hdr_buf, 1, hdr_sz + 0x1c, out_fp);
	ssize_t in_sz;
	while (written > 0) {
		in_sz = fread(dec_buf, 1, block_sz_full, tmp_blk_fp);
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
