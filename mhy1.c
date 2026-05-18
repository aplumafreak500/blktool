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

/* located in mhy0.c and blk.c */
extern const uint8_t gf256exp[256];
extern const uint8_t gf256log[256];
extern const uint8_t lut[3][16];
extern const uint8_t key[8];
extern const uint8_t gf_idx[8];
extern const uint8_t blkScrambleTbl[0x400];
uint8_t gf256mul(uint8_t a, uint8_t b);
uint8_t gf256div(uint8_t a, uint8_t b);
int32_t unshuffleInt(const uint8_t* buf);
uint32_t unshuffleUint(const uint8_t* buf);
void shuffleInt(uint8_t* buf, int32_t i);
void shuffleUint(uint8_t* buf, uint32_t i);

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
	/* TODO by here, uint64 at in+4 should equal 0x6d68796e65776563 (b"mhynewec") */
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
#if 1
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
#if 1
	snprintf(filenameBuf, 1024, "%s.hdr_decomp", filename);
	file = fopen(filenameBuf, "wb");
	if (file == NULL) {
		fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
		free(hdr_buf);
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
		free(hdr_buf);
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
			free(data_buf);
			return -1;
		}
#if 1
		snprintf(filenameBuf, 1024, "%s.blk%d.decrypt", filename, i);
		file = fopen(filenameBuf, "wb");
		if (file == NULL) {
			fprintf(stderr, "Can't open file %s: %s\n", filenameBuf, strerror(errno));
			free(hdr_buf);
			free(data_buf);
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
			free(data_buf);
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
			free(data_buf);
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
	free(data_buf);
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
		free(dec_buf);
		return -1;
	}
	cmp_buf = malloc(0x50000);
	if (cmp_buf == NULL) {
		fprintf(stderr, "Can't allocate block compression buffer\n");
		free(dec_buf);
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
			free(dec_buf);
			free(cmp_buf);
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
		free(dec_buf);
		return -1;
	}
	cmp_buf = malloc(cmp_sz);
	if (cmp_buf == NULL) {
		fprintf(stderr, "Can't allocate compressed header buffer\n");
		free(hdr_buf);
		free(dec_buf);
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
		free(hdr_buf);
		free(dec_buf);
		free(cmp_buf);
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
	free(dec_buf);
	free(cmp_buf);
	return 0;
}
