/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <endian.h>
#include <sys/random.h>
#include "blk.h"
#include "mhy0.h"
#include "mhy1.h"
#include "encr.h"
#include "blb3.h"
#include "mr0k.h"
#include "ec2b.h"
#include "mhycrypt.h"

static void usage() {
	fprintf(stderr, "usage: %s <type>\n", program_invocation_name);
	fprintf(stderr, "type can be `blk`, `mhy0`, or `ec2b`\n");
}

static void blk_usage() {
	fprintf(stderr, "usage: %s blk <mode> <input> <output> (seed)\n", program_invocation_name);
	fprintf(stderr, "mode can be `encrypt` or `decrypt`\n(seed file is optional)\n");
}

static void mhy0_usage() {
	fprintf(stderr, "usage: %s mhy0 <mode> <input> <output>\n", program_invocation_name);
	fprintf(stderr, "mode can be `pack` or `unpack`\n");
}

static void mhy1_usage() {
	fprintf(stderr, "usage: %s mhy1 <mode> <input> <output>\n", program_invocation_name);
	fprintf(stderr, "mode can be `pack` or `unpack`\n");
}

static void ec2b_usage() {
	fprintf(stderr, "usage: %s ec2b xor <input> <output>\n", program_invocation_name);
	fprintf(stderr, "       %s ec2b gen <output>\n", program_invocation_name);
	fprintf(stderr, "       %s ec2b edit <arguments> <input>\n", program_invocation_name);
	fprintf(stderr, "please run `%s ec2b edit -h` for further help", program_invocation_name);
}

static void ec2b_xor_usage() {
	fprintf(stderr, "usage: %s ec2b xor <input> <output>\n", program_invocation_name);
}

static void ec2b_gen_usage() {
	fprintf(stderr, "usage: %s ec2b gen <output>\n", program_invocation_name);
}

static void ec2b_edit_usage() {
	fprintf(stderr, "usage: %s ec2b edit <arguments> <input>\n", program_invocation_name);
	fprintf(stderr, "please run `%s ec2b edit -h` for further help", program_invocation_name);
}

static void ec2b_edit_help() {
	fprintf(stderr, "usage: %s ec2b edit <arguments> <input>\n", program_invocation_name);
	fprintf(stderr, "arguments:\n"
	"-h: show this help\n"
	"-g: regenerate scrambling key\n"
	"-d: regenerate scrambling data\n"
	"-s: regenerate xor seed\n"
	"-S <seed>: provide a new xor seed\n"
	"-o <output>: place new file in <output> instead of editing <input> in place\n"
	"-i <input>: specify input\n");
}

typedef struct {
	uint64_t seed;
	uint8_t key[32];
	uint16_t blkSz;
} __attribute__((packed)) seed_t;

static unsigned int blk_main(unsigned int argc, const char** argv) {
	if (argc < 4) {
		blk_usage();
		return -1;
	}
	const char* mode = argv[1];
	const char* in_file = argv[2];
	const char* out_file = argv[3];
	const char* seed_file = NULL;
	if (argc >= 4) {
		seed_file = argv[4];
	}
	FILE* in_fp = fopen(in_file, "rb");
	if (in_fp == NULL) {
		fprintf(stderr, "input file open error: %s\n", strerror(errno));
		return -1;
	}
	FILE* out_fp = fopen(out_file, "wb");
	if (out_fp == NULL) {
		fprintf(stderr, "output file open error: %s\n", strerror(errno));
		return -1;
	}
	FILE* seed_fp = NULL;
	blk0_header_t hdr;
	seed_t seed;
	uint8_t* buf;
	size_t bufSz;
	if (strncasecmp(mode, "encrypt", 8) == 0) {
		unsigned int hasSeed = 0;
		if (seed_file != NULL) {
			seed_fp = fopen(seed_file, "rb");
		}
		if (seed_fp != NULL) {
#ifndef NDEBUG
			memset(&seed, 0, sizeof(seed));
#endif
			fread(&seed, sizeof(seed), 1, seed_fp);
			fclose(seed_fp);
			fprintf(stderr, "Read from seed file %s\n", seed_file);
			hasSeed = 1;
		}
		else {
			getrandom(&seed, sizeof(seed) - sizeof(uint16_t), 0);
		}
		fseek(in_fp, 0, SEEK_END);
		bufSz = ftell(in_fp);
		fseek(in_fp, 0, SEEK_SET);
		buf = malloc(bufSz);
		if (buf == NULL) {
			fprintf(stderr, "can't allocate buffer\n");
			return -1;
		}
		fread(buf, bufSz, 1, in_fp);
		fclose(in_fp);
		if (!hasSeed) seed.blkSz = bufSz <= 2048 ? bufSz : 2048;
		seed.blkSz = be16toh(seed.blkSz) & ~7;
		seed.seed = be64toh(seed.seed);
		fprintf(stderr, "Read from input file %s\n", in_file);
		fprintf(stderr, "\t(key1 hex: %016llx%016llx key2 hex: %016llx%016llx seed size: %hu seed: 0x%016llx)\n", (unsigned long long) be64toh(((uint64_t*) seed.key)[0]), (unsigned long long) be64toh(((uint64_t*) seed.key)[1]), (unsigned long long) be64toh(((uint64_t*) seed.key)[2]), (unsigned long long) be64toh(((uint64_t*) seed.key)[3]), seed.blkSz, (unsigned long long) seed.seed);
		encrypt_blk0(buf, bufSz, seed.blkSz, seed.key, seed.seed);
		hdr.magic = htobe32(0x626c6b00);
		hdr.version = htole32(16);
		memcpy(hdr.key1, seed.key, 32);
		hdr.blkSz = htole16(seed.blkSz);
		fwrite(&hdr, sizeof(hdr), 1, out_fp);
		fwrite(buf, bufSz, 1, out_fp);
		fclose(out_fp);
		fprintf(stderr, "Wrote to output file %s\n", out_file);
		fprintf(stderr, "\t(key1 hex: %016llx%016llx key2 hex: %016llx%016llx seed size: %hu)\n", (unsigned long long) be64toh(((uint64_t*) seed.key)[0]), (unsigned long long) be64toh(((uint64_t*) seed.key)[1]), (unsigned long long) be64toh(((uint64_t*) seed.key)[2]), (unsigned long long) be64toh(((uint64_t*) seed.key)[3]), seed.blkSz);
		return 0;
	}
	else if (strncasecmp(mode, "decrypt", 8) == 0) {
		fseek(in_fp, 0, SEEK_END);
		bufSz = ftell(in_fp) - sizeof(hdr);
		fseek(in_fp, 0, SEEK_SET);
		buf = malloc(bufSz);
		if (buf == NULL) {
			fprintf(stderr, "can't allocate buffer\n");
			return -1;
		}
		fread(&hdr, sizeof(hdr), 1, in_fp);
		fread(buf, bufSz, 1, in_fp);
		fclose(in_fp);
		fprintf(stderr, "Read from input file %s\n", in_file);
		if (be32toh(hdr.magic) != 0x626c6b00) {
			fprintf(stderr, "Bad file magic 0x%08x\n", be32toh(hdr.magic));
			return -1;
		}
		if (le32toh(hdr.version) != 16) {
			fprintf(stderr, "Bad file version %u\n", le32toh(hdr.version));
			return -1;
		}
		uint64_t seed_in;
		fprintf(stderr, "\t(key1 hex: %016llx%016llx key2 hex: %016llx%016llx seed size: %hu)\n", (unsigned long long) be64toh(((uint64_t*) hdr.key1)[0]), (unsigned long long) be64toh(((uint64_t*) hdr.key1)[1]), (unsigned long long) be64toh(((uint64_t*) hdr.key2)[0]), (unsigned long long) be64toh(((uint64_t*) hdr.key2)[1]), le16toh(hdr.blkSz));
		decrypt_blk0(buf, bufSz, le16toh(hdr.blkSz), hdr.key1, &seed_in, NULL);
		fwrite(buf, bufSz, 1, out_fp);
		fclose(out_fp);
		fprintf(stderr, "Wrote to output file %s\n", out_file);
		fprintf(stderr, "\t(key1 hex: %016llx%016llx key2 hex: %016llx%016llx seed size: %hu seed: 0x%016llx)\n", (unsigned long long) be64toh(((uint64_t*) hdr.key1)[0]), (unsigned long long) be64toh(((uint64_t*) hdr.key1)[1]), (unsigned long long) be64toh(((uint64_t*) hdr.key2)[0]), (unsigned long long) be64toh(((uint64_t*) hdr.key2)[1]), le16toh(hdr.blkSz), (unsigned long long) seed_in);
		if (seed_file != NULL) {
			seed_fp = fopen(seed_file, "wb");
			if (seed_fp != NULL) {
				seed.seed = htobe64(seed_in);
				memcpy(seed.key, hdr.key1, 32);
				seed.blkSz = htobe16(le16toh(hdr.blkSz));
				fwrite(&seed, sizeof(seed), 1, seed_fp);
				fclose(seed_fp);
				fprintf(stderr, "Wrote to seed file %s\n", seed_file);
			}
		}
		return 0;
	}
	blk_usage();
	return -1;
}

static unsigned int mhy0_main(unsigned int argc, const char** argv) {
	if (argc < 4) {
		mhy0_usage();
		return -1;
	}
	const char* mode = argv[1];
	const char* in_file = argv[2];
	const char* out_file = argv[3];
	uint8_t* buf;
	size_t bufSz;
	static char filenameBuf[1024];
	unsigned int i = 0;
	int ret;
	if (strncasecmp(mode, "pack", 4) == 0) {
		FILE* out_fp = fopen(out_file, "wb");
		if (out_fp == NULL) {
			fprintf(stderr, "output file open error: %s\n", strerror(errno));
			return -1;
		}
		unsigned int mhy0_cnt;
		if (argc > 4) {
			mhy0_cnt = strtoul(argv[4], NULL, 10);
		}
		else {
			mhy0_cnt = 1;
		}
		for (i = 0; i < mhy0_cnt; i++) {
			snprintf(filenameBuf, 1024, "%s.pack%d", in_file, i);
			ret = pack_mhy0(filenameBuf, out_fp);
			if (ret) {
				fprintf(stderr, "can't pack mhy0 data from packfile(s) %s*\n", filenameBuf);
				fclose(out_fp);
				return ret;
			}
		}
		fclose(out_fp);
		fprintf(stderr, "Sucessfully packed mhy0 file %s\n", out_file);
		return 0;
	}
	else if (strncasecmp(mode, "unpack", 6) == 0) {
		FILE* in_fp = fopen(in_file, "rb");
		if (in_fp == NULL) {
			fprintf(stderr, "input file open error: %s\n", strerror(errno));
			return -1;
		}
		fseek(in_fp, 0, SEEK_END);
		bufSz = ftell(in_fp);
		fseek(in_fp, 0, SEEK_SET);
		buf = malloc(bufSz);
		if (buf == NULL) {
			fprintf(stderr, "can't allocate buffer\n");
			return -1;
		}
		fread(buf, bufSz, 1, in_fp);
		fclose(in_fp);
		fprintf(stderr, "Read from input file %s\n", in_file);
		uint8_t* next_mhy0 = buf;
		uint8_t* current_mhy0 = buf;
		while (current_mhy0 < buf + bufSz) {
			snprintf(filenameBuf, 1024, "%s.pack%d", out_file, i);
			fprintf(stderr, "buf 0x%08lx bufSz 0x%08lx eof 0x%08lx current_mhy0 0x%08lx file %s\n", (unsigned long) buf, bufSz, (unsigned long) buf + bufSz, (unsigned long) current_mhy0, filenameBuf);
			ret = extract_mhy0(current_mhy0, filenameBuf, &next_mhy0);
			if (ret) {
				fprintf(stderr, "can't extract mhy0 data at offset 0x%08lx\n", (unsigned long) current_mhy0 - (unsigned long) buf);
				return ret;
			}
			current_mhy0 = next_mhy0;
			i++;
		}
		fprintf(stderr, "Sucessfully extracted mhy0 file %s\n", in_file);
		return 0;
	}
	mhy0_usage();
	return -1;
}

static unsigned int mhy1_main(unsigned int argc, const char** argv) {
	if (argc < 4) {
		mhy1_usage();
		return -1;
	}
	const char* mode = argv[1];
	const char* in_file = argv[2];
	const char* out_file = argv[3];
	uint8_t* buf;
	size_t bufSz;
	static char filenameBuf[1024];
	unsigned int i = 0;
	int ret;
	if (strncasecmp(mode, "pack", 4) == 0) {
		FILE* out_fp = fopen(out_file, "wb");
		if (out_fp == NULL) {
			fprintf(stderr, "output file open error: %s\n", strerror(errno));
			return -1;
		}
		unsigned int mhy1_cnt;
		if (argc > 4) {
			mhy1_cnt = strtoul(argv[4], NULL, 10);
		}
		else {
			mhy1_cnt = 1;
		}
		for (i = 0; i < mhy1_cnt; i++) {
			snprintf(filenameBuf, 1024, "%s.pack%d", in_file, i);
			ret = pack_mhy1(filenameBuf, out_fp);
			if (ret) {
				fprintf(stderr, "can't pack mhy1 data from packfile(s) %s*\n", filenameBuf);
				fclose(out_fp);
				return ret;
			}
		}
		fclose(out_fp);
		fprintf(stderr, "Sucessfully packed mhy1 file %s\n", out_file);
		return 0;
	}
	else if (strncasecmp(mode, "unpack", 6) == 0) {
		FILE* in_fp = fopen(in_file, "rb");
		if (in_fp == NULL) {
			fprintf(stderr, "input file open error: %s\n", strerror(errno));
			return -1;
		}
		fseek(in_fp, 0, SEEK_END);
		bufSz = ftell(in_fp);
		fseek(in_fp, 0, SEEK_SET);
		buf = malloc(bufSz);
		if (buf == NULL) {
			fprintf(stderr, "can't allocate buffer\n");
			return -1;
		}
		fread(buf, bufSz, 1, in_fp);
		fclose(in_fp);
		fprintf(stderr, "Read from input file %s\n", in_file);
		uint8_t* next_mhy1 = buf;
		uint8_t* current_mhy1 = buf;
		while (current_mhy1 < buf + bufSz) {
			snprintf(filenameBuf, 1024, "%s.pack%d", out_file, i);
			fprintf(stderr, "buf 0x%08lx bufSz 0x%08lx eof 0x%08lx current_mhy1 0x%08lx file %s\n", (unsigned long) buf, bufSz, (unsigned long) buf + bufSz, (unsigned long) current_mhy1, filenameBuf);
			ret = extract_mhy1(current_mhy1, filenameBuf, &next_mhy1);
			if (ret) {
				fprintf(stderr, "can't extract mhy1 data at offset 0x%08lx\n", (unsigned long) current_mhy1 - (unsigned long) buf);
				return ret;
			}
			current_mhy1 = next_mhy1;
			i++;
		}
		fprintf(stderr, "Sucessfully extracted mhy1 file %s\n", in_file);
		return 0;
	}
	mhy1_usage();
	return -1;
}

static unsigned int encr_main(unsigned int argc, const char** argv) {
	if (argc < 4) {
		//encr_usage();
		return -1;
	}
	const char* mode = argv[1];
	const char* in_file = argv[2];
	const char* out_file = argv[3];
	uint8_t* buf;
	size_t bufSz;
	static char filenameBuf[1024];
	unsigned int i = 0;
	int ret;
	if (strncasecmp(mode, "pack", 4) == 0) {
#if 0
		fprintf(stderr, "ENCR packing is not implemented yet.\nPlease check back in later.");
		return 10;
#else
		FILE* out_fp = fopen(out_file, "wb");
		if (out_fp == NULL) {
			fprintf(stderr, "output file open error: %s\n", strerror(errno));
			return -1;
		}
		unsigned int encr_cnt;
		if (argc > 4) {
			encr_cnt = strtoul(argv[4], NULL, 10);
		}
		else {
			encr_cnt = 1;
		}
		for (i = 0; i < encr_cnt; i++) {
			snprintf(filenameBuf, 1024, "%s.pack%d", in_file, i);
			ret = pack_encr(filenameBuf, out_fp);
			if (ret) {
				fprintf(stderr, "can't pack encr data from packfile(s) %s*\n", filenameBuf);
				fclose(out_fp);
				return ret;
			}
		}
		fclose(out_fp);
		fprintf(stderr, "Sucessfully packed encr file %s\n", out_file);
		return 0;
#endif
	}
	else if (strncasecmp(mode, "unpack", 6) == 0) {
		FILE* in_fp = fopen(in_file, "rb");
		if (in_fp == NULL) {
			fprintf(stderr, "input file open error: %s\n", strerror(errno));
			return -1;
		}
		fseek(in_fp, 0, SEEK_END);
		bufSz = ftell(in_fp);
		fseek(in_fp, 0, SEEK_SET);
		buf = malloc(bufSz);
		if (buf == NULL) {
			fprintf(stderr, "can't allocate buffer\n");
			return -1;
		}
		fread(buf, bufSz, 1, in_fp);
		fclose(in_fp);
		fprintf(stderr, "Read from input file %s\n", in_file);
		const uint8_t* next_encr = buf;
		const uint8_t* current_encr = buf;
		while (current_encr < buf + bufSz) {
			snprintf(filenameBuf, 1024, "%s.pack%d", out_file, i);
			fprintf(stderr, "buf 0x%08lx bufSz 0x%08lx eof 0x%08lx current_encr 0x%08lx file %s\n", (unsigned long) buf, bufSz, (unsigned long) buf + bufSz, (unsigned long) current_encr, filenameBuf);
			ret = extract_encr(current_encr, filenameBuf, &next_encr);
			if (ret) {
				fprintf(stderr, "can't extract encr data at offset 0x%08lx\n", (unsigned long) current_encr - (unsigned long) buf);
				return ret;
			}
			current_encr = next_encr;
			i++;
		}
		fprintf(stderr, "Sucessfully extracted encr file %s\n", in_file);
		return 0;
	}
	//encr_usage();
	return -1;
}

static unsigned int blb3_main(unsigned int argc, const char** argv) {
	if (argc < 4) {
		//blb3_usage();
		return -1;
	}
	const char* mode = argv[1];
	const char* in_file = argv[2];
	const char* out_file = argv[3];
	uint8_t* buf;
	size_t bufSz;
	static char filenameBuf[1024];
	unsigned int i = 0;
	int ret;
	if (strncasecmp(mode, "pack", 4) == 0) {
		FILE* out_fp = fopen(out_file, "wb");
		if (out_fp == NULL) {
			fprintf(stderr, "output file open error: %s\n", strerror(errno));
			return -1;
		}
		unsigned int blb3_cnt;
		if (argc > 4) {
			blb3_cnt = strtoul(argv[4], NULL, 10);
		}
		else {
			blb3_cnt = 1;
		}
		for (i = 0; i < blb3_cnt; i++) {
			snprintf(filenameBuf, 1024, "%s.pack%d", in_file, i);
			ret = pack_blb3(filenameBuf, out_fp);
			if (ret) {
				fprintf(stderr, "can't pack blb3 data from packfile(s) %s*\n", filenameBuf);
				fclose(out_fp);
				return ret;
			}
		}
		fclose(out_fp);
		fprintf(stderr, "Sucessfully packed blb3 file %s\n", out_file);
		return 0;
	}
	else if (strncasecmp(mode, "unpack", 6) == 0) {
		FILE* in_fp = fopen(in_file, "rb");
		if (in_fp == NULL) {
			fprintf(stderr, "input file open error: %s\n", strerror(errno));
			return -1;
		}
		fseek(in_fp, 0, SEEK_END);
		bufSz = ftell(in_fp);
		fseek(in_fp, 0, SEEK_SET);
		buf = malloc(bufSz);
		if (buf == NULL) {
			fprintf(stderr, "can't allocate buffer\n");
			return -1;
		}
		fread(buf, bufSz, 1, in_fp);
		fclose(in_fp);
		fprintf(stderr, "Read from input file %s\n", in_file);
		uint8_t* next_blb3 = buf;
		uint8_t* current_blb3 = buf;
		while (current_blb3 < buf + bufSz) {
			snprintf(filenameBuf, 1024, "%s.pack%d", out_file, i);
			fprintf(stderr, "buf 0x%08lx bufSz 0x%08lx eof 0x%08lx current_blb3 0x%08lx file %s\n", (unsigned long) buf, bufSz, (unsigned long) buf + bufSz, (unsigned long) current_blb3, filenameBuf);
			ret = extract_blb3(current_blb3, filenameBuf, &next_blb3);
			if (ret) {
				fprintf(stderr, "can't extract blb3 data at offset 0x%08lx\n", (unsigned long) current_blb3 - (unsigned long) buf);
				return ret;
			}
			current_blb3 = next_blb3;
			i++;
		}
		fprintf(stderr, "Sucessfully extracted blb3 file %s\n", in_file);
		return 0;
	}
	//blb3_usage();
	return -1;
}

static unsigned int mr0k_main(unsigned int argc, const char** argv) {
	if (argc < 4) {
		//mr0k_usage();
		return -1;
	}
	const char* mode = argv[1];
	const char* in_file = argv[2];
	const char* out_file = argv[3];
	FILE* in_fp = fopen(in_file, "rb");
	if (in_fp == NULL) {
		fprintf(stderr, "input file open error: %s\n", strerror(errno));
		return -1;
	}
	FILE* out_fp = fopen(out_file, "wb");
	if (out_fp == NULL) {
		fprintf(stderr, "output file open error: %s\n", strerror(errno));
		return -1;
	}
	uint8_t* buf;
	size_t bufSz;
	if (strncasecmp(mode, "encrypt", 8) == 0) {
		fseek(in_fp, 0, SEEK_END);
		bufSz = ftell(in_fp);
		fseek(in_fp, 0, SEEK_SET);
		buf = malloc(bufSz);
		if (buf == NULL) {
			fprintf(stderr, "can't allocate buffer\n");
			return -1;
		}
		fread(buf, bufSz, 1, in_fp);
		fclose(in_fp);
		fprintf(stderr, "Read from input file %s\n", in_file);
		mr0k_encrypt(buf, bufSz, 1);
		*(uint32_t*) buf = htobe32(0x6d72306b);
		fwrite(buf, bufSz, 1, out_fp);
		fclose(out_fp);
		fprintf(stderr, "Wrote to output file %s\n", out_file);
		return 0;
	}
	else if (strncasecmp(mode, "decrypt", 8) == 0) {
		fseek(in_fp, 0, SEEK_END);
		bufSz = ftell(in_fp);
		fseek(in_fp, 0, SEEK_SET);
		buf = malloc(bufSz);
		if (buf == NULL) {
			fprintf(stderr, "can't allocate buffer\n");
			return -1;
		}
		fread(buf, bufSz, 1, in_fp);
		fclose(in_fp);
		fprintf(stderr, "Read from input file %s\n", in_file);
		mr0k_decrypt(buf, bufSz, 1);
		*(uint32_t*) buf = htobe32(0x4d723044);
		fwrite(buf, bufSz, 1, out_fp);
		fclose(out_fp);
		fprintf(stderr, "Wrote to output file %s\n", out_file);
		return 0;
	}
	//mr0k_usage();
	return -1;
}

static unsigned int ec2b_main(int argc, const char** argv) {
	if (argc < 2) {
		ec2b_usage();
		return -1;
	}
	const char* mode_s = argv[1];
	if (strncasecmp(mode_s, "xor", 3) == 0) {
		if (argc < 4) {
			ec2b_xor_usage();
			return -1;
		}
		const char* in_file = argv[2];
		const char* out_file = argv[3];
		FILE* in_fp = fopen(in_file, "rb");
		if (in_fp == NULL) {
			fprintf(stderr, "input file open error: %s\n", strerror(errno));
			return -1;
		}
		FILE* out_fp = fopen(out_file, "wb");
		if (out_fp == NULL) {
			fprintf(stderr, "output file open error: %s\n", strerror(errno));
			return -1;
		}
		uint8_t xor_buf[4096];
		ec2b_t ec2b;
		fread(&ec2b, sizeof(ec2b), 1, in_fp);
		fclose(in_fp);
		if (be32toh(ec2b.magic) != 0x45633262) {
			fprintf(stderr, "Bad file magic 0x%08x\n", be32toh(ec2b.magic));
			return -1;
		}
		if (le32toh(ec2b.keySz) != 16) {
			fprintf(stderr, "Bad key length 0x%08x\n", le32toh(ec2b.keySz));
			return -1;
		}
		if (le32toh(ec2b.dataSz) != 2048) {
			fprintf(stderr, "Bad data length 0x%08x\n", le32toh(ec2b.dataSz));
			return -1;
		}
		xorKeyFromEc2b(&ec2b, xor_buf);
		fwrite(xor_buf, 4096, 1, out_fp);
		fclose(out_fp);
		fprintf(stderr, "Sucessfully derived xor data from %s\n", in_file);
		return 0;
	}
	else if (strncasecmp(mode_s, "gen", 3) == 0) {
		if (argc < 3) {
			ec2b_gen_usage();
			return -1;
		}
		const char* out_file = argv[2];
		FILE* out_fp = fopen(out_file, "wb");
		if (out_fp == NULL) {
			fprintf(stderr, "output file open error: %s\n", strerror(errno));
			return -1;
		}
		ec2b_t ec2b;
		uint64_t seed;
		genNewEc2b(&ec2b, NULL, NULL, &seed, 1);
		fwrite(&ec2b, sizeof(ec2b), 1, out_fp);
		fclose(out_fp);
		fprintf(stderr, "Generated new ec2b %s with seed 0x%016llx\n", out_file, (unsigned long long) seed);
		return 0;
	}
	else if (strncasecmp(mode_s, "edit", 4) == 0) {
		if (argc < 3) {
			ec2b_edit_usage();
			return -1;
		}
		const char* in_file = NULL;
		const char* out_file = NULL;
		unsigned int gen_key = 0;
		unsigned int gen_data = 0;
		unsigned int gen_seed = 0;
		unsigned int new_seed = 0;
		unsigned int output_to_input = 0;
		ec2b_t in_ec2b, out_ec2b;
		uint64_t seed;
		int i;
		for (i = 2; i < argc; i++) {
			if (strncasecmp(argv[i], "-h", 2) == 0 || strncmp(argv[i], "-?", 2) == 0) {
				ec2b_edit_help();
				return 0;
			}
			else if (strncmp(argv[i], "-k", 2) == 0) {
				gen_key = 1;
				continue;
			}
			else if (strncmp(argv[i], "-d", 2) == 0) {
				gen_data = 1;
				continue;
			}
			else if (strncmp(argv[i], "-s", 2) == 0) {
				if (!new_seed) gen_seed = 1;
				continue;
			}
			else if (strncmp(argv[i], "-S", 2) == 0) {
				if (i + 1 > argc) {
					fprintf(stderr, "we need a seed to work with\n");
					return -1;
				}
				const char* seed_c = argv[i + 1];
				char* tail = NULL;
				errno = 0;
				seed = strtoull(seed_c, &tail, 0);
				if (seed_c == tail) {
					fprintf(stderr, "we need a seed to work with\n");
					return -1;
				}
				new_seed = 1;
				gen_seed = 0;
				// TODO overflow
				i++;
				continue;
			}
			else if (strncmp(argv[i], "-o", 2) == 0) {
				if (i + 1 > argc) {
					fprintf(stderr, "we need a file to work with\n");
					return -1;
				}
				out_file = argv[i + 1];
				i++;
				continue;
			}
			else if (strncmp(argv[i], "-i", 2) == 0) {
				if (i + 1 > argc) {
					fprintf(stderr, "we need a file to work with\n");
					return -1;
				}
				in_file = argv[i + 1];
				i++;
				continue;
			}
			else {
				if (i == 2) {
					in_file = argv[i];
					continue;
				}
				else {
					fprintf(stderr, "unrecognized argument %s\n", argv[i]);
					return -1;
				}
			}
		}
#if 1
		if (!(gen_key || gen_data || gen_seed || new_seed)) {
			fprintf(stderr, "skipping no-op, please specify one or more of -k/-d/-s/-S\n");
			return -1;
		}
#endif
		if (in_file == NULL) {
			fprintf(stderr, "we need a file to work with\n");
			return -1;
		}
		if (out_file == NULL) {
			out_file = in_file;
		}
		if (strcmp(in_file, out_file) == 0) {
			output_to_input = 1;
			out_file = NULL;
		}
		FILE* in_fp = fopen(in_file, output_to_input ? "rb+" : "rb");
		if (in_fp == NULL) {
			fprintf(stderr, "input file open error: %s\n", strerror(errno));
			return -1;
		}
		FILE* out_fp;
		if (output_to_input) out_fp = in_fp;
		else {
			out_fp = fopen(out_file, "wb");
			if (out_fp == NULL) {
				fprintf(stderr, "output file open error: %s\n", strerror(errno));
				return -1;
			}
		}
		fread(&in_ec2b, sizeof(ec2b_t), 1, in_fp);
		if (be32toh(in_ec2b.magic) != 0x45633262) {
			fprintf(stderr, "Bad file magic 0x%08x\n", be32toh(in_ec2b.magic));
			return -1;
		}
		if (le32toh(in_ec2b.keySz) != 16) {
			fprintf(stderr, "Bad key length 0x%08x\n", le32toh(in_ec2b.keySz));
			return -1;
		}
		if (le32toh(in_ec2b.dataSz) != 2048) {
			fprintf(stderr, "Bad data length 0x%08x\n", le32toh(in_ec2b.dataSz));
			return -1;
		}
		if (output_to_input) {
			fseek(out_fp, 0, SEEK_SET);
		}
		else {
			fclose(in_fp);
		}
		in_fp = NULL;
		uint8_t* key = NULL;
		uint8_t* data = NULL;
		if (!gen_key) key = in_ec2b.key;
		if (!gen_data) data = in_ec2b.data;
		if (gen_seed) {
			getrandom(&seed, sizeof(uint64_t), 0);
			new_seed = 1;
		}
		genNewEc2b(&out_ec2b, key, data, &seed, !new_seed);
		fwrite(&out_ec2b, sizeof(ec2b_t), 1, out_fp);
		fclose(out_fp);
		fprintf(stderr, "Generated new ec2b %s with seed 0x%016llx\n", output_to_input ? in_file : out_file, (unsigned long long) seed);
		return 0;
	}
	ec2b_usage();
	return -1;
}

static unsigned int xor_main(unsigned int argc, const char** argv) {
	if (argc < 4) {
		//xor_usage();
		return -1;
	}
	const char* in_file = argv[1];
	const char* key_file = argv[2];
	const char* out_file = argv[3];
	FILE* in_fp = fopen(in_file, "rb");
	if (in_fp == NULL) {
		fprintf(stderr, "input file open error: %s\n", strerror(errno));
		return -1;
	}
	FILE* out_fp = fopen(out_file, "wb");
	if (out_fp == NULL) {
		fprintf(stderr, "output file open error: %s\n", strerror(errno));
		return -1;
	}
	FILE* key_fp = fopen(key_file, "rb");
	if (key_fp == NULL) {
		fprintf(stderr, "key file open error: %s\n", strerror(errno));
		return -1;
	}
	uint8_t* buf;
	uint8_t* key_buf;
	size_t bufSz, keyBufSz;
	fseek(in_fp, 0, SEEK_END);
	bufSz = ftell(in_fp);
	fseek(in_fp, 0, SEEK_SET);
	buf = malloc(bufSz);
	if (buf == NULL) {
		fprintf(stderr, "can't allocate buffer\n");
		return -1;
	}
	fseek(key_fp, 0, SEEK_END);
	keyBufSz = ftell(key_fp);
	fseek(key_fp, 0, SEEK_SET);
	key_buf = malloc(keyBufSz);
	if (key_buf == NULL) {
		fprintf(stderr, "can't allocate buffer\n");
		return -1;
	}
	fread(buf, bufSz, 1, in_fp);
	fclose(in_fp);
	fprintf(stderr, "Read from input file %s\n", in_file);
	fread(key_buf, keyBufSz, 1, key_fp);
	fclose(key_fp);
	fprintf(stderr, "Read from key file %s\n", key_file);
	xorCrypt(buf, bufSz, key_buf, keyBufSz);
	fwrite(buf, bufSz, 1, out_fp);
	fclose(out_fp);
	fprintf(stderr, "Wrote to output file %s\n", out_file);
	return 0;
}

int main(int argc, const char** argv) {
	if (argc < 2) {
		usage();
		return -1;
	}
	const char* mode = argv[1];
	if (strncasecmp(mode, "blk", 3) == 0) {
		return blk_main(argc - 1, &argv[1]);
	}
	else if (strncasecmp(mode, "mhy0", 4) == 0) {
		return mhy0_main(argc - 1, &argv[1]);
	}
	else if (strncasecmp(mode, "mhy1", 4) == 0) {
		return mhy1_main(argc - 1, &argv[1]);
	}
	else if (strncasecmp(mode, "encr", 4) == 0) {
		return encr_main(argc - 1, &argv[1]);
	}
	else if (strncasecmp(mode, "blb3", 4) == 0) {
		return blb3_main(argc - 1, &argv[1]);
	}
	else if (strncasecmp(mode, "mr0k", 5) == 0) {
		return mr0k_main(argc - 1, &argv[1]);
	}
	else if (strncasecmp(mode, "ec2b", 4) == 0) {
		return ec2b_main(argc - 1, &argv[1]);
	}
	else if (strncasecmp(mode, "xor", 3) == 0) {
		return xor_main(argc - 1, &argv[1]);
	}
	usage();
	return -1;
}
