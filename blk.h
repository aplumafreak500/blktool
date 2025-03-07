/* SPDX-License-Identifier: MPL-2.0 */
/* ©2025 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef BLK_H
#define BLK_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint32_t magic;
	uint32_t version;
	uint8_t key1[16];
	uint8_t key2[16];
	uint16_t blkSz;
} __attribute__((packed)) blk0_header_t;

void decrypt_blk0(uint8_t*, size_t, size_t, uint8_t*, uint64_t*, uint8_t*);
void encrypt_blk0(uint8_t*, size_t, size_t, uint8_t*, uint64_t);
#endif
