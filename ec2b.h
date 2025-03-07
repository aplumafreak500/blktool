/* SPDX-License-Identifier: MPL-2.0 */
/* ©2025 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef EC2B_H
#define EC2B_H
#include <stdint.h>

typedef struct {
	uint32_t magic;
	uint32_t keySz;
	uint8_t key[16];
	uint32_t dataSz;
	uint8_t data[2048];
} ec2b_t;

void xorKeyFromEc2b(const ec2b_t*, uint8_t*);
void genNewEc2b(ec2b_t*, uint8_t*, uint8_t*, uint64_t*, unsigned int);
#endif
