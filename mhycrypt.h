/* SPDX-License-Identifier: MPL-2.0 */
/* ©2025 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef MHYCRYPT_H
#define MHYCRYPT_H
#include <stdint.h>
#include <stddef.h>

void xorCrypt(uint8_t*, size_t, const uint8_t*, size_t);
void aesScrambleKey(uint8_t* key, const uint8_t roundKeys[11][16]);
void aesUnscrambleKey(uint8_t* key, const uint8_t roundKeys[11][16]);
void genXorpadFromSeed(uint64_t seed, uint8_t*, size_t, unsigned int, unsigned int);
#endif
