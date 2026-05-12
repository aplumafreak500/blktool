/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef MHYCRYPT_H
#define MHYCRYPT_H
#include <stdint.h>
#include <stddef.h>

void xorCrypt(uint8_t*, size_t, const uint8_t*, size_t);
void aesScrambleKey(uint8_t* key, const uint8_t roundKeys[11][16]);
void aesUnscrambleKey(uint8_t* key, const uint8_t roundKeys[11][16]);
void aesScrambleKeyMhy(uint8_t* key, const uint8_t roundKeys[11][16]);
void aesUnscrambleKeyMhy(uint8_t* key, const uint8_t roundKeys[11][16]);
void aesGetRoundKeys(const uint8_t* key, uint8_t roundKeys[11][16]);
void rc4_mhy(const uint8_t* key, size_t keySz, uint8_t* data, size_t dataSz, const uint8_t* opBytes, size_t opBytesSz);
void rc4_dec_mhy(const uint8_t* key, size_t keySz, uint8_t* data, size_t dataSz, const uint8_t* opBytes, size_t opBytesSz);
void genXorpadFromSeed(uint64_t seed, uint8_t*, size_t, unsigned int, unsigned int);
#endif
