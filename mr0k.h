/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef MR0K_H
#define MR0K_H
#include <stdint.h>
int mr0k_decrypt(uint8_t*, size_t, unsigned int);
int mr0k_encrypt(uint8_t*, size_t, unsigned int);
#endif
