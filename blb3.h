/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef BLB3_H
#define BLB3_H
#include <stdint.h>
#include <stddef.h>
int extract_blb3(uint8_t*, const char*, uint8_t**);
int pack_blb3(const char*, FILE*);
#endif
