/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef MHY1_H
#define MHY1_H
#include <stdint.h>
#include <stddef.h>
int extract_mhy1(uint8_t*, const char*, uint8_t**);
int pack_mhy1(const char*, FILE*);
#endif
