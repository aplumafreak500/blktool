/* SPDX-License-Identifier: MPL-2.0 */
/* ©2025 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef MHY0_H
#define MHY0_H
#include <stdint.h>
#include <stddef.h>
int extract_mhy0(uint8_t*, const char*, uint8_t**);
int pack_mhy0(const char*, FILE*);
#endif
