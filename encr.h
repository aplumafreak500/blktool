/* SPDX-License-Identifier: MPL-2.0 */
/* ©2026 Alex Pensinger (ArcticLuma113) */
/* Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/ */

#ifndef ENCR_H
#define ENCR_H
#include <stdint.h>
#include <stddef.h>
int extract_encr(const uint8_t*, const char*, const uint8_t**);
int pack_encr(const char*, FILE*);
#endif
