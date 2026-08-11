# SPDX-License-Identifier: MPL-2.0
# ©2026 Alex Pensinger (ArcticLuma113)
# Released under the terms of the MPLv2, which can be viewed at https://mozilla.org/MPL/2.0/

SRC = blktool.c blk.c mhy0.c mhy1.c encr.c ec2b.c mhycrypt.c mr0k.c mt19937-64.c lz4.c lz4hc.c
TGT = blktool
OBJ = $(SRC:%.c=%.o)
CC := gcc
CFLAGS := -O2 -g -Wall -Wextra -Wshadow -Wno-unused-result
LDFLAGS := 

.PHONY: all clean
.SUFFIXES:

all: $(TGT)

clean:
	rm -f $(OBJ) $(TGT)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TGT): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)
