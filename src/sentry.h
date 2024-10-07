// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: CPL-1.0

#pragma once

#include "packet_info.h"

int InitSentry(void);
void FreeSentry(void);
void RunSentry(struct PacketInfo *pi);
