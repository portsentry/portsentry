// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
//
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "packet_info.h"

int InitSentry(void);
void FreeSentry(void);
void RunSentry(const struct PacketInfo *pi);
