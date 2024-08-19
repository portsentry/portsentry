// SPDX-FileCopyrightText: 2024 Marcus Hufvudsson <mh@protohuf.com>
// SPDX-FileContributor: Craig Rowland
//
// SPDX-License-Identifier: CPL-1.0

#pragma once
#include <sys/param.h>

#define TCPPACKETLEN 80
#define UDPPACKETLEN 68

#define ERROR -1
#define TRUE 1
#define FALSE 0
#define MAXBUF 1024
/* max size of an IP address plus NULL */
#define IPMAXBUF 16

#define ERRNOMAXBUF 1024

#define MAX_INTERFACES 1024

#undef max
#define max(x, y) ((x) > (y) ? (x) : (y))
