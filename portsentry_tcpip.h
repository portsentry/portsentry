/* Versions of Linux are not consistent in how the TCP/UDP/IP headers
* defined. This file contains the Linux/BSD headers from RedHat 5.0 and
* should clear up compile problems. CHR
*/


/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_TCP_H
#define _NETINET_TCP_H	1

#include <features.h>

__BEGIN_DECLS

struct tcphdr
  {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#else
#error	"Adjust your <bits/endian.h> defines"
#endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

#endif /* tcp.h */



#ifndef __NETINET_IP_H
#define __NETINET_IP_H 1

__BEGIN_DECLS

struct timestamp
  {
    u_int8_t len;
    u_int8_t ptr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t flags:4;
    u_int8_t overflow:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t overflow:4;
    u_int8_t flags:4;
#else
#error	"Please fix <bytesex.h>"
#endif
    u_int32_t data[9];
  };

struct ip_options
  {
    u_int32_t faddr;		/* Saved first hop address */
    u_int8_t optlen;
    u_int8_t srr;
    u_int8_t rr;
    u_int8_t ts;
    u_int8_t is_setbyuser:1;	/* Set by setsockopt?			*/
    u_int8_t is_data:1;		/* Options in __data, rather than skb	*/
    u_int8_t is_strictroute:1; /* Strict source route		*/
    u_int8_t srr_is_hit:1;	/* Packet destination addr was our one	*/
    u_int8_t is_changed:1;	/* IP checksum more not valid		*/
    u_int8_t rr_needaddr:1;	/* Need to record addr of outgoing dev	*/
    u_int8_t ts_needtime:1;	/* Need to record timestamp		*/
    u_int8_t ts_needaddr:1;	/* Need to record addr of outgoing dev  */
    u_int8_t router_alert;
    u_int8_t __pad1;
    u_int8_t __pad2;
    u_int8_t __data[0];
  };

struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t ihl:4;
    u_int8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t	version:4;
    u_int8_t ihl:4;
#else
#error	"Please fix <bytesex.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };

#endif

#ifndef __NETINET_UDP_H
#define __NETINET_UDP_H    1

__BEGIN_DECLS

/* UDP header as specified by RFC 768, August 1980. */
struct udphdr {
  u_int16_t	source;
  u_int16_t	dest;
  u_int16_t	len;
  u_int16_t	check;
};

__END_DECLS

#endif /* netinet/udp.h */
