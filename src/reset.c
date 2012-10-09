/**
 * Snoopy - A lightweight bypass censorship system for HTTP
 * Copyright (C) 2012- Changli Gao <xiaosuo@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "reset.h"
#include "types.h"
#include <string.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <unistd.h>

static int l_sock = -1;

int reset_init(void)
{
	int ok = 1;

	l_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (l_sock < 0)
		goto err;
	if (setsockopt(l_sock, IPPROTO_IP, IP_HDRINCL, &ok, sizeof(ok)) < 0)
		goto err2;

	return 0;
err2:
	close(l_sock);
	l_sock = -1;
err:
	return -1;
}

static uint32_t csum32(uint32_t initval, const uint16_t *buf, size_t nwords)
{
	while (nwords-- > 0) {
		initval += *buf++;
		/**
		 * XXX: Please don't remove the following line, otherwise, some
		 * GCC version may fail to generate the correct ASM code.
		 */
		asm volatile("":::"memory");
	}

	return initval;
}

static uint16_t csum_fold(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}

struct tcpv4 {
	struct ip	ip;
	struct tcphdr	th;
};

struct pseudohdr {
	be32_t	saddr;
	be32_t	daddr;
	uint8_t	mbz;
	uint8_t	proto;
	be16_t	len;
};

static uint16_t tcp_csum(const struct tcpv4 *p)
{
	struct pseudohdr ps = {
		.saddr	= p->ip.ip_src.s_addr,
		.daddr	= p->ip.ip_dst.s_addr,
		.mbz	= 0,
		.proto	= IPPROTO_TCP,
		.len	= htons(sizeof(struct tcphdr)),
	};

	return csum_fold(csum32(csum32(0, (const uint16_t *)&ps, sizeof(ps) / 2),
				(const uint16_t *)&p->th, sizeof(p->th) / 2));
}

static int send_tcp(const struct tcpv4 *p)
{
	struct sockaddr_in dst;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr = p->ip.ip_dst;
	dst.sin_port = p->th.th_dport;

	if (sendto(l_sock, p, sizeof(*p), 0, (struct sockaddr *)&dst,
		   sizeof(dst)) < 0)
		return -1;

	return 0;
}

int reset(const struct ip *ip)
{
	const struct tcphdr *th = (const struct tcphdr *)(((const uint32_t *)ip) + ip->ip_hl);
	uint32_t ack = ntohl(th->th_seq) + !!(th->th_flags & TH_SYN) +
		       !!(th->th_flags & TH_FIN) + ntohs(ip->ip_len) -
		       ip->ip_hl * 4 - th->th_off * 4;
	struct tcpv4 rst = {
		.ip = {
			.ip_v	= 4,
			.ip_hl	= sizeof(struct ip) / 4,
			.ip_tos	= 0,
			.ip_len	= htons(sizeof(rst)),
			.ip_id	= 0, /* the kernel will fill it */
			.ip_off	= 0,
			.ip_ttl	= 128,
			.ip_p	= IPPROTO_TCP,
			.ip_sum	= 0, /* the kernel will fill it */
			.ip_src	= ip->ip_dst,
			.ip_dst	= ip->ip_src,
		},
		.th = {
			.th_sport	= th->th_dport,
			.th_dport	= th->th_sport,
			.th_seq		= (th->th_flags & TH_ACK) ? th->th_ack : 0,
			.th_ack		= htonl(ack),
			.th_off		= sizeof(struct tcphdr) / 4,
			.th_x2		= 0,
			.th_flags	= TH_RST | TH_ACK,
			.th_win		= 0,
			.th_sum		= 0,
			.th_urp		= 0,
		},
	};

	rst.th.th_sum = tcp_csum(&rst);

	return send_tcp(&rst);
}

void reset_exit(void)
{
	close(l_sock);
	l_sock = -1;
}
