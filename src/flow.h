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

#ifndef __FLOW_H
#define __FLOW_H

#include <stdint.h>
#include <netinet/ip.h>
#include <sys/time.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>

enum {
	PKT_DIR_C2S,
	PKT_DIR_S2C,
	PKT_DIR_NUM,
};

struct flow_stat {
	uint64_t	create;
	uint64_t	normal;
	uint64_t	gc;
	uint64_t	reset;
	uint64_t	loss_of_sync;
	uint64_t	early_drop;
	uint64_t	active;
};

extern struct flow_stat g_flow_stat;

void flow_stat_show(void);

typedef struct flow flow_t;

int flow_add_tag(flow_t *f, int id, void *data, void (*free)(void *data));
void *flow_get_tag(flow_t *f, int id);
void flow_del_tag(flow_t *f, int id);

typedef void (*flow_data_handler)(flow_t *f, int dir, const unsigned char *data,
		int len, void *user);

int flow_init(void);
int flow_inspect(struct ip *ip, struct tcphdr *tcph, const unsigned char *data,
		int len, flow_data_handler h, void *user);
void flow_exit(void);

#endif /* __FLOW_H */
