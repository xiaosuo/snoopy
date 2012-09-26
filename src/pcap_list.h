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

#ifndef __PCAP_LIST_H
#define __PCAP_LIST_H

#include "types.h"
#include <pcap/pcap.h>

struct vlan_hdr {
	be16_t	tci;
	be16_t	encapsulated_proto;
};

typedef struct pcap_list pcap_list_t;

pcap_list_t *pcap_list_alloc(void);
int pcap_list_add(pcap_list_t *pl, const char *name);
void pcap_list_free(pcap_list_t *pl);
void pcap_list_breakloop(pcap_list_t *pl);
const char *pcap_list_geterr(pcap_list_t *pl);
int pcap_list_stats(pcap_list_t *pl, struct pcap_stat *st);
int pcap_list_open_live(pcap_list_t *pl, int snap_len, int buf_size);
int pcap_list_open_offline(pcap_list_t *pl, const char *fn);
int pcap_list_setfilter(pcap_list_t *pl, const char *str);
int pcap_list_datalink(pcap_list_t *pl);
int pcap_list_loop(pcap_list_t *pl, pcap_handler callback, u_char *user);

#endif /* __PCAP_LIST_H */
