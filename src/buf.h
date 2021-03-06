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

#ifndef __BUF_H
#define __BUF_H

#include "list.h"
#include <stdint.h>
#include <stdlib.h>

#define SEQ_GT(s1, s2) ((int)((s1) - (s2)) > 0)
#define SEQ_LT(s1, s2) ((int)((s1) - (s2)) < 0)
#define SEQ_GE(s1, s2) ((int)((s1) - (s2)) >= 0)
#define SEQ_LE(s1, s2) ((int)((s1) - (s2)) <= 0)

struct mb {
	unsigned char		*head;
	unsigned char		*data;
	uint32_t		seq;
	uint32_t		len;
	slist_entry(struct mb)	link;
};

static inline void mb_free(struct mb *m)
{
	free(m->head);
	free(m);
}

struct buf {
	uint32_t			seq;
	slist_head( , struct mb)	mb_list;
};

static inline void buf_init(struct buf *b, uint32_t seq)
{
	b->seq = seq;
	slist_head_init(&b->mb_list);
}

int buf_add(struct buf *h, uint32_t seq, const unsigned char *data,
		uint32_t len);

static inline struct mb *buf_del(struct buf *b)
{
	struct mb *m;

	if ((m = slist_first(&b->mb_list)) && m->seq == b->seq) {
		slist_del_head(&b->mb_list, m, link);
		b->seq = m->seq + m->len;
		return m;
	}

	return NULL;
}

void buf_drain_to(struct buf *h, uint32_t seq);
void buf_drain(struct buf *b);

#endif /* __BUF_H */
