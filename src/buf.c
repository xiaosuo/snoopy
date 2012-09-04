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

#include "buf.h"
#include <assert.h>
#include <string.h>

/* this value is copied from /proc/sys/net/ipv4/tcp_wmem */
#define BUF_LIMIT	4194304

static struct mb *mb_alloc(uint32_t seq, const unsigned char *data,
		uint32_t len)
{
	struct mb *m = malloc(sizeof(*m));

	if (!m)
		goto err;
	m->seq = seq;
	m->head = malloc(len);
	if (!m->head)
		goto err2;
	m->data = m->head;
	memcpy(m->data, data, len);
	m->len = len;

	return m;
err2:
	free(m);
err:
	return NULL;
}

int buf_add(struct buf *h, uint32_t seq, const unsigned char *data,
		uint32_t len)
{
	uint32_t end = seq + len;
	struct mb **pprev, *i, *m;
	uint32_t mseq, mlen;

	assert(len > 0);

	/* left edge */
	mseq = SEQ_GE(seq, h->seq) ? seq : h->seq;
	data += mseq - seq;
	seq = mseq;

	/* right edge */
	mseq = h->seq + BUF_LIMIT;
	if (SEQ_GT(end, mseq))
		end = mseq;

	if (!SEQ_LT(seq, end))
		goto err;

	slist_for_each_pprev(i, pprev, &h->mb_list, link) {
		/* seq < i->seq */
		if (SEQ_LT(seq, i->seq)) {
			mseq = SEQ_LE(end, i->seq) ? end : i->seq;
			mlen = mseq - seq;
			m = mb_alloc(seq, data, mlen);
			if (!m)
				goto err;
			slist_insert_before(i, pprev, m, link);
			/* fill in a hole */
			if (seq + mlen == end)
				goto out;
			/* there has been one copy */
			mseq = i->seq + i->len;
			if (SEQ_LE(end, mseq))
				goto out;
			data += mseq - seq;
			seq = mseq;
			continue;
		}
		/* seq >= i->seq && seq < i->seq + i->len */
		mseq = i->seq + i->len;
		if (SEQ_LT(seq, mseq)) {
			if (SEQ_LE(end, mseq))
				goto out;
			data += mseq - seq;
			seq = mseq;
		}
	}

	if (SEQ_LT(seq, end)) {
		m = mb_alloc(seq, data, end - seq);
		if (!m)
			goto err;
		slist_insert_before(NULL, pprev, m, link);
	}
out:
	return 0;
err:
	return -1;
}

void buf_drain_to(struct buf *b, uint32_t seq)
{
	struct mb *m;

	assert(SEQ_GT(seq, b->seq));

	while ((m = slist_first(&b->mb_list))) {
		if (SEQ_GE(seq, m->seq + m->len)) {
			slist_del_head(&b->mb_list, m, link);
			mb_free(m);
			continue;
		}
		if (SEQ_GT(seq, m->seq)) {
			uint32_t dseq = seq - m->seq;

			m->data += dseq;
			m->len -= dseq;
			m->seq = seq;
		}
		break;
	}

	b->seq = seq;
}

void buf_drain(struct buf *b)
{
	struct mb *m;

	while ((m = slist_first(&b->mb_list))) {
		slist_del_head(&b->mb_list, m, link);
		mb_free(m);
	}
}
