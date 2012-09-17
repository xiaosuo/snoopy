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

#include "flow.h"
#include "types.h"
#include "buf.h"
#include "time.h"
#include "list.h"
#include "utils.h"
#include "jhash.h"
#include <assert.h>
#include <time.h>
#include <inttypes.h>
#include <stdio.h>

enum {
	FLOW_FLAG_INIT		= 0,
	FLOW_FLAG_CLNT_SYN	= 1,
	FLOW_FLAG_SERV_SYN	= 2,
	FLOW_FLAG_BOTH_SYN	= 3,
	FLOW_FLAG_CLNT_FIN	= 4,
	FLOW_FLAG_SERV_FIN	= 8,
	FLOW_FLAG_BOTH_FIN	= 12,
	FLOW_FLAG_ACK		= 16,
};

enum {
	FLOW_STATE_INCOMP,
	FLOW_STATE_COMP,
	FLOW_STATE_NUM,
};

struct flow_tag {
	int				id;
	void				*data;
	void				(*free)(void *data);
	slist_entry(struct flow_tag)	link;
};

struct flow {
	be32_t				src;
	be32_t				dst;
	be16_t				sport;
	be16_t				dport;
	uint16_t			flags;
	uint16_t			state;
	uint32_t			fin_seq[PKT_DIR_NUM];
	struct buf			buf[PKT_DIR_NUM];
	slist_head( , struct flow_tag)	tag_list;
	list_entry(struct flow)		hash_link;
	tlist_entry(struct flow)	gc_link;
	struct timeval			timeout;
};

#define FLOW_NR_MAX		(1 << 20)
#define FLOW_EARLY_DROP_LIMIT	10

struct flow_gc_list {
	tlist_head( , struct flow)	list;
	time_t				timeout;
} flow_gc_list[FLOW_STATE_NUM] = {
	[FLOW_STATE_INCOMP] = {
		.list		= TLIST_HEAD_INITIALIZER(&flow_gc_list[FLOW_STATE_INCOMP].list),
		.timeout	= 30,
	},
	[FLOW_STATE_COMP] = {
		.list		= TLIST_HEAD_INITIALIZER(&flow_gc_list[FLOW_STATE_COMP].list),
		.timeout	= 300,
	},
};

static list_head( , struct flow) *l_hash_table = NULL;
static uint32_t l_hash_salt;
struct flow_stat g_flow_stat = { 0 };

void flow_stat_show(void)
{
	printf("flow create: %" PRIu64 "\n", g_flow_stat.create);
	printf("flow normal: %" PRIu64 "\n", g_flow_stat.normal);
	printf("flow gc: %" PRIu64 "\n", g_flow_stat.gc);
	printf("flow reset: %" PRIu64 "\n", g_flow_stat.reset);
	printf("flow loss of sync: %" PRIu64 "\n", g_flow_stat.loss_of_sync);
	printf("flow early drop: %" PRIu64 "\n", g_flow_stat.early_drop);
	printf("flow active: %" PRIu64 "\n", g_flow_stat.active);
}

int flow_add_tag(flow_t *f, int id, void *data, void (*free)(void *data))
{
	struct flow_tag *t = malloc(sizeof(*t));

	if (!t)
		return -1;
	t->id = id;
	t->data = data;
	t->free = free;
	slist_add_head(&f->tag_list, t, link);

	return 0;
}

void *flow_get_tag(flow_t *f, int id)
{
	struct flow_tag *t;

	slist_for_each(t, &f->tag_list, link) {
		if (t->id == id)
			return t->data;
	}

	return NULL;
}

void flow_del_tag(flow_t *f, int id)
{
	struct flow_tag *t, **pp;

	slist_for_each_pprev(t, pp, &f->tag_list, link) {
		if (t->id == id) {
			slist_del(t, pp, link);
			t->free(t->data);
			free(t);
			break;
		}
	}
}

static void flow_gc_del(struct flow *f)
{
	if (!tlist_entry_inline(&f->gc_link))
		return;
	tlist_del(&flow_gc_list[f->state].list, f, gc_link);
	tlist_entry_init(&f->gc_link);
}

static void flow_gc_add(struct flow *f)
{
	struct flow_gc_list *l = &flow_gc_list[f->state];

	assert(!tlist_entry_inline(&f->gc_link));

	tlist_add_tail(&l->list, f, gc_link);
	f->timeout.tv_sec = g_time.tv_sec + l->timeout;
	f->timeout.tv_usec = g_time.tv_usec;
}

static void flow_free(struct flow *f)
{
	struct flow_tag *t;

	buf_drain(&f->buf[PKT_DIR_C2S]);
	buf_drain(&f->buf[PKT_DIR_S2C]);
	while ((t = slist_first(&f->tag_list))) {
		slist_del_head(&f->tag_list, t, link);
		t->free(t->data);
		free(t);
	}
	list_del(f, hash_link);
	flow_gc_del(f);
	free(f);
	--g_flow_stat.active;
}

static inline uint32_t flow_hash(be32_t src, be32_t dst, be16_t sport,
	be16_t dport)
{
	union {
		struct {
			be16_t	port1;
			be16_t	port2;
		};
		be32_t	ports;
	} port;

	if (src > dst)
		swap(src, dst);
	if (sport <= dport) {
		port.port1 = sport;
		port.port2 = dport;
	} else {
		port.port1 = dport;
		port.port2 = sport;
	}

	return jhash_3words(src, dst, port.ports, l_hash_salt);
}

struct flow *flow_alloc(struct ip *ip, struct tcphdr *tcph)
{
	struct flow *f = malloc(sizeof(*f));

	if (!f)
		goto err;
	f->src = ip->ip_src.s_addr;
	f->dst = ip->ip_dst.s_addr;
	f->sport = tcph->th_sport;
	f->dport = tcph->th_dport;
	f->flags = FLOW_FLAG_INIT;
	f->state = FLOW_STATE_INCOMP;
	buf_init(&f->buf[PKT_DIR_C2S], 0);
	buf_init(&f->buf[PKT_DIR_S2C], 0);
	slist_head_init(&f->tag_list);
	tlist_entry_init(&f->gc_link);
	++g_flow_stat.active;
	g_flow_stat.create++;

	return f;
err:
	return NULL;
}

static struct flow *flow_get(struct ip *ip, struct tcphdr *tcph, int *dir)
{
	struct flow *f;
	uint32_t hash = flow_hash(ip->ip_src.s_addr, ip->ip_dst.s_addr,
			tcph->th_sport, tcph->th_dport);
	int early_drop_limit = FLOW_EARLY_DROP_LIMIT;

	hash &= FLOW_NR_MAX - 1;
	list_for_each(f, &l_hash_table[hash], hash_link) {
		if (ip->ip_src.s_addr == f->src &&
		    ip->ip_dst.s_addr == f->dst &&
		    tcph->th_sport == f->sport && tcph->th_dport == f->dport) {
			*dir = PKT_DIR_C2S;
			goto out;
		}
		if (ip->ip_dst.s_addr == f->src &&
		    ip->ip_src.s_addr == f->dst &&
		    tcph->th_dport == f->sport && tcph->th_sport == f->dport) {
			*dir = PKT_DIR_S2C;
			goto out;
		}
	}

	/* only SYN can open a new connection */
	if ((tcph->th_flags & (TH_SYN | TH_ACK)) != TH_SYN)
		goto err;

	/* the flow table is full, so we need to drop some incomplete
	 * connection randomly to free space */
	while (g_flow_stat.active >= FLOW_NR_MAX) {
		int bucket;
		struct flow *df = NULL;

		if (--early_drop_limit < 0)
			goto err;

		bucket = random() & (FLOW_NR_MAX - 1);
		list_for_each(f, &l_hash_table[bucket], hash_link) {
			if (f->state == FLOW_STATE_INCOMP)
				df = f;
		}
		if (df) {
			flow_free(f);
			g_flow_stat.early_drop++;
			break;
		}
	}

	f = flow_alloc(ip, tcph);
	if (!f)
		goto err;
	list_add_head(&l_hash_table[hash], f, hash_link);
	*dir = PKT_DIR_C2S;
out:
	return f;
err:
	return NULL;
}

static void flow_gc(const struct timeval *tv, void *user)
{
	struct flow *f;
	int state;

	for (state = 0; state < FLOW_STATE_NUM; state++) {
		struct flow_gc_list *l = &flow_gc_list[state];

		while ((f = tlist_first(&l->list))) {
			if (timercmp(&f->timeout, tv, >))
				break;
			flow_free(f);
			g_flow_stat.gc++;
		}
	}
}

int flow_inspect(struct ip *ip, struct tcphdr *tcph, const unsigned char *data,
		int len, flow_data_handler h, void *user)
{
	struct flow *f;
	int dir;

	f = flow_get(ip, tcph, &dir);
	if (!f)
		goto err;

	if (tcph->th_flags & TH_RST) {
		flow_free(f);
		g_flow_stat.reset++;
		goto out;
	}
	flow_gc_del(f);
	if (tcph->th_flags & TH_SYN) {
		if (dir == PKT_DIR_C2S) {
			if (f->flags == FLOW_FLAG_INIT) {
				f->buf[dir].seq = ntohl(tcph->th_seq) + 1;
				f->flags = FLOW_FLAG_CLNT_SYN;
			}
		} else {
			if ((f->flags & FLOW_FLAG_BOTH_SYN) ==
					FLOW_FLAG_CLNT_SYN) {
				f->buf[dir].seq = ntohl(tcph->th_seq) + 1;
				f->flags |= FLOW_FLAG_SERV_SYN;
			}
		}
	} else if (tcph->th_flags & TH_ACK) {
		if ((f->flags & FLOW_FLAG_BOTH_SYN) == FLOW_FLAG_BOTH_SYN &&
		    (f->flags & FLOW_FLAG_BOTH_FIN) == 0) {
			f->flags |= FLOW_FLAG_ACK;
			f->state = FLOW_STATE_COMP;
		}
	}
	if (tcph->th_flags & TH_FIN) {
		int flag;

		if (dir == PKT_DIR_C2S)
			flag = FLOW_FLAG_CLNT_FIN;
		else
			flag = FLOW_FLAG_SERV_FIN;
		if (!(f->flags & flag)) {
			f->state = FLOW_STATE_INCOMP;
			f->flags |= flag;
			f->fin_seq[dir] = ntohl(tcph->th_seq) + len + 1;
		}
	}
	flow_gc_add(f);

	if (tcph->th_flags & TH_ACK) {
		/* Loss of synchronization:
		 * Some segments received by ends are lost for us, and we
		 * can't recover the corresponding connections in any way, so
		 * we have to drop them. */
		if (SEQ_GT(ntohl(tcph->th_ack), f->buf[!dir].seq)) {
			g_flow_stat.loss_of_sync++;
			goto err2;
		}
	}

	if ((f->flags & FLOW_FLAG_ACK) && len > 0) {
		uint32_t seq = ntohl(tcph->th_seq);
		struct buf *buf = &f->buf[dir];

		if (seq == buf->seq) {
			struct mb *m;

			h(f, dir, data, len, user);
			buf_drain_to(buf, seq + len);
			while ((m = buf_del(buf))) {
				h(f, dir, m->data, m->len, user);
				mb_free(m);
			}
		} else if (buf_add(buf, seq, data, len)) {
			goto err;
		}
	}

	if ((f->flags & (dir == PKT_DIR_C2S ? FLOW_FLAG_CLNT_FIN :
			FLOW_FLAG_SERV_FIN)) &&
	    f->buf[dir].seq == f->fin_seq[dir] - 1U)
		f->buf[dir].seq++;

	if ((f->flags & FLOW_FLAG_BOTH_FIN) == FLOW_FLAG_BOTH_FIN &&
	    f->buf[PKT_DIR_C2S].seq == f->fin_seq[PKT_DIR_C2S] &&
	    f->buf[PKT_DIR_S2C].seq == f->fin_seq[PKT_DIR_S2C]) {
		flow_free(f);
		g_flow_stat.normal++;
	}
out:
	return 0;
err2:
	flow_free(f);
err:
	return -1;
}

static void *l_flow_gc_time_update_handle;

int flow_init(void)
{
	if (get_random_bytes(&l_hash_salt, sizeof(l_hash_salt)))
		goto err;
	l_hash_table = calloc(FLOW_NR_MAX, sizeof(*l_hash_table));
	if (!l_hash_table)
		goto err;
	l_flow_gc_time_update_handle = time_register_update_handler(flow_gc,
			NULL);
	if (!l_flow_gc_time_update_handle)
		goto err2;
	srandom(l_hash_salt);

	return 0;
err2:
	free(l_hash_table);
err:
	return -1;
}

void flow_exit(void)
{
	int i;

	time_unregister_update_handler(l_flow_gc_time_update_handle);
	for (i = 0; i < FLOW_NR_MAX; i++) {
		struct flow *f, *n;

		list_for_each_safe(f, n, &l_hash_table[i], hash_link)
			flow_free(f);
	}
	free(l_hash_table);
}
