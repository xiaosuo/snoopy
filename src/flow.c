
#include "flow.h"
#include "types.h"
#include "buf.h"
#include "time.h"
#include <assert.h>
#include <time.h>

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
	int			id;
	void			*data;
	void			(*free)(void *data);
	struct flow_tag		*next;
};

struct flow {
	be32_t			src;
	be32_t			dst;
	be16_t			sport;
	be16_t			dport;
	int			flags;
	struct buf		buf[PKT_DIR_NUM];
	struct flow_tag		*tag;
	struct flow		*hash_next;
	struct flow		**hash_pprev;
	struct flow		*gc_next;
	struct flow		**gc_pprev;
	struct timeval		timeout;
};

#define FLOW_NR_MAX		(1 << 20)
#define FLOW_EARLY_DROP_LIMIT	10

struct flow_gc_head {
	struct flow	*head;
	struct flow	**ptail;
	time_t		timeout;
} flow_gc_head[FLOW_STATE_NUM] = {
	[FLOW_STATE_INCOMP] = {
		.ptail		= &flow_gc_head[FLOW_STATE_INCOMP].head,
		.timeout	= 30,
	},
	[FLOW_STATE_COMP] = {
		.ptail		= &flow_gc_head[FLOW_STATE_COMP].head,
		.timeout	= 300,
	},
};

static struct flow **l_hash_table = NULL;
int g_flow_cnt = 0;

static inline int flow_state(struct flow *f)
{
	int flags = f->flags;

	if ((flags & FLOW_FLAG_ACK) && !(flags & FLOW_FLAG_BOTH_FIN))
		return FLOW_STATE_COMP;

	return FLOW_STATE_INCOMP;
}

int flow_add_tag(flow_t *f, int id, void *data, void (*free)(void *data))
{
	struct flow_tag *t = malloc(sizeof(*t));

	if (!t)
		return -1;
	t->id = id;
	t->data = data;
	t->free = free;
	t->next = f->tag;
	f->tag = t;

	return 0;
}

void *flow_get_tag(flow_t *f, int id)
{
	struct flow_tag *t;

	for (t = f->tag; t; t = t->next) {
		if (t->id == id)
			return t->data;
	}

	return NULL;
}

void flow_del_tag(flow_t *f, int id)
{
	struct flow_tag *t, **pp;

	for (pp = &f->tag; (t = *pp); pp = &t->next) {
		if (t->id == id) {
			*pp = t->next;
			t->free(t->data);
			free(t);
			break;
		}
	}
}

static void flow_gc_del(struct flow *f)
{
	if (!f->gc_pprev)
		return;
	*(f->gc_pprev) = f->gc_next;
	if (f->gc_next)
		f->gc_next->gc_pprev = f->gc_pprev;
	else
		flow_gc_head[flow_state(f)].ptail = f->gc_pprev;
	f->gc_pprev = NULL;
}

static void flow_gc_add(struct flow *f)
{
	struct flow_gc_head *h = &flow_gc_head[flow_state(f)];

	assert(!f->gc_pprev);

	f->gc_next = NULL;
	*(h->ptail) = f;
	f->gc_pprev = h->ptail;
	h->ptail = &f->gc_next;
	f->timeout.tv_sec = g_time.tv_sec + h->timeout;
	f->timeout.tv_usec = g_time.tv_usec;
}

static void flow_free(struct flow *f)
{
	struct flow_tag *t;

	buf_drain(&f->buf[PKT_DIR_C2S]);
	buf_drain(&f->buf[PKT_DIR_S2C]);
	while ((t = f->tag)) {
		f->tag = t->next;
		t->free(t->data);
		free(t);
	}
	*(f->hash_pprev) = f->hash_next;
	if (f->hash_next)
		f->hash_next->hash_pprev = f->hash_pprev;
	flow_gc_del(f);
	free(f);
	--g_flow_cnt;
}

static inline uint32_t flow_hash(be32_t src, be32_t dst, be16_t sport,
	be16_t dport)
{
	return src ^ (src >> 16) ^ dst ^ (dst >> 16) ^ ntohs(sport ^ dport);
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
	buf_init(&f->buf[PKT_DIR_C2S], 0);
	buf_init(&f->buf[PKT_DIR_S2C], 0);
	f->tag = NULL;
	f->gc_pprev = NULL;
	++g_flow_cnt;

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
	for (f = l_hash_table[hash]; f; f = f->hash_next) {
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
	while (g_flow_cnt >= FLOW_NR_MAX) {
		int bucket;
		struct flow *df = NULL;

		if (--early_drop_limit < 0)
			goto err;

		bucket = random() & (FLOW_NR_MAX - 1);
		for (f = l_hash_table[bucket]; f; f = f->hash_next) {
			if (flow_state(f) == FLOW_STATE_INCOMP)
				df = f;
		}
		if (df) {
			flow_free(f);
			break;
		}
	}

	f = flow_alloc(ip, tcph);
	if (!f)
		goto err;
	f->hash_next = l_hash_table[hash];
	l_hash_table[hash] = f;
	if (f->hash_next)
		f->hash_next->hash_pprev = &f->hash_next;
	f->hash_pprev = &l_hash_table[hash];
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
		struct flow_gc_head *h = &flow_gc_head[state];

		while ((f = h->head)) {
			if (timercmp(&f->timeout, tv, >))
				break;
			flow_free(f);
		}
	}
}

int flow_inspect(const struct timeval *ts, struct ip *ip, struct tcphdr *tcph,
		const unsigned char *data, int len, flow_data_handler h,
		void *user)
{
	struct flow *f;
	int dir;

	f = flow_get(ip, tcph, &dir);
	if (!f)
		goto err;

	if (tcph->th_flags & TH_RST) {
		flow_free(f);
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
		if ((f->flags & FLOW_FLAG_BOTH_SYN) == FLOW_FLAG_BOTH_SYN)
			f->flags |= FLOW_FLAG_ACK;
	}
	if (tcph->th_flags & TH_FIN) {
		if (dir == PKT_DIR_C2S)
			f->flags |= FLOW_FLAG_CLNT_FIN;
		else
			f->flags |= FLOW_FLAG_SERV_FIN;
		if ((f->flags & FLOW_FLAG_BOTH_FIN) == FLOW_FLAG_BOTH_FIN) {
			flow_free(f);
			goto out;
		}
	}
	flow_gc_add(f);

	if (tcph->th_flags & TH_ACK) {
		/* Loss of synchronization:
		 * Some segments received by ends are lost for us, and we
		 * can't recover the corresponding connections in any way, so
		 * we have to drop them. */
		if (SEQ_GT(ntohl(tcph->th_ack), f->buf[!dir].seq))
			goto err2;
	}

	if ((f->flags & FLOW_FLAG_ACK) && len > 0) {
		uint32_t seq = ntohl(tcph->th_seq);
		struct buf *buf = &f->buf[dir];

		if (seq == buf->seq) {
			struct mb *m;

			h(f, dir, &g_time, data, len, user);
			buf_drain_to(buf, seq + len);
			while ((m = buf_del(buf))) {
				h(f, dir, &g_time, m->data, m->len, user);
				mb_free(m);
			}
		} else if (buf_add(buf, seq, data, len)) {
			goto err;
		}
	}

	if ((tcph->th_flags & TH_FIN) &&
	    ntohl(tcph->th_seq) + len == f->buf[dir].seq)
		f->buf[dir].seq++;
out:
	return 0;
err2:
	flow_free(f);
err:
	return -1;
}

int flow_init(void)
{
	l_hash_table = calloc(FLOW_NR_MAX, sizeof(*l_hash_table));
	if (!l_hash_table)
		goto err;
	if (time_register_update_handler(flow_gc, NULL))
		goto err2;
	srandom(time(NULL));

	return 0;
err2:
	free(l_hash_table);
err:
	return -1;
}
