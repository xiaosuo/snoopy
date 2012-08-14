
#include "flow.h"
#include "types.h"
#include "buf.h"
#include <time.h>

enum {
	FLOW_STATE_INIT		= 0,
	FLOW_STATE_CLNT_SYN	= 1,
	FLOW_STATE_SERV_SYN	= 2,
	FLOW_STATE_BOTH_SYN	= 3,
	FLOW_STATE_CLNT_FIN	= 4,
	FLOW_STATE_SERV_FIN	= 8,
	FLOW_STATE_BOTH_FIN	= 12,
	FLOW_STATE_ACK		= 16,
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
	int			state;
	struct buf		clnt;
	struct buf		serv;
	struct flow_tag		*tag;
	struct flow		*hash_next;
	struct flow		**hash_pprev;
	struct flow		*gc_next;
	struct flow		**gc_pprev;
	struct timeval		timeout;
};

#define FLOW_GC_INCOMP_TIMEO	30
#define FLOW_GC_COMP_TIMEO	300
#define FLOW_NR_MAX		(1 << 20)

static struct flow *l_gc_incomp_head = NULL;
static struct flow **l_gc_incomp_ptail = &l_gc_incomp_head;

static struct flow *l_gc_comp_head = NULL;
static struct flow **l_gc_comp_ptail = &l_gc_comp_head;

static struct flow **l_hash_table = NULL;
static int l_flow_cnt = 0;

/* this is used to avoid clock rollback */
static struct timeval l_time = { 0 };

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

int flow_init(void)
{
	l_hash_table = calloc(FLOW_NR_MAX, sizeof(*l_hash_table));
	if (!l_hash_table)
		return -1;
	srandom(time(NULL));

	return 0;
}

static void flow_gc_del(struct flow *f)
{
	if (!f->gc_pprev)
		return;
	*(f->gc_pprev) = f->gc_next;
	if (f->gc_next) {
		f->gc_next->gc_pprev = f->gc_pprev;
	} else {
		if (f->state < FLOW_STATE_ACK)
			l_gc_incomp_ptail = f->gc_pprev;
		else
			l_gc_comp_ptail = f->gc_pprev;
	}
	f->gc_pprev = NULL;
}

static void flow_gc_add(struct flow *f)
{
	f->gc_next = NULL;
	if (f->state < FLOW_STATE_ACK) {
		*(l_gc_incomp_ptail) = f;
		f->gc_pprev = l_gc_incomp_ptail;
		l_gc_incomp_ptail = &f->gc_next;
	} else {
		*(l_gc_comp_ptail) = f;
		f->gc_pprev = l_gc_comp_ptail;
		l_gc_comp_ptail = &f->gc_next;
	}
}

static void flow_free(struct flow *f)
{
	struct flow_tag *t;

	buf_drain(&f->clnt);
	buf_drain(&f->serv);
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
	--l_flow_cnt;
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
	f->state = FLOW_STATE_INIT;
	buf_init(&f->clnt, 0);
	buf_init(&f->serv, 0);
	f->tag = NULL;
	flow_gc_add(f);
	f->timeout.tv_sec = l_time.tv_sec + FLOW_GC_INCOMP_TIMEO;
	f->timeout.tv_usec = l_time.tv_usec;
	++l_flow_cnt;

	return f;
err:
	return NULL;
}

static struct flow *flow_get(struct ip *ip, struct tcphdr *tcph, bool *is_clnt,
		bool *is_new)
{
	struct flow *f;
	uint32_t hash = flow_hash(ip->ip_src.s_addr, ip->ip_dst.s_addr,
			tcph->th_sport, tcph->th_dport);

	hash &= FLOW_NR_MAX - 1;
	for (f = l_hash_table[hash]; f; f = f->hash_next) {
		if (ip->ip_src.s_addr == f->src &&
		    ip->ip_dst.s_addr == f->dst &&
		    tcph->th_sport == f->sport && tcph->th_dport == f->dport) {
			*is_clnt = true;
			*is_new = false;
			goto out;
		}
		if (ip->ip_dst.s_addr == f->src &&
		    ip->ip_src.s_addr == f->dst &&
		    tcph->th_dport == f->sport && tcph->th_sport == f->dport) {
			*is_clnt = false;
			*is_new = false;
			goto out;
		}
	}

	/* only SYN can open a new connection */
	if ((tcph->th_flags & (TH_SYN | TH_ACK)) != TH_SYN)
		goto err;

	/* the flow table is full, so we need to drop some incomplete
	 * connection randomly to free space */
	while (l_flow_cnt >= FLOW_NR_MAX) {
		int bucket = random() & (FLOW_NR_MAX - 1);

		/* TODO: tail drop */
		for (f = l_hash_table[bucket]; f; f = f->hash_next) {
			if (f->state < FLOW_STATE_ACK) {
				flow_free(f);
				break;
			}
		}
	}

	f = flow_alloc(ip, tcph);
	if (!f)
		goto err;
	f->hash_next = l_hash_table[hash];
	l_hash_table[hash] = f;
	f->hash_pprev = &l_hash_table[hash];
	*is_clnt = true;
	*is_new = true;
out:
	return f;
err:
	return NULL;
}

static void flow_gc(void)
{
	struct flow *f;

	while ((f = l_gc_incomp_head)) {
		if (timercmp(&f->timeout, &l_time, >))
			break;
		flow_free(f);
	}

	while ((f = l_gc_comp_head)) {
		if (timercmp(&f->timeout, &l_time, >))
			break;
		flow_free(f);
	}
}

/* two lists for incomplete flow or complete flow */
int flow_inspect(const struct timeval *ts, struct ip *ip, struct tcphdr *tcph,
		const unsigned char *data, int len, flow_data_handler h,
		void *user)
{
	struct flow *f;
	bool is_clnt, is_new;

	if (timercmp(ts, &l_time, >)) {
		l_time = *ts;
		flow_gc();
	}

	f = flow_get(ip, tcph, &is_clnt, &is_new);
	if (!f)
		goto err;

	if (tcph->th_flags & TH_RST) {
		flow_free(f);
		goto out;
	}
	if (!is_new)
		flow_gc_del(f);
	if (tcph->th_flags & TH_SYN) {
		if (is_clnt) {
			if (f->state == FLOW_STATE_INIT) {
				f->clnt.seq = ntohl(tcph->th_seq) + 1;
				f->state = FLOW_STATE_CLNT_SYN;
			}
		} else {
			if ((f->state & FLOW_STATE_BOTH_SYN) ==
					FLOW_STATE_CLNT_SYN) {
				f->serv.seq = ntohl(tcph->th_seq) + 1;
				f->state |= FLOW_STATE_SERV_SYN;
			}
		}
	} else if (tcph->th_flags & TH_FIN) {
		if (is_clnt) {
			f->state |= FLOW_STATE_CLNT_FIN;
		} else {
			f->state |= FLOW_STATE_SERV_FIN;
		}
		if ((f->state & FLOW_STATE_BOTH_FIN) == FLOW_STATE_BOTH_FIN) {
			flow_free(f);
			goto out;
		}
	} else if (tcph->th_flags & TH_ACK) {
		if ((f->state & FLOW_STATE_BOTH_SYN) == FLOW_STATE_BOTH_SYN)
			f->state |= FLOW_STATE_ACK;
	}
	if (!is_new)
		flow_gc_add(f);

	if ((f->state & FLOW_STATE_ACK) && len > 0) {
		uint32_t seq = ntohl(tcph->th_seq);
		struct buf *buf = is_clnt ? &f->clnt : &f->serv;

		if (seq == buf->seq) {
			struct mb *m;

			h(f, is_clnt, data, len, user);
			buf_drain_to(buf, seq + len);
			while ((m = buf_del(buf))) {
				h(f, is_clnt, m->data, m->len, user);
				mb_free(m);
			}
		} else if (buf_add(buf, seq, data, len)) {
			goto err;
		}
	}
out:
	return 0;
err:
	return -1;
}
