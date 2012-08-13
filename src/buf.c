
#include "buf.h"
#include "utils.h"
#include <assert.h>
#include <string.h>

/* this value is copied from /proc/sys/net/ipv4/tcp_wmem */
#define BUF_LIMIT	4194304

#define SEQ_GT(s1, s2) ((int)((s1) - (s2)) > 0)
#define SEQ_LT(s1, s2) ((int)((s1) - (s2)) < 0)
#define SEQ_GE(s1, s2) ((int)((s1) - (s2)) >= 0)
#define SEQ_LE(s1, s2) ((int)((s1) - (s2)) <= 0)

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
	mseq = MAX(seq, h->seq);
	data += mseq - seq;
	seq = mseq;

	/* right edge */
	end = MIN(end, h->seq + BUF_LIMIT);

	if (!SEQ_LT(seq, end))
		goto err;

	for (pprev = &h->first; (i = *pprev); pprev = &i->next) {
		/* seq < i->seq */
		if (SEQ_LT(seq, i->seq)) {
			mlen = MIN(end, i->seq) - seq;
			m = mb_alloc(seq, data, mlen);
			if (!m)
				goto err;
			m->next = i;
			*pprev = m;
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
		m->next = NULL;
		*pprev = m;
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

	while ((m = b->first)) {
		if (SEQ_GE(seq, m->seq + m->len)) {
			b->first = m->next;
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

	while ((m = b->first)) {
		b->first = m->next;
		mb_free(m);
	}
}
