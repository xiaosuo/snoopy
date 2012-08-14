
#include "patn.h"
#include "utils.h"
#include "queue.h"
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct patn {
	unsigned char	*raw;
	int		len;
	char		*enc;
	struct patn	*next;
};

static void patn_free(struct patn *p)
{
	free(p->raw);
	free(p->enc);
	free(p);
}

static struct patn *patn_alloc(const unsigned char *data, int len)
{
	struct patn *p = malloc(sizeof(*p));

	if (!p)
		goto err;
	p->raw = xmemdup(data, len);
	if (!p->raw)
		goto err2;
	p->len = url_decode(p->raw, len);
	if (p->len < 0)
		goto err3;
	p->enc = xmemdup(data, len);
	if (!p->enc)
		goto err3;

	return p;
err3:
	free(p->raw);
err2:
	free(p);
err:
	return NULL;
}

#define PATN_ALPHABET_SIZE	256

struct patn_res {
	struct patn	*patn;
	struct patn_res	*next;
};

struct patn_state {
	struct patn_state	*next[PATN_ALPHABET_SIZE];
	struct patn_state	*fail;
	struct patn_res		*res;
	struct patn_state	*free_next;
};

int patn_state_add_res(struct patn_state *s, struct patn *p)
{
	struct patn_res *r = malloc(sizeof(*r));

	if (!r)
		return -1;
	r->patn = p;
	r->next = s->res;
	s->res = r;

	return 0;
}

void patn_state_free(struct patn_state *s)
{
	struct patn_res *r;

	while ((r = s->res)) {
		s->res = r->next;
		free(r);
	}
}

struct patn_list {
	struct patn		*patn;
	struct patn_state	*root;
	struct patn_state	*free_list;
};

struct patn_list *patn_list_alloc(void)
{
	struct patn_list *l = malloc(sizeof(*l));

	if (!l)
		goto err;
	l->patn = NULL;
	l->root = calloc(1, sizeof(struct patn_state));
	if (!l->root)
		goto err2;
	l->free_list = l->root;

	return l;
err2:
	free(l);
err:
	return NULL;
}

static int patn_list_add_patn(struct patn_list *l, const unsigned char *data,
			      int len)
{
	struct patn *p;
	struct patn_state *s;
	int i;

	p = patn_alloc(data, len);
	if (!p)
		goto err;
	p->next = l->patn;
	l->patn = p;

	s = l->root;
	for (i = 0; i < p->len; i++) {
		unsigned char c = p->raw[i];

		if (!s->next[c]) {
			struct patn_state *n = calloc(1, sizeof(*n));
			if (!n)
				goto err;
			s->next[c] = n;
			n->free_next = l->free_list;
			l->free_list = n;
		}
		s = s->next[c];
	}
	if (patn_state_add_res(s, p))
		goto err;

	return 0;
err:
	return -1;
}

static int patn_list_compile(struct patn_list *l)
{
	struct patn_state *s;
	queue_t *q;
	int c;

	q = queue_alloc();
	if (!q)
		goto err;
	s = l->root;
	for (c = 0; c < PATN_ALPHABET_SIZE; c++) {
		if (s->next[c]) {
			if (queue_add(q, s->next[c]))
				goto err2;
			s->next[c]->fail = s;
		} else {
			s->next[c] = s;
		}
	}
	while ((s = queue_del(q))) {
		for (c = 0; c < PATN_ALPHABET_SIZE; c++) {
			struct patn_state *tmp_s;
			struct patn_res *r;

			if (!s->next[c])
				continue;
			if (queue_add(q, s->next[c]))
				goto err2;
			tmp_s = s->fail;
			while (!tmp_s->next[c])
				tmp_s = tmp_s->fail;
			s->next[c]->fail = tmp_s->next[c];
			for (r = s->next[c]->fail->res; r; r = r->next) {
				if (patn_state_add_res(s->next[c], r->patn))
					goto err2;
			}
		}
	}

	/* NFA to DFA */
	s = l->root;
	for (c = 0; c < PATN_ALPHABET_SIZE; c++) {
		if (s->next[c] != s) {
			if (queue_add(q, s->next[c]))
				goto err2;
		}
	}
	while ((s = queue_del(q))) {
		for (c = 0; c < PATN_ALPHABET_SIZE; c++) {
			if (s->next[c]) {
				if (queue_add(q, s->next[c]))
					goto err2;
			} else {
				s->next[c] = s->fail->next[c];
			}
		}
	}

	queue_free(q);

	return 0;
err2:
	queue_free(q);
err:
	return -1;
}

patn_list_t *patn_list_load(const char *fn)
{
	FILE *fp;
	struct patn_list *l;
	unsigned char buf[LINE_MAX];

	l = patn_list_alloc();
	if (!l)
		goto err;
	fp = fopen(fn, "r");
	if (!fp)
		goto err2;
	while (fgets((char *)buf, sizeof(buf), fp)) {
		int len = strspn((char *)buf, " \t\r\n");

		/* skip emtpy lines */
		if (buf[len] == '\0')
			continue;

		/* remove the CR and NL from the tail */
		len = strlen((char *)buf);
		if (buf[len - 1] == '\n')
			buf[--len] = '\0';
		if (buf[len - 1] == '\r')
			buf[--len] = '\0';

		if (patn_list_add_patn(l, buf, len))
			goto err3;
	}
	if (!feof(fp) || ferror(fp))
		goto err3;
	fclose(fp);
	if (patn_list_compile(l))
		goto err3;

	return l;
err3:
	fclose(fp);
err2:
	patn_list_free(l);
err:
	return NULL;
}

void patn_list_free(patn_list_t *l)
{
	struct patn *p;
	struct patn_state *s;

	while ((p = l->patn)) {
		l->patn = p->next;
		patn_free(p);
	}

	while ((s = l->free_list)) {
		l->free_list = s->free_next;
		patn_state_free(s);
	}
	free(l);
}

struct patn_sch_ctx {
	struct patn_state	*state;
};

patn_sch_ctx_t *patn_sch_ctx_alloc(void)
{
	return calloc(1, sizeof(patn_sch_ctx_t));
}

void patn_sch_ctx_free(patn_sch_ctx_t *ctx)
{
	free(ctx);
}

void patn_sch_ctx_reset(patn_sch_ctx_t *c)
{
	c->state = NULL;
}

int patn_sch(patn_list_t *l, patn_sch_ctx_t *c, const unsigned char *buf,
	     int len, int (*cb)(const char *patn, void *data), void *data)
{
	struct patn_state *s;
	int n = 0;

	if (c->state)
		s = c->state;
	else
		s = l->root;
	while (len-- > 0) {
		struct patn_res *r;

		s = s->next[*buf++];
		for (r = s->res; r; r = r->next) {
			int retval = cb(r->patn->enc, data);

			if (retval < 0) { /* ignore errors */
				continue;
			} else if (retval > 0) {
				n++;
				c->state = NULL;
				goto out;
			} else {
				n++;
			}
		}
	}
	c->state = s;
out:
	return n;
}

#ifdef TEST
#include <assert.h>

static int patn_print(const char *patn, void *data)
{
	printf("%s\n", patn);

	return 0;
}

int main(void)
{
	patn_list_t *l;
	patn_sch_ctx_t *c;

	assert((l = patn_list_load("../test/patn.txt")));
	assert((c = patn_sch_ctx_alloc()));
	assert((patn_sch(l, c, "he and she are hers friends", 27,
			 patn_print, NULL) == 5));
	patn_list_free(l);
	patn_sch_ctx_free(c);

	return EXIT_SUCCESS;
}
#endif
