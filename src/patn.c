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

#include "patn.h"
#include "utils.h"
#include "queue.h"
#include "list.h"
#include "ctab.h"
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct patn {
	unsigned char			*patn;
	slist_entry(struct patn)	link;
};

static void patn_free(struct patn *p)
{
	free(p->patn);
	free(p);
}

static struct patn *patn_alloc(const unsigned char *patn)
{
	struct patn *p = malloc(sizeof(*p));

	if (!p)
		goto err;
	p->patn = (unsigned char *)strdup((const char *)patn);
	if (!p->patn)
		goto err2;

	return p;
err2:
	free(p);
err:
	return NULL;
}

#define PATN_ALPHABET_SIZE	256

struct patn_res {
	struct patn			*patn;
	slist_entry(struct patn_res)	link;
};

struct patn_state {
	struct patn_state		*next[PATN_ALPHABET_SIZE];
	struct patn_state		*fail;
	slist_head( , struct patn_res)	res_list;
	slist_entry(struct patn_state)	link;
};

int patn_state_add_res(struct patn_state *s, struct patn *p)
{
	struct patn_res *r = malloc(sizeof(*r));

	if (!r)
		return -1;
	r->patn = p;
	slist_add_head(&s->res_list, r, link);

	return 0;
}

void patn_state_free(struct patn_state *s)
{
	struct patn_res *r;

	while ((r = slist_first(&s->res_list))) {
		slist_del_head(&s->res_list, r, link);
		free(r);
	}
	free(s);
}

struct patn_list {
	slist_head( , struct patn)		patn_list;
	struct patn_state			*root;
	slist_head( , struct patn_state)	free_list;
};

struct patn_list *patn_list_alloc(void)
{
	struct patn_list *l = malloc(sizeof(*l));

	if (!l)
		goto err;
	slist_head_init(&l->patn_list);
	l->root = calloc(1, sizeof(struct patn_state));
	if (!l->root)
		goto err2;
	slist_head_init(&l->root->res_list);
	slist_head_init(&l->free_list);
	slist_add_head(&l->free_list, l->root, link);

	return l;
err2:
	free(l);
err:
	return NULL;
}

static int patn_list_add_patn(struct patn_list *l, const unsigned char *patn)
{
	struct patn *p;
	struct patn_state *s;
	int i;

	p = patn_alloc(patn);
	if (!p)
		goto err;
	slist_add_head(&l->patn_list, p, link);

	s = l->root;
	for (i = 0; p->patn[i] != '\0'; i++) {
		unsigned char c = p->patn[i];

		if (!s->next[c]) {
			struct patn_state *n = calloc(1, sizeof(*n));
			if (!n)
				goto err;
			slist_head_init(&n->res_list);
			s->next[c] = n;
			slist_add_head(&l->free_list, n, link);
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
			slist_for_each(r, &s->next[c]->fail->res_list, link) {
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
		unsigned char *ptr = (unsigned char *)__skip_space((char *)buf);
		int len, i;

		/* skip empty lines */
		if (*ptr == '\0')
			continue;
		len = strlen((char *)ptr);
		while (len > 0 && is_space(ptr[len - 1]))
			ptr[--len] = '\0';

		/* check if there is a space in the keyword*/
		for (i = 0; i < len; i++) {
			if (is_space(ptr[i]))
				goto err3;
		}

		if (patn_list_add_patn(l, ptr))
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

	while ((p = slist_first(&l->patn_list))) {
		slist_del_head(&l->patn_list, p, link);
		patn_free(p);
	}

	while ((s = slist_first(&l->free_list))) {
		slist_del_head(&l->free_list, s, link);
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
	     int len, int (*cb)(const unsigned char *patn, void *data),
	     void *data)
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
		slist_for_each(r, &s->res_list, link) {
			int retval = cb(r->patn->patn, data);

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

static int patn_print(const unsigned char *patn, void *data)
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
