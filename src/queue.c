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

#include "queue.h"
#include <stdlib.h>

struct queue_item {
	void			*data;
	struct queue_item	*next;
};

struct queue {
	struct queue_item	*first;
	struct queue_item	**ptail;
};

queue_t *queue_alloc(void)
{
	queue_t *q = malloc(sizeof(*q));

	if (q) {
		q->first = NULL;
		q->ptail = &q->first;
	}

	return q;
}

void queue_free(queue_t *q)
{
	while (queue_del(q))
		/* empty */ ;
	free(q);
}

int queue_add(queue_t *q, void *data)
{
	struct queue_item *i = malloc(sizeof(*i));

	if (!i)
		return -1;
	i->data = data;
	i->next = NULL;
	*(q->ptail) = i;
	q->ptail = &i->next;

	return 0;
}

void *queue_del(queue_t *q)
{
	struct queue_item *i = q->first;

	if (i) {
		void *data = i->data;

		q->first = i->next;
		if (q->ptail == &i->next)
			q->ptail = &q->first;
		free(i);

		return data;
	}

	return NULL;
}
