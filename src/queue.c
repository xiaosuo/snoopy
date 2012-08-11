
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
