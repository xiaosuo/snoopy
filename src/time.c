
#include "time.h"
#include <stdlib.h>

struct timeval g_time = { 0 };

struct time_update_handler_iter {
	time_update_handler		h;
	void				*user;
	struct time_update_handler_iter	*next;
};

static struct time_update_handler_iter *l_time_update_handler_head = NULL;

int time_register_update_handler(time_update_handler h, void *user)
{
	struct time_update_handler_iter *i = malloc(sizeof(*i));

	if (!i)
		return -1;

	i->h = h;
	i->user = user;
	i->next = l_time_update_handler_head;
	l_time_update_handler_head = i;

	return 0;
}

void time_update(const struct timeval *tv)
{
	if (timercmp(tv, &g_time, >)) {
		struct time_update_handler_iter *i;

		g_time = *tv;
		for (i = l_time_update_handler_head; i; i = i->next)
			i->h(&g_time, i->user);
	}
}
