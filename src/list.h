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

#ifndef __LIST_H
#define __LIST_H

/* Singly-linked List */

#define slist_head(name, type) \
struct name { \
	type	*first; \
}

#define SLIST_HEAD_INITIALIZER(head) { .first = NULL }

#define slist_head_init(head) \
do { \
	(head)->first = NULL; \
} while (0)

#define slist_entry(type) \
struct { \
	type	*next; \
}

#define slist_add_head(head, item, entry) \
do { \
	(item)->entry.next = (head)->first; \
	(head)->first = (item); \
} while (0)

#define slist_first(head) ((head)->first)

#define slist_del_head(head, item, entry) \
do { \
	(head)->first = (item)->entry.next; \
} while (0)

#define slist_for_each(item, head, entry) \
	for (item = (head)->first; item; item = item->entry.next)

#define slist_for_each_pprev(item, pitem, head, entry) \
	for (pitem = &(head)->first; (item = *pitem); \
	     pitem = &item->entry.next)

#define slist_del(item, pitem, entry) \
do { \
	*(pitem) = item->entry.next; \
} while (0)

#define slist_insert_before(item, pitem, new, entry) \
do { \
	new->entry.next = item; \
	*(pitem) = new; \
} while (0)

/* Singly-linked Tail List */

#define stlist_head(name, type) \
struct name { \
	type	*first; \
	type	**ptail; \
}

#define STLIST_HEAD_INITIALIZER(head) \
{ \
	.first	= NULL, \
	.ptail	= &(head)->first, \
}

#define stlist_head_init(head) \
do { \
	(head)->first = NULL; \
	(head)->ptail = &(head)->first; \
} while (0)

#define stlist_entry(type) \
struct { \
	type	*next; \
}

#define stlist_add_tail(head, item, entry) \
do { \
	(item)->entry.next = NULL; \
	*((head)->ptail) = item; \
	(head)->ptail = &(item)->entry.next; \
} while (0)

#define stlist_first(head) ((head)->first)

#define stlist_del_head(head, item, entry) \
do { \
	(head)->first = (item)->entry.next; \
	if (!(head)->first) \
		(head)->ptail = &(head)->first; \
} while (0)

#define stlist_for_each slist_for_each

/* List */

#define list_head(name, type) \
struct name { \
	type	*first; \
}

#define LIST_HEAD_INITIALIZER(head)	{ .first = NULL }

#define list_head_init(head) \
do { \
	(head)->first = NULL; \
} while (0)

#define list_entry(type) \
struct { \
	type	*next; \
	type	**pprev; \
}

#define list_add_head(head, item, entry) \
do { \
	(item)->entry.next = (head)->first; \
	(head)->first = (item); \
	(item)->entry.pprev = &(head)->first; \
	if ((item)->entry.next) \
		(item)->entry.next->entry.pprev = &(item)->entry.next; \
} while (0)

#define list_del(item, entry) \
do { \
	*((item)->entry.pprev) = (item)->entry.next; \
	if ((item)->entry.next) \
		(item)->entry.next->entry.pprev = (item)->entry.pprev; \
} while (0)

#define list_for_each slist_for_each

#define list_for_each_safe(item, nitem, head, entry) \
	for (item = (head)->first; item && ({ nitem = item->entry.next; 1; }); \
	     item = nitem)

/* Tail List */

#define tlist_head(name, type) \
struct name { \
	type	*first; \
	type	**ptail; \
}

#define TLIST_HEAD_INITIALIZER(head) \
{ \
	.first	= NULL, \
	.ptail	= &(head)->first, \
}

#define tlist_head_init(head) \
do { \
	(head)->first = NULL; \
	(head)->ptail = (head)->first; \
} while (0)

#define tlist_first(head) ((head)->first)

#define tlist_entry(type) \
struct { \
	type	*next; \
	type	**pprev; \
}

#define tlist_entry_init(entry) \
do { \
	(entry)->pprev = NULL; \
} while (0)

#define tlist_entry_inline(entry) ((entry)->pprev != NULL)

#define tlist_add_tail(head, item, entry) \
do { \
	(item)->entry.next = NULL; \
	*((head)->ptail) = (item); \
	(item)->entry.pprev = (head)->ptail; \
	(head)->ptail = &(item)->entry.next; \
} while (0)

#define tlist_del(head, item, entry) \
do { \
	*((item)->entry.pprev) = (item)->entry.next; \
	if ((item)->entry.next) \
		(item)->entry.next->entry.pprev = (item)->entry.pprev; \
	else \
		(head)->ptail = (item)->entry.pprev; \
} while (0)

#endif /* __LIST_H */
