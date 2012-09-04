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

#define slist_head(name, type) \
struct name { \
	type	*first; \
}

#define SLIST_HEAD_INITIALIZER(head) { NULL }

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

#endif /* __LIST_H */
