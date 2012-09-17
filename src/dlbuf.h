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

#ifndef __DLBUF_H
#define __DLBUF_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct dlbuf {
	char		*buf;
	uint32_t	len;
	uint32_t	size;
};

static inline void dlbuf_init(struct dlbuf *dlb, uint32_t size)
{
	dlb->buf = malloc(size);
	dlb->len = 0;
	dlb->size = dlb->buf ? size : 0;
}

static inline void dlbuf_reset(struct dlbuf *dlb)
{
	free(dlb->buf);
	dlb->buf = NULL;
	dlb->len = 0;
	dlb->size = 0;
}

static inline int dlbuf_resize(struct dlbuf *dlb, uint32_t size)
{
	void *ptr = realloc(dlb->buf, size);

	if (!ptr)
		return -1;
	dlb->buf = ptr;
	dlb->size = size;

	return 0;
}

static inline int dlbuf_append(struct dlbuf *dlb, const void *data,
		uint32_t len, uint32_t max)
{
	if (dlb->len + len >= dlb->size &&
	    (dlb->len + len >= max || dlbuf_resize(dlb, dlb->len + len + 1)))
		return -1;
	memcpy(dlb->buf + dlb->len, data, len);
	dlb->len += len;
	dlb->buf[dlb->len] = '\0';

	return 0;
}

#endif /* __DLBUF_H */
