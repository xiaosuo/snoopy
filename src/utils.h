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

#ifndef __UTILS_H
#define __UTILS_H

#include <stdlib.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#define swap(x, y) \
do { \
	typeof(x) __t__ = x; \
	x = y; \
	y = __t__; \
} while (0)

#define NIPQUAD_FMT "%hhu.%hhu.%hhu.%hhu"
#define NIPQUAD(addr) \
	((uint8_t *)&addr)[0], \
	((uint8_t *)&addr)[1], \
	((uint8_t *)&addr)[2], \
	((uint8_t *)&addr)[3]

#define die(fmt, args...) \
do { \
	fprintf(stderr, fmt, ##args); \
	exit(EXIT_FAILURE); \
} while (0)

int url_decode(unsigned char *buf, int len);
void *xmemdup(const void *data, int len);
int if_get_mtu(const char *name);
#ifndef __GLIBC__
void *memmem(const void *haystack, size_t haystacklen,
		const void *needle, size_t needlelen);
#endif

#define strncasecmp_c(str1, str2) strncasecmp(str1, str2, sizeof(str2) - 1)

size_t strlncpy(char *dst, size_t size, const char *src, size_t len);
size_t strlncat(char *dst, size_t size, const char *src, size_t len);
void strtolower(char *str);
int get_quoted_str_len(const char *str, int size);
int get_random_bytes(void *buf, size_t size);

#endif /* __UTILS_H */
