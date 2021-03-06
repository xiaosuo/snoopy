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

#include "utils.h"
#include "ctab.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>

static inline unsigned char hexval(unsigned char v)
{
	switch (v) {
	case '0'...'9':
		return v - '0';
	case 'a'...'f':
		return v - 'a' + 10;
	case 'A'...'F':
		return v - 'A' + 10;
	default:
		return 0;
	}
}

int url_decode(unsigned char *buf, int len)
{
	unsigned char *dec = buf;
	int dec_len = 0;
	unsigned char c;

	while (len-- > 0) {
		c = *buf++;
		if (c == '%') {
			unsigned char l;

			if (!is_hex(c = *buf++) || !is_hex(l = *buf++))
				return -1;
			c = (hexval(c) << 4) | hexval(l);
			len -= 2;
		}
		*dec++ = c;
		dec_len++;
	}
	*dec = '\0';

	return dec_len;
}

void *xmemdup(const void *data, int len)
{
	void *r = malloc(len + 1);

	if (r) {
		memcpy(r, data, len);
		((char *)r)[len] = '\0';
	}

	return r;
}

int if_get_mtu(const char *name)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

	if (s < 0)
		goto err;
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFMTU, &ifr))
		goto err2;
	close(s);

	return ifr.ifr_mtu;
err2:
	close(s);
err:
	return -1;
}

#ifndef __GLIBC__
void *memmem(const void *haystack, size_t haystacklen,
		const void *needle, size_t needlelen)
{
	assert(needlelen > 0);

	while (haystacklen >= needlelen) {
		if (memcmp(haystack, needle, needlelen) == 0)
			return (void *)haystack;
		haystack++;
		haystacklen--;
	}

	return NULL;
}
#endif

size_t strlncpy(char *dst, size_t size, const char *src, size_t len)
{
	size_t n = 0;

	assert(size > 0);

	while (size > 1 && len > 0 && *src) {
		*dst++ = *src++;
		n++;
		size--;
		len--;
	}
	*dst = '\0';

	return n;
}

size_t strlncat(char *dst, size_t size, const char *src, size_t len)
{
	size_t n = strlen(dst);

	if (size - n > 1)
		n += strlncpy(dst + n, size - n, src, len);

	return n;
}

void strtolower(char *str)
{
	int c;

	while ((c = *(unsigned char *)str)) {
		if (is_upalpha(c))
			*(unsigned char *)str = c + ('a' - 'A');
		str++;
	}
}

/* quoted-pair    = "\" CHAR */
static bool is_quoted_pair(const char *str)
{
	return str[0] == '\\' && is_char(str[1]);
}

/**
 * quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
 * qdtext         = <any TEXT except <">>
 */
/* return 0 on malformed quoted string */
int get_quoted_str_len(const char *str, int size)
{
	int len = 0;

	assert(*str == '"');
	str++;
	len++;
	size--;

	while (1) {
		if (size < 1)
			return 0;
		if (len >= 2 && is_quoted_pair(str)) {
			len += 2;
			str += 2;
			size -= 2;
		} else if (*str == '"') {
			return len + 1;
		} else {
			if (!is_text(*str))
				return 0;
			len++;
			str++;
			size--;
		}
	}
}

int get_random_bytes(void *buf, size_t size)
{
	int fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0)
		goto err;
	if (read(fd, buf, size) != size)
		goto err2;
	close(fd);

	return 0;
err2:
	close(fd);
err:
	return -1;
}

int set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return -1;

	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#ifndef NDEBUG
#include "unitest.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

UNITEST_CASE(utils)
{
	char buf[] = "you%20are%20good%3b%3b";

	assert(url_decode((unsigned char *)buf, strlen(buf)) == 14);
	assert(strcmp(buf, "you are good;;") == 0);
}
#endif
