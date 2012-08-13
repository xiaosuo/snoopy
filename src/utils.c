
#include "utils.h"
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

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

			if (!isxdigit((c = *buf++)) || !isxdigit((l = *buf++)))
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

void *memdup(const void *data, int len)
{
	void *r = malloc(len + 1);

	if (r) {
		memcpy(r, data, len);
		((char *)data)[len] = '\0';
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

void *memmem(const void *haystack, size_t haystacklen,
	     const void *needle, size_t needlelen)
{
	assert(needlelen > 0);

	while (haystacklen >= needlelen) {
		if (memcmp(haystack, needle, needlelen) == 0)
			return (void *)haystack;
		haystack++;
	}

	return NULL;
}

#ifdef TEST
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
	char buf[] = "you%20are%20good%3b%3b";

	assert(url_decode(buf, strlen(buf)) == 14);
	printf("%s\n", buf);
	printf("%d\n", if_get_mtu("en1"));

	return 0;
}
#endif
