
#include "utils.h"
#include <ctype.h>

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

#ifdef TEST
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
	char buf[] = "you%20are%20good%3b%3b";

	assert(url_decode(buf, strlen(buf)) == 14);
	printf("%s\n", buf);

	return 0;
}
#endif
