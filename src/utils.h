
#ifndef __UTILS_H
#define __UTILS_H

#include <stdlib.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

int url_decode(unsigned char *buf, int len);
void *memdup(const void *data, int len);
int if_get_mtu(const char *name);
void *memmem(const void *haystack, size_t haystacklen,
	     const void *needle, size_t needlelen);

#endif /* __UTILS_H */
