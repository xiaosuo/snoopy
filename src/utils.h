
#ifndef __UTILS_H
#define __UTILS_H

int url_decode(unsigned char *buf, int len);
void *memdup(const void *data, int len);
int if_get_mtu(const char *name);

#endif /* __UTILS_H */
