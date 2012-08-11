
#ifndef __LOG_H
#define __LOG_H

#include "types.h"
#include <sys/time.h>

int log_open(const char *fn);
int log_write(const struct timeval *ts, be32_t clnt, be32_t serv,
	      const char *host, const char *path, const char *keyword);
void log_close(void);

#endif /* __LOG_H */
