
#include "log.h"
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int l_log_fd = -1;

int log_open(const char *fn)
{
	assert(l_log_fd < 0);
	l_log_fd = open(fn, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (l_log_fd < 0)
		return -1;

	return 0;
}

#define NIPQUAD_FMT "%hhu.%hhu.%hhu.%hhu"
#define NIPQUAD(addr) \
	((uint8_t *)&addr)[0], \
	((uint8_t *)&addr)[1], \
	((uint8_t *)&addr)[2], \
	((uint8_t *)&addr)[3]

int log_write(const struct timeval *ts, be32_t clnt, be32_t serv,
	      const char *host, const char *path, const char *keyword)
{
	char buf[LINE_MAX];
	struct tm tm;
	int len, retval;

	gmtime_r(&ts->tv_sec, &tm);
	len = strftime(buf, sizeof(buf), "%FT%T", &tm);
	retval = snprintf(buf + len, sizeof(buf) - len,
			 ".%06ldZ " NIPQUAD_FMT " " NIPQUAD_FMT " "
			 "http://%s%s %s\n",
			 (long)ts->tv_usec, NIPQUAD(clnt), NIPQUAD(serv),
			 host, path, keyword);
	if (retval < 0 || retval >= sizeof(buf) - len ||
	    write(l_log_fd, buf, retval + len) != retval + len)
		return -1;

	return 0;
}

void log_close(void)
{
	assert(l_log_fd >= 0);
	close(l_log_fd);
	l_log_fd = -1;
}

#ifdef TEST
int main(void)
{
	struct timeval ts;

	gettimeofday(&ts, NULL);
	assert(log_open("snoopy.log") == 0);
	assert(log_write(&ts, 0x01020304, 0x05060708, "example.com",
			 "/dir/file", "test") == 0);
	log_close();

	return EXIT_SUCCESS;
}
#endif
