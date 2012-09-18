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

#include "log.h"
#include "utils.h"
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

#ifndef NDEBUG
#include "unitest.h"

UNITEST_CASE(log)
{
	struct timeval ts;

	gettimeofday(&ts, NULL);
	assert(log_open("snoopy.log") == 0);
	assert(log_write(&ts, 0x01020304, 0x05060708, "example.com",
			 "/dir/file", "test") == 0);
	log_close();
	remove("snoopy.log");
}
#endif
