
#ifndef __TIME_H
#define __TIME_H

#include <sys/time.h>

extern struct timeval g_time;

typedef void (*time_update_handler)(const struct timeval *tv, void *user);

int time_register_update_handler(time_update_handler h, void *user);

void time_update(const struct timeval *tv);

#endif /* __TIME_H */
