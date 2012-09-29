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

#ifndef __TIME_H
#define __TIME_H

#include <sys/time.h>

extern struct timeval g_time;

typedef void (*time_update_handler)(const struct timeval *tv, void *user);

void *time_register_update_handler(time_update_handler h, void *user);
void time_deregister_update_handler(void *handle);

void time_update(const struct timeval *tv);

#endif /* __TIME_H */
