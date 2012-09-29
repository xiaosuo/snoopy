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

#ifndef __UNITEST_H
#define __UNITEST_H

#ifndef NDEBUG
void unitest_register(const char *name, void (*func)(void));
void unitest_deregister_all(void);
void unitest_run_all(void);
#define UNITEST_CASE(name) \
static void __unitest_##name(void); \
__attribute__((constructor)) void __unitest_register_##name(void) \
{ \
	unitest_register(#name, __unitest_##name); \
} \
static void __unitest_##name(void)
#else /* NDEBUG */
#define UNITEST_CASE(name) \
static void __unitest_##name(void)
#endif /* NDEBUG */

#endif /* __UNITEST_H */
