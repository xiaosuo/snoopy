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

/**
 * A simple shared library to detect use-after-free bugs.
 *
 * Compile:
 *  $ cc -o libuse-after-free.so -fPIC -shared use-after-free.c
 *
 * Usage:
 *  $ LD_PRELOAD=./libuse-after-free.so ./a.out
 *
 * Usage with gdb. The following is an example gdb script:
 *  set args -R rules.conf -k keywords.conf -r crash.pcap -l log
 *  set exec-wrapper env 'LD_PRELOAD=./libuse-after-free.so'
 *  file ./snoopy
 *  r
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define ALIGN_TO_PAGE(size) ((size + getpagesize() - 1) & ~(getpagesize() - 1))

struct mm_meta {
	size_t	size;
};

#define MM_META_SIZE	((sizeof(struct mm_meta) + 7) & ~7)

#define my_assert(args...) \
do { \
	if (!(args)) { \
		fprintf(stderr, "error at: %s:%d\n", __FILE__, __LINE__); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

void *malloc(size_t size)
{
	struct mm_meta *meta;

	size = ALIGN_TO_PAGE(MM_META_SIZE + size);
	meta = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	my_assert(meta != MAP_FAILED);
	meta->size = size;

	return ((void *)meta) + MM_META_SIZE;
}

void free(void *ptr)
{
	struct mm_meta *meta;
	size_t size;

	if (!ptr)
		return;
	meta = ptr - MM_META_SIZE;
	size = meta->size;
	my_assert((((unsigned long)meta) & (getpagesize() - 1UL)) == 0UL);
	my_assert(munmap(meta, size) == 0);
	my_assert(mmap(meta, size, PROT_NONE,
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
			-1, 0) != MAP_FAILED);
}

void *calloc(size_t nmemb, size_t size)
{
	void *ptr = malloc(nmemb * size);

	if (ptr)
		memset(ptr, 0, nmemb * size);

	return ptr;
}
