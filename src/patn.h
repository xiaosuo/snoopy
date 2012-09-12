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

#ifndef __PATN_H
#define __PATN_H

typedef struct patn_list patn_list_t;
typedef struct patn_sch_ctx patn_sch_ctx_t;

patn_list_t *patn_list_load(const char *fn);
void patn_list_free(patn_list_t *l);

patn_sch_ctx_t *patn_sch_ctx_alloc(void);
void patn_sch_ctx_free(patn_sch_ctx_t *ctx);
void patn_sch_ctx_reset(patn_sch_ctx_t *c);
int patn_sch(patn_list_t *l, patn_sch_ctx_t *c, const unsigned char *buf,
	     int len, int (*cb)(const unsigned char *patn, void *data),
	     void *data);

#endif /* __PATN_H */
