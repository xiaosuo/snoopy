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

#ifndef __RULE_H
#define __RULE_H

#include "types.h"
#include <stdbool.h>

typedef struct rule_list rule_list_t;

rule_list_t *rule_list_load(const char *fn);
bool rule_list_match(rule_list_t *l, be32_t _ip, be16_t _port);
void rule_list_free(rule_list_t *l);
int rule_list_dump(rule_list_t *l, const char *fn);

#endif /* __RULE_H */
