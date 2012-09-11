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

#ifndef __HTML_H
#define __HTML_H

typedef struct html_parse_ctx html_parse_ctx_t;
html_parse_ctx_t *html_parse_ctx_alloc(const char *charset);
void html_parse_ctx_free(html_parse_ctx_t *ctx);

typedef void (*html_data_handler)(const unsigned char *data, int len,
		void *user);

int html_parse(html_parse_ctx_t *ctx, const unsigned char *data, int len,
		html_data_handler h, void *user);

#endif /* __HTML_H */
