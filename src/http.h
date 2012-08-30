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

#ifndef __HTTP_H
#define __HTTP_H

typedef void (*http_request_line_handler)(const char *method, const char *path,
		const char *http_version, void *user);
typedef void (*http_header_field_handler)(const char *name, const char *value,
		void *user);
typedef void (*http_body_handler)(const unsigned char *data, int len,
				  void *user);
typedef void (*http_msg_end_handler)(void *user);

typedef struct http_inspector http_inspector_t;

http_inspector_t *http_inspector_alloc(void);
void http_inspector_free(http_inspector_t *insp);
void http_inspector_set_request_line_handler(http_inspector_t *insp,
		http_request_line_handler h);
void http_inspector_set_header_field_handler(http_inspector_t *insp, int dir,
		http_header_field_handler h);
void http_inspector_set_body_handler(http_inspector_t *insp, int dir,
		http_body_handler h);
void http_inspector_set_msg_end_handler(http_inspector_t *insp, int dir,
		http_msg_end_handler h);

typedef struct http_inspect_ctx http_inspect_ctx_t;
http_inspect_ctx_t *http_inspect_ctx_alloc(void);
void http_inspect_ctx_free(http_inspect_ctx_t *ctx);
int http_inspect_data(http_inspector_t *insp, http_inspect_ctx_t *ctx, int dir,
		const unsigned char *data, int len, void *user);

#endif /* __HTTP_H */
