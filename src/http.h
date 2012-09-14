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

#include <stdint.h>

struct http_stat {
	uint64_t	overflowed_line;
	uint64_t	malformed_start_line;
	uint64_t	malformed_request_line;
	uint64_t	malformed_status_line;
	uint64_t	malformed_header;
	uint64_t	malformed_content_encoding;
	uint64_t	malformed_chunk_size;
	uint64_t	malformed_chunk_crlf;
	uint64_t	malformed_trailer;
	uint64_t	good;
};

extern struct http_stat g_http_stat;

void http_stat_show(void);

typedef void (*http_request_line_handler)(const char *method, const char *path,
		int minor_ver, void *user);
typedef void (*http_status_line_handler)(int minor_ver, int status_code,
		const char *reason_phase, void *user);
typedef void (*http_header_field_handler)(const char *name, int name_len,
		const char *value, int value_len, void *user);
typedef void (*http_body_handler)(const unsigned char *data, int len,
				  void *user);
typedef void (*http_msg_end_handler)(void *user);

typedef struct http_parser http_parser_t;

http_parser_t *http_parser_alloc(void);
void http_parser_free(http_parser_t *pasr);
void http_parser_set_request_line_handler(http_parser_t *pasr,
		http_request_line_handler h);
void http_parser_set_status_line_handler(http_parser_t *pasr,
		http_status_line_handler h);
void http_parser_set_header_field_handler(http_parser_t *pasr, int dir,
		http_header_field_handler h);
void http_parser_set_body_handler(http_parser_t *pasr, int dir,
		http_body_handler h);
void http_parser_set_msg_end_handler(http_parser_t *pasr, int dir,
		http_msg_end_handler h);

typedef struct http_parse_ctx http_parse_ctx_t;
http_parse_ctx_t *http_parse_ctx_alloc(void);
void http_parse_ctx_free(http_parse_ctx_t *ctx);
int http_parse(http_parser_t *pasr, http_parse_ctx_t *ctx, int dir,
		const unsigned char *data, int len, void *user);

#endif /* __HTTP_H */
