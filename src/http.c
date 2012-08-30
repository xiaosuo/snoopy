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

#include "http.h"
#include "utils.h"
#include "flow.h"
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <zlib.h>

struct http_parser {
	http_request_line_handler	request_line;
	http_header_field_handler	header_field[PKT_DIR_NUM];
	http_body_handler		body[PKT_DIR_NUM];
	http_msg_end_handler		msg_end[PKT_DIR_NUM];
};

http_parser_t *http_parser_alloc(void)
{
	return calloc(1, sizeof(struct http_parser));
}

void http_parser_free(http_parser_t *pasr)
{
	free(pasr);
}

void http_parser_set_request_line_handler(http_parser_t *pasr,
		http_request_line_handler h)
{
	pasr->request_line = h;
}

void http_parser_set_header_field_handler(http_parser_t *pasr, int dir,
		http_header_field_handler h)
{
	pasr->header_field[dir] = h;
}

void http_parser_set_body_handler(http_parser_t *pasr, int dir,
		http_body_handler h)
{
	pasr->body[dir] = h;
}

void http_parser_set_msg_end_handler(http_parser_t *pasr, int dir,
		http_msg_end_handler h)
{
	pasr->msg_end[dir] = h;
}

static void call_request_line_handler(http_parser_t *pasr,
		const char *method, const char *path, const char *http_version,
		void *user)
{
	if (pasr->request_line)
		pasr->request_line(method, path, http_version, user);
}

static void call_header_field_handler(http_parser_t *pasr, int dir,
		const char *name, const char *value, void *user)
{
	if (pasr->header_field[dir])
		pasr->header_field[dir](name, value, user);
}

static void call_body_handler(http_parser_t *pasr, int dir,
		const unsigned char *data, int len, void *user)
{
	if (pasr->body[dir])
		pasr->body[dir](data, len, user);
}

static void call_msg_end_handler(http_parser_t *pasr, int dir, void *user)
{
	if (pasr->msg_end[dir])
		pasr->msg_end[dir](user);
}

/*
        generic-message = start-line
                          *(message-header CRLF)
                          CRLF
                          [ message-body ]
        start-line      = Request-Line | Status-Line
*/

enum {
	HTTP_STATE_START_LINE,
	HTTP_STATE_MSG_HDR,
	HTTP_STATE_MSG_BODY,
	HTTP_STATE_MSG_CHUNK_SIZE,
	HTTP_STATE_MSG_CHUNK_DATA,
	HTTP_STATE_MSG_CHUNK_CRLF,
	HTTP_STATE_MSG_CHUNK_TRAILER,
};

#define HTTP_LINE_SIZE	1024

enum {
	MINOR_STATE_INIT,
	MINOR_STATE_CR,
	MINOR_STATE_CRLF,
};

enum {
	HTTP_CE_NONE,
	HTTP_CE_GZIP,
	HTTP_CE_DEFLATE,
};

struct http_parse_ctx_common {
	int			state;
	int			minor_state;
	unsigned long long	body_len;
	int			line_len;
	unsigned int		is_chunked	: 1;
	unsigned int		ce		: 2;
	unsigned int		ce_end		: 1;
	z_streamp		streamp;
	char			line[HTTP_LINE_SIZE]; /* it must be the last */
};

static void http_parse_ctx_common_init(struct http_parse_ctx_common *c)
{
	memset(c, 0, offsetof(struct http_parse_ctx_common, line));
}

static void http_parse_ctx_common_reset(struct http_parse_ctx_common *c)
{
	if (c->streamp) {
		inflateEnd(c->streamp);
		free(c->streamp);
	}
	http_parse_ctx_common_init(c);
}

static int http_parse_ctx_common_add_line(struct http_parse_ctx_common *c,
		const unsigned char *str, int len)
{
	if (c->line_len + len >= sizeof(c->line))
		return -1;
	memcpy(c->line + c->line_len, str, len);
	c->line_len += len;
	c->line[c->line_len] = '\0';

	return 0;
}

struct http_parse_ctx {
	struct http_parse_ctx_common	common[PKT_DIR_NUM];
};

http_parse_ctx_t *http_parse_ctx_alloc(void)
{
	struct http_parse_ctx *c = malloc(sizeof(*c));

	if (!c)
		return NULL;
	http_parse_ctx_common_init(&c->common[PKT_DIR_C2S]);
	http_parse_ctx_common_init(&c->common[PKT_DIR_S2C]);

	return c;
}

void http_parse_ctx_free(http_parse_ctx_t *ctx)
{
	int dir;

	for (dir = 0; dir < PKT_DIR_NUM; dir++) {
		if (ctx->common[dir].streamp) {
			inflateEnd(ctx->common[dir].streamp);
			free(ctx->common[dir].streamp);
		}
	}
	free(ctx);
}

/*
        Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
       HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
       DIGIT          = <any US-ASCII digit "0".."9">
*/
static int http_parse_request_line(http_parser_t *pasr, char *line, void *user)
{
	char *path = strchr(line, ' ');
	char *ver;

	if (!path)
		goto err;
	*path++ = '\0';
	ver = strchr(path, ' ');
	if (!ver)
		goto err;
	*ver++ = '\0';

	call_request_line_handler(pasr, line, path, ver, user);

	return 0;
err:
	return -1;
}

/*
       Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
*/
static int http_get_line(struct http_parse_ctx_common *c,
		bool *end, const unsigned char *data, int len, void *user)
{
	int n;
	const unsigned char *ptr;

	*end = false;
	switch (c->minor_state) {
	case MINOR_STATE_INIT:
		ptr = memmem(data, len, "\r\n", 2);
		if (ptr) {
			ptr += 2;
			n = ptr - data;
			if (http_parse_ctx_common_add_line(c, data, n - 2))
				goto err;
			*end = true;
			break;
		}
		if (data[len - 1] == '\r')
			c->minor_state = MINOR_STATE_CR;
		n = len;
		if (http_parse_ctx_common_add_line(c, data, n))
			goto err;
		break;
	case MINOR_STATE_CR:
		c->minor_state = MINOR_STATE_INIT;
		if (data[0] == '\n') {
			n = 1;
			c->line[--c->line_len] = '\0';
			*end = true;
			break;
		}
		n = 0;
		break;
	default:
		abort();
	}

	return n;
err:
	return -1;
}

/* 
       message-header = field-name ":" [ field-value ]
       field-name     = token
       field-value    = *( field-content | LWS )
       field-content  = <the OCTETs making up the field-value
                        and consisting of either *TEXT or combinations
                        of token, separators, and quoted-string>
       token          = 1*<any CHAR except CTLs or separators>
       separators     = "(" | ")" | "<" | ">" | "@"
                      | "," | ";" | ":" | "\" | <">
                      | "/" | "[" | "]" | "?" | "="
                      | "{" | "}" | SP | HT
       CHAR           = <any US-ASCII character (octets 0 - 127)>
       CTL            = <any US-ASCII control character
                        (octets 0 - 31) and DEL (127)>
       quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
       qdtext         = <any TEXT except <">>
       quoted-pair    = "\" CHAR
       OCTET          = <any 8-bit sequence of data>
       SP             = <US-ASCII SP, space (32)>
       HT             = <US-ASCII HT, horizontal-tab (9)>
       <">            = <US-ASCII double-quote mark (34)>
       CRLF           = CR LF
       LWS            = [CRLF] 1*( SP | HT )
*/
static int http_parse_header_field(http_parser_t *pasr,
		struct http_parse_ctx_common *c, int dir, char *hdr,
		void *user)
{
	char *fv = strchr(hdr, ':');

	if (!fv)
		goto err;
	*fv++ = '\0';
	while (*fv == ' ' || *fv == '\t')
		fv++;

	if (strcasecmp(hdr, "Content-Length") == 0) {
		c->body_len = strtoull(fv, NULL, 0);
	} else if (strcasecmp(hdr, "Transfer-Encoding") == 0) {
		/*
		 * Transfer-Encoding       = "Transfer-Encoding" ":" 1#transfer-coding
		 * transfer-coding         = "chunked" | transfer-extension
		 * transfer-extension      = token *( ";" parameter )
		 */
		/* All transfer-coding values are case-insensitive */
		if (strcasecmp(fv, "chunked") == 0)
			c->is_chunked = 1;
	} else if (strcasecmp(hdr, "Content-Encoding") == 0) {
		/*
		 * Content-Encoding  = "Content-Encoding" ":" 1#content-coding
		 * content-coding   = token
		 * All content-coding values are case-insensitive
		 */
		/*
		 * If multiple encodings have been applied to an entity,
		 * the content codings MUST be listed in the order in which
		 * they were applied.
		 */
		/* We only support one encoding now */
		if (c->streamp) {
			inflateEnd(c->streamp);
			free(c->streamp);
			c->streamp = NULL;
		}
		if (strcasecmp(fv, "gzip") == 0 ||
		    strcasecmp(fv, "x-gzip") == 0)
			c->ce = HTTP_CE_GZIP;
		else if (strcasecmp(fv, "deflate") == 0)
			c->ce = HTTP_CE_DEFLATE;
		else
			c->ce = HTTP_CE_NONE;
	}

	call_header_field_handler(pasr, dir, hdr, fv, user);

	return 0;
err:
	return -1;
}

static int http_parse_msg_hdr(http_parser_t *pasr,
		struct http_parse_ctx_common *c, bool *end, int dir,
		const unsigned char *data, int len, void *user)
{
	int n;
	const unsigned char *ptr;

	*end = false;
	switch (c->minor_state) {
	case MINOR_STATE_INIT:
		ptr = memmem(data, len, "\r\n", 2);
		if (ptr) {
			ptr += 2;
			n = ptr - data;
			if (n + c->line_len == 2) {
				*end = true;
				break;
			}
			if (ptr == data + len) {
				if (http_parse_ctx_common_add_line(c, data, n))
					goto err;
				c->minor_state = MINOR_STATE_CRLF;
				break;
			}
			if (*ptr == ' ' || *ptr == '\t') {
				/* LWS */
				n++;
				if (http_parse_ctx_common_add_line(c, data, n))
					goto err;
				break;
			}
			if (http_parse_ctx_common_add_line(c, data, n - 2))
				goto err;
			if (http_parse_header_field(pasr, c, dir, c->line,
					user))
				goto err;
			c->line_len = 0;
			break;
		}
		if (data[len - 1] == '\r')
			c->minor_state = MINOR_STATE_CR;
		n = len;
		if (http_parse_ctx_common_add_line(c, data, n))
			goto err;
		break;
	case MINOR_STATE_CR:
		if (data[0] == '\n') {
			if (c->line_len == 1) {
				n = 1;
				c->minor_state = MINOR_STATE_INIT;
				*end = true;
				break;
			}
			c->minor_state = MINOR_STATE_CRLF;
			n = 1;
			if (http_parse_ctx_common_add_line(c, data, n))
				goto err;
			break;
		}
		c->minor_state = MINOR_STATE_INIT;
		n = 0;
		break;
	case MINOR_STATE_CRLF:
		c->minor_state = MINOR_STATE_INIT;
		if (data[0] == ' ' || data[0] == '\t') {
			/* LWS */
			n = 1;
			if (http_parse_ctx_common_add_line(c, data, n))
				goto err;
			break;
		}
		c->line_len -= 2;
		c->line[c->line_len] = '\0';
		n = 0;
		if (http_parse_header_field(pasr, c, dir, c->line, user))
			goto err;
		c->line_len = 0;
		break;
	default:
		abort();
	}

	return n;
err:
	return -1;
}

#define HTTP_DECODE_BUF_SIZE	4096

static int decode_content(http_parser_t *pasr, struct http_parse_ctx_common *c,
		int dir, const unsigned char *data, int len, void *user)
{
	switch (c->ce) {
	case HTTP_CE_NONE:
		call_body_handler(pasr, dir, data, len, user);
		break;
	case HTTP_CE_GZIP:
	case HTTP_CE_DEFLATE: {
		unsigned char buf[HTTP_DECODE_BUF_SIZE];
		z_streamp streamp = c->streamp;

		if (c->ce_end)
			break;
		if (!streamp) {
			c->streamp = calloc(1, sizeof(z_stream));
			if (!c->streamp)
				goto err;
			if (inflateInit2(c->streamp, MAX_WBITS + 32) != Z_OK)
				goto err2;
			streamp = c->streamp;
		}
		streamp->next_in = (unsigned char *)data;
		streamp->avail_in = len;
		do {
			streamp->next_out = buf;
			streamp->avail_out = sizeof(buf);
			switch (inflate(streamp, Z_NO_FLUSH)) {
			case Z_OK:
				break;
			case Z_STREAM_END:
				c->ce_end = 1;
				break;
			default:
				goto err;
				break;
			}
			if (streamp->avail_out != sizeof(buf)) {
				int n = sizeof(buf) - streamp->avail_out;

				call_body_handler(pasr, dir, buf, n, user);
			}
			if (c->ce_end) {
				inflateEnd(c->streamp);
				free(c->streamp);
				c->streamp = NULL;
				break;
			}
		} while (streamp->avail_in > 0);
		break;
	}
	default:
		abort();
	}

	return 0;
err2:
	free(c->streamp);
	c->streamp = NULL;
err:
	return -1;
}

/* return -1 on fatal, and callers should not call it again.
 * return 0 if all the data is consumed or bufferd. */
static int __http_parse(http_parser_t *pasr, struct http_parse_ctx_common *c,
		int dir, const unsigned char *data, int len, void *user)
{
	int n;
	bool end;

	switch (c->state) {
	case HTTP_STATE_START_LINE:
		n = http_get_line(c, &end, data, len, user);
		if (n < 0)
			goto err;
		if (!end)
			break;
		c->state = HTTP_STATE_MSG_HDR;
		if (dir == PKT_DIR_C2S) {
			if (http_parse_request_line(pasr, c->line, user))
				goto err;
		}
		c->line_len = 0;
		break;
	case HTTP_STATE_MSG_HDR:
		n = http_parse_msg_hdr(pasr, c, &end, dir, data, len, user);
		if (n < 0)
			goto err;
		if (!end)
			break;
		if (c->is_chunked) {
			c->state = HTTP_STATE_MSG_CHUNK_SIZE;
			c->line_len = 0;
		} else if (c->body_len == 0) {
			http_parse_ctx_common_reset(c);
			call_msg_end_handler(pasr, dir, user);
		} else {
			c->state = HTTP_STATE_MSG_BODY;
			c->line_len = 0;
		}
		break;
	case HTTP_STATE_MSG_BODY:
		assert(c->body_len > 0);
		n = MIN(len, c->body_len);
		c->body_len -= n;
		if (decode_content(pasr, c, dir, data, n, user))
			goto err;
		if (c->body_len == 0) {
			http_parse_ctx_common_reset(c);
			call_msg_end_handler(pasr, dir, user);
		}
		break;
/*
       Chunked-Body   = *chunk
                        last-chunk
                        trailer
                        CRLF

       chunk          = chunk-size [ chunk-extension ] CRLF
                        chunk-data CRLF
       chunk-size     = 1*HEX
       last-chunk     = 1*("0") [ chunk-extension ] CRLF

       chunk-extension= *( ";" chunk-ext-name [ "=" chunk-ext-val ] )
       chunk-ext-name = token
       chunk-ext-val  = token | quoted-string
       chunk-data     = chunk-size(OCTET)
       trailer        = *(entity-header CRLF)
*/
	case HTTP_STATE_MSG_CHUNK_SIZE:
		n = http_get_line(c, &end, data, len, user);
		if (n < 0)
			goto err;
		if (!end)
			break;
		c->body_len = strtoull(c->line, NULL, 16);
		if (c->body_len > 0)
			c->state = HTTP_STATE_MSG_CHUNK_DATA;
		else
			c->state = HTTP_STATE_MSG_CHUNK_TRAILER;
		c->line_len = 0;
		break;
	case HTTP_STATE_MSG_CHUNK_DATA:
		assert(c->body_len > 0);
		n = MIN(len, c->body_len);
		c->body_len -= n;
		if (decode_content(pasr, c, dir, data, n, user))
			goto err;
		if (c->body_len == 0)
			c->state = HTTP_STATE_MSG_CHUNK_CRLF;
		break;
	case HTTP_STATE_MSG_CHUNK_CRLF:
		n = http_get_line(c, &end, data, len, user);
		if (n < 0)
			goto err;
		if (!end)
			break;
		if (c->line_len != 0)
			goto err;
		c->state = HTTP_STATE_MSG_CHUNK_SIZE;
		break;
	case HTTP_STATE_MSG_CHUNK_TRAILER:
		n = http_parse_msg_hdr(pasr, c, &end, dir, data, len, user);
		if (n < 0)
			goto err;
		if (!end)
			break;
		http_parse_ctx_common_reset(c);
		call_msg_end_handler(pasr, dir, user);
		break;
	default:
		abort();
	}

	return n;
err:
	return -1;
}

int http_parse(http_parser_t *pasr, http_parse_ctx_t *ctx, int dir,
		const unsigned char *data, int len, void *user)
{
	struct http_parse_ctx_common *c;
	int n;

	c = &ctx->common[dir];
	while (len > 0) {
		n = __http_parse(pasr, c, dir, data, len, user);
		if (n < 0)
			return -1;
		data += n;
		len -= n;
	}

	return 0;
}

#ifdef TEST
#include <stdio.h>

void print_body(const unsigned char *data, int len, void *user)
{
	int *poff = user;
	const char *exp = " 1234\n";

	if (!poff) {
		assert(len == 6 && memcmp(data, " 1234\n", 6) == 0);
	} else {
		assert(len == 1 && exp[*poff] == *data);
		*poff += 1;
	}
}

void print_hdr(const char *name, const char *value, void *user)
{
	if (strcasecmp(name, "Host") == 0)
		assert(strcmp(value, "www.test.com") == 0);
	else if (strcasecmp(name, "Test") == 0)
		assert(strcmp(value, "multi\r\n line") == 0);
}

void print_path(const char *method, const char *path, const char *http_version,
		void *user)
{
	assert(strcmp(path, "/test") == 0);
}

int main(void)
{
	const char *req = 
			"GET /test HTTP/1.1\r\n"
			"Host: www.test.com\r\n"
			"Test: multi\r\n"
			" line\r\n"
			"\r\n";
	const char *res =
			"HTTP/1.1 200 OK\r\n"
			"Content-Length: 6\r\n"
			"Connection: close\r\n"
			"\r\n"
			" 1234\n";
	int i;
	http_parser_t *pasr;
	http_parse_ctx_t *c;
	int off = 0;

	pasr = http_parser_alloc();
	assert(pasr);
	http_parser_set_request_line_handler(pasr, print_path);
	http_parser_set_header_field_handler(pasr, PKT_DIR_C2S, print_hdr);
	http_parser_set_body_handler(pasr, PKT_DIR_S2C, print_body);

	c = http_parse_ctx_alloc();
	assert(c);

	assert(http_parse(pasr, c, PKT_DIR_C2S, req, strlen(req), NULL) == 0);
	assert(http_parse(pasr, c, PKT_DIR_S2C, res, strlen(res), NULL) == 0);
	for (i = 0; i < strlen(req); i++)
		assert(http_parse(pasr, c, PKT_DIR_C2S, req + i, 1, NULL) == 0);
	for (i = 0; i < strlen(res); i++)
		assert(http_parse(pasr, c, PKT_DIR_S2C, res + i, 1, &off) == 0);
	http_parser_free(pasr);
	http_parse_ctx_free(c);

	return EXIT_SUCCESS;
}
#endif /* TEST */
