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
#include "ctab.h"
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <zlib.h>
#include <stdio.h>
#include <inttypes.h>

struct http_stat g_http_stat = { 0 };

void http_stat_show(void)
{
	printf("http overflowed line: %" PRIu64 "\n",
	       g_http_stat.overflowed_line);
	printf("http malformed start line: %" PRIu64 "\n",
	       g_http_stat.malformed_start_line);
	printf("http malformed request-line: %" PRIu64 "\n",
	       g_http_stat.malformed_request_line);
	printf("http malformed status-line: %" PRIu64 "\n",
	       g_http_stat.malformed_status_line);
	printf("http malformed header: %" PRIu64 "\n",
	       g_http_stat.malformed_header);
	printf("http malformed content-encoding: %" PRIu64 "\n",
	       g_http_stat.malformed_content_encoding);
	printf("http malformed chunk-size: %" PRIu64 "\n",
	       g_http_stat.malformed_chunk_size);
	printf("http malformed chunk-data: %" PRIu64 "\n",
	       g_http_stat.malformed_chunk_data);
	printf("http malformed trailer: %" PRIu64 "\n",
	       g_http_stat.malformed_trailer);
	printf("http good: %" PRIu64 "\n", g_http_stat.good);
}

struct http_parser {
	http_request_line_handler	request_line;
	http_status_line_handler	status_line;
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

void http_parser_set_status_line_handler(http_parser_t *pasr,
		http_status_line_handler h)
{
	pasr->status_line = h;
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

static void call_request_line_handler(http_parser_t *pasr, const char *method,
		const char *path, int minor_ver, void *user)
{
	if (pasr->request_line)
		pasr->request_line(method, path, minor_ver, user);
}

static void call_status_line_handler(http_parser_t *pasr, int minor_ver,
		int status_code, const char *reason_phase, void *user)
{
	if (pasr->status_line)
		pasr->status_line(minor_ver, status_code, reason_phase, user);
}

static void call_header_field_handler(http_parser_t *pasr, int dir,
		const char *name, int name_len, const char *value,
		int value_len, void *user)
{
	if (pasr->header_field[dir])
		pasr->header_field[dir](name, name_len, value, value_len, user);
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
	MINOR_STATE_LF,
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
	g_http_stat.good++;
	http_parse_ctx_common_init(c);
}

static int http_parse_ctx_common_add_line(struct http_parse_ctx_common *c,
		const unsigned char *str, int len)
{
	if (c->line_len + len >= sizeof(c->line)) {
		g_http_stat.overflowed_line++;
		return -1;
	}
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

static int http_parse_version(char *ver, char **end)
{
	int minor_ver;

	if (strncasecmp(ver, "HTTP", 4) != 0)
		goto err;
	ver = __skip_space(ver + 4);
	if (*ver != '/')
		goto err;
	ver = __skip_space(ver + 1);
	if (!is_digit(*ver) || atoi(ver) != 1)
		goto err;
	ver = __skip_space(__skip_digit(ver + 1));
	if (*ver != '.')
		goto err;
	ver = __skip_space(ver + 1);
	if (!is_digit(*ver))
		goto err;
	minor_ver = atoi(ver);
	*end = __skip_digit(ver + 1);

	return minor_ver;
err:
	return -1;
}

/**
 * Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
 * HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
 * DIGIT          = <any US-ASCII digit "0".."9">
 */
static int http_parse_request_line(http_parser_t *pasr, char *line, void *user)
{
	char *path, *ver;
	int minor_ver, len = __token_len(line);

	if (len == 0)
		goto err;
	path = line + len;
	if (!is_space(*path))
		goto err;
	*path++ = '\0';

	path = __skip_space(path);
	ver = path;
	do {
		if (*ver == '\0')
			goto err;
		ver++;
	} while (!is_space(*ver));
	*ver++ = '\0';

	minor_ver = http_parse_version(__skip_space(ver), &ver);
	if (minor_ver < 0)
		goto err;
	if (*__skip_space(ver) != '\0')
		goto err;

	call_request_line_handler(pasr, line, path, minor_ver, user);

	return 0;
err:
	return -1;
}

/* Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF */
static int http_parse_status_line(http_parser_t *pasr, char *line, void *user)
{
	int status_code, minor_ver = http_parse_version(line, &line);

	if (minor_ver < 0)
		goto err;
	if (!is_space(*line))
		goto err;
	line = __skip_space(line + 1);
	if (!is_digit(*line))
		goto err;
	status_code = atoi(line);
	line = __skip_space(__skip_digit(line + 1));

	call_status_line_handler(pasr, minor_ver, status_code, line, user);

	return 0;
err:
	return -1;
}

static int http_get_line(struct http_parse_ctx_common *c,
		bool *end, const unsigned char *data, int len)
{
	int n;
	const unsigned char *ptr;

	*end = false;
	ptr = memchr(data, '\n', len);
	if (ptr) {
		n = ptr - data;
		if (http_parse_ctx_common_add_line(c, data, n))
			goto err;
		if (c->line_len > 0 && c->line[c->line_len - 1] == '\r')
			c->line[--c->line_len] = '\0';
		n++;
		*end = true;
	} else {
		n = len;
		if (http_parse_ctx_common_add_line(c, data, n))
			goto err;
	}

	return n;
err:
	return -1;
}

/*
 * Transfer-Encoding       = "Transfer-Encoding" ":" 1#transfer-coding
 * transfer-coding         = "chunked" | transfer-extension
 * transfer-extension      = token *( ";" parameter )
 * All transfer-coding values are case-insensitive
 */
static int http_parse_transfer_encoding(struct http_parse_ctx_common *c,
		const char *fv, int fv_len)
{
	const char *tok;

	tok = fv;
	while (1) {
		int len = __token_len(tok);

		if (len == 7 && strncasecmp_c(tok, "chunked") == 0)
			c->is_chunked = 1;
		else if (len > 0)
			c->is_chunked = 0;
		tok = __skip_lws(tok + len);
		if (*tok == '\0') {
			break;
		} else if (*tok == ',') {
			tok = __skip_lws(++tok);
		} else if (*tok == ';') {
next_attr:
			tok = __skip_lws(++tok);
			len = __token_len(tok);
			if (len == 0)
				goto err;
			tok = __skip_lws(tok + len);
			if (*tok != '=')
				goto err;
			tok = __skip_lws(++tok);
			if (*tok == '"')
				len = get_quoted_str_len(tok,
						fv_len - (tok - fv));
			else
				len = __token_len(tok);
			if (len == 0)
				goto err;
			tok = __skip_lws(tok + len);
			if (*tok == '\0')
				break;
			else if (*tok == ',')
				tok = __skip_lws(++tok);
			else if (*tok == ';')
				goto next_attr;
			else
				goto err;
		} else {
			goto err;
		}
	}

	return 0;
err:
	return -1;
}

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
static int http_parse_content_encoding(struct http_parse_ctx_common *c,
		const char *fv)
{
	const char *tok;

	if (c->streamp) {
		inflateEnd(c->streamp);
		free(c->streamp);
		c->streamp = NULL;
	}

	tok = fv;
	while (1) {
		int len = __token_len(tok);

		if ((len == 4 && strncasecmp_c(tok, "gzip") == 0) ||
		    (len == 6 && strncasecmp_c(tok, "x-gzip") == 0))
			c->ce = HTTP_CE_GZIP;
		else if (len == 7 && strncasecmp_c(tok, "deflate") == 0)
			c->ce = HTTP_CE_DEFLATE;
		else if (len > 0)
			c->ce = HTTP_CE_NONE;
		tok = __skip_lws(tok + len);
		if (*tok == '\0')
			break;
		else if (*tok == ',')
			tok = __skip_lws(++tok);
		else
			goto err;
	}

	return 0;
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
       OCTET          = <any 8-bit sequence of data>
       <">            = <US-ASCII double-quote mark (34)>
*/
static int http_parse_header_field(http_parser_t *pasr,
		struct http_parse_ctx_common *c, int dir, char *hdr,
		int hdr_len, void *user)
{
	char *fv;
	int fn_len, fv_len;

	fn_len = __token_len(hdr);
	if (fn_len == 0)
		goto err;

	fv = __skip_lws(hdr + fn_len);
	if (*fv != ':')
		goto err;
	hdr[fn_len] = '\0';
	fv = __skip_lws(++fv);
	fv_len = hdr_len - (fv - hdr);
	while (fv_len > 0 && is_lws(fv[fv_len - 1]))
		fv[--fv_len] = '\0';

	if (fn_len == 14 && strcasecmp(hdr, "Content-Length") == 0) {
		c->body_len = strtoull(fv, NULL, 0);
	} else if (fn_len == 17 && strcasecmp(hdr, "Transfer-Encoding") == 0) {
		if (http_parse_transfer_encoding(c, fv, fv_len))
			goto err;
	} else if (fn_len == 16 && strcasecmp(hdr, "Content-Encoding") == 0) {
		if (http_parse_content_encoding(c, fv))
			goto err;
	}

	call_header_field_handler(pasr, dir, hdr, fn_len, fv, fv_len, user);

	return 0;
err:
	return -1;
}

static int http_parse_msg_hdr(http_parser_t *pasr,
		struct http_parse_ctx_common *c, bool *end, int dir,
		const unsigned char *data, int len, void *user)
{
	int n;
	bool eol; /* end of line */

	*end = false;
	switch (c->minor_state) {
	case MINOR_STATE_INIT:
		n = http_get_line(c, &eol, data, len);
		if (!eol)
			break;
		if (c->line_len == 0) {
			*end = true;
			break;
		}
		c->minor_state = MINOR_STATE_LF;
		break;
	case MINOR_STATE_LF:
		c->minor_state = MINOR_STATE_INIT;
		if (is_lws(data[0])) {
			/* LWS */
			n = 1;
			if (http_parse_ctx_common_add_line(c, data, n))
				goto err;
			break;
		}
		n = 0;
		if (http_parse_header_field(pasr, c, dir, c->line,
				c->line_len, user))
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
			int r;

			c->streamp = calloc(1, sizeof(z_stream));
			if (!c->streamp)
				goto err;
			if (c->ce == HTTP_CE_DEFLATE) {
				/**
				 * Some servers return files without zlib
				 * headers, we detect it with the first byte.
				 * The least-significant 4 bits in zlib header
				 * for deflate algorithm is a fixed value 8,
				 * and for raw deflate, it means non-final
				 * non-compressed block. As the other bits
				 * except for the least-significant 3 bits in
				 * this byte are ignored, they should be
				 * cleared, then the least-significant 4 bits
				 * should not be 8.
				 *
				 * See RFC1950 and RFC1951 for more details.
				 */
				if (((*data) & 0x0f) == 8)
					r = inflateInit(c->streamp);
				else
					r = inflateInit2(c->streamp,
							-MAX_WBITS);
			} else {
				r = inflateInit2(c->streamp, MAX_WBITS + 16);
			}
			if (r != Z_OK)
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
		n = http_get_line(c, &end, data, len);
		if (!end) {
			if (n < 0)
				g_http_stat.malformed_start_line++;
			break;
		}
		/* ignore empty lines before start lines */
		if (__space_len(c->line) == c->line_len) {
			c->line_len = 0;
			break;
		}
		c->state = HTTP_STATE_MSG_HDR;
		if (dir == PKT_DIR_C2S) {
			if (http_parse_request_line(pasr, c->line, user)) {
				g_http_stat.malformed_request_line++;
				goto err;
			}
		} else {
			if (http_parse_status_line(pasr, c->line, user)) {
				g_http_stat.malformed_status_line++;
				goto err;
			}
		}
		c->line_len = 0;
		break;
	case HTTP_STATE_MSG_HDR:
		n = http_parse_msg_hdr(pasr, c, &end, dir, data, len, user);
		if (!end) {
			if (n < 0)
				g_http_stat.malformed_header++;
			break;
		}
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
		if (decode_content(pasr, c, dir, data, n, user)) {
			g_http_stat.malformed_content_encoding++;
			goto err;
		}
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
		n = http_get_line(c, &end, data, len);
		if (!end) {
			if (n < 0)
				g_http_stat.malformed_chunk_size++;
			break;
		}
		c->body_len = strtoull(__skip_lws(c->line), NULL, 16);
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
		if (decode_content(pasr, c, dir, data, n, user)) {
			g_http_stat.malformed_content_encoding++;
			goto err;
		}
		if (c->body_len == 0)
			c->state = HTTP_STATE_MSG_CHUNK_CRLF;
		break;
	case HTTP_STATE_MSG_CHUNK_CRLF:
		n = http_get_line(c, &end, data, len);
		if (!end) {
			if (n < 0)
				g_http_stat.malformed_chunk_data++;
			break;
		}
		if (c->line_len != 0) {
			g_http_stat.malformed_chunk_data++;
			goto err;
		}
		c->state = HTTP_STATE_MSG_CHUNK_SIZE;
		break;
	case HTTP_STATE_MSG_CHUNK_TRAILER:
		n = http_parse_msg_hdr(pasr, c, &end, dir, data, len, user);
		if (!end) {
			if (n < 0)
				g_http_stat.malformed_trailer++;
			break;
		}
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

void print_hdr(const char *name, int name_len, const char *value,
		int value_len, void *user)
{
	if (strcasecmp(name, "Host") == 0)
		assert(strcmp(value, "www.test.com") == 0);
	else if (strcasecmp(name, "Test") == 0)
		assert(strcmp(value, "multi line") == 0);
}

void print_path(const char *method, const char *path, int minor_ver,
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
