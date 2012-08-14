
#include "http.h"
#include "utils.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct request_line_handler_iter {
	http_request_line_handler		handler;
	struct request_line_handler_iter	*next;
};

struct header_field_handler_iter {
	http_header_field_handler		handler;
	struct header_field_handler_iter	*next;
};

struct body_handler_iter {
	http_body_handler		handler;
	struct body_handler_iter	*next;
};

struct http_inspector {
	struct request_line_handler_iter	*request_line;
	struct header_field_handler_iter	*request_header_field;
	struct body_handler_iter		*response_body;
};

http_inspector_t *http_inspector_alloc(void)
{
	return calloc(1, sizeof(struct http_inspector));
}

void http_inspector_free(http_inspector_t *insp)
{
	struct request_line_handler_iter *rq_line;
	struct header_field_handler_iter *hdr_fild;
	struct body_handler_iter *body;

	while ((rq_line = insp->request_line)) {
		insp->request_line = rq_line->next;
		free(rq_line);
	}

	while ((hdr_fild = insp->request_header_field)) {
		insp->request_header_field = hdr_fild->next;
		free(hdr_fild);
	}

	while ((body = insp->response_body)) {
		insp->response_body = body->next;
		free(body);
	}

	free(insp);
}

int http_inspector_add_request_line_handler(http_inspector_t *insp,
		http_request_line_handler h)
{
	struct request_line_handler_iter *i = malloc(sizeof(*i));

	if (!i)
		return -1;
	i->handler = h;
	i->next = insp->request_line;
	insp->request_line = i;

	return 0;
}

int http_inspector_add_request_header_field_handler(http_inspector_t *insp,
		http_header_field_handler h)
{
	struct header_field_handler_iter *i = malloc(sizeof(*i));

	if (!i)
		return -1;
	i->handler = h;
	i->next = insp->request_header_field;
	insp->request_header_field = i;

	return 0;
}

int http_inspector_add_response_body_handler(http_inspector_t *insp,
		http_body_handler h)
{
	struct body_handler_iter *i = malloc(sizeof(*i));

	if (!i)
		return -1;
	i->handler = h;
	i->next = insp->response_body;
	insp->response_body = i;

	return 0;
}

static void call_request_line_handler(http_inspector_t *insp,
		const char *method, const char *path, const char *http_version,
		void *user)
{
	struct request_line_handler_iter *i;

	for (i = insp->request_line; i; i = i->next)
		i->handler(method, path, http_version, user);
}

static void call_request_header_field_handler(http_inspector_t *insp,
		const char *name, const char *value, void *user)
{
	struct header_field_handler_iter *i;

	for (i = insp->request_header_field; i; i = i->next)
		i->handler(name, value, user);
}

static void call_response_body_handler(http_inspector_t *insp,
		const unsigned char *data, int len, void *user)
{
	struct body_handler_iter *i;

	for (i = insp->response_body; i; i = i->next)
		i->handler(data, len, user);
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
};

#define HTTP_LINE_SIZE	1024

enum {
	MINOR_STATE_INIT,
	MINOR_STATE_CR,
	MINOR_STATE_CRLF,
};

struct http_inspect_ctx_common {
	int			state;
	int			minor_state;
	unsigned long long	body_len;
	int			line_len;
	char			line[HTTP_LINE_SIZE];
};

static void http_inspect_ctx_common_init(struct http_inspect_ctx_common *c)
{
	c->state = HTTP_STATE_START_LINE;
	c->minor_state = MINOR_STATE_INIT;
	c->body_len = 0;
	c->line_len = 0;
}

static int http_inspect_ctx_common_add_line(struct http_inspect_ctx_common *c,
		const unsigned char *str, int len)
{
	if (c->line_len + len >= sizeof(c->line))
		return -1;
	memcpy(c->line + c->line_len, str, len);
	c->line_len += len;
	c->line[c->line_len] = '\0';

	return 0;
}

struct http_inspect_ctx {
	struct http_inspect_ctx_common	clnt;
	struct http_inspect_ctx_common	serv;
};

http_inspect_ctx_t *http_inspect_ctx_alloc(void)
{
	struct http_inspect_ctx *c = malloc(sizeof(*c));

	if (!c)
		return NULL;
	http_inspect_ctx_common_init(&c->clnt);
	http_inspect_ctx_common_init(&c->serv);

	return c;
}

void http_inspect_ctx_free(http_inspect_ctx_t *ctx)
{
	free(ctx);
}

/*
        Request-Line   = Method SP Request-URI SP HTTP-Version CRLF
*/
static int http_parse_request_line(http_inspector_t *insp,
		char *line, void *user)
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

	call_request_line_handler(insp, line, path, ver, user);

	return 0;
err:
	return -1;
}

static int http_handle_state_start_line(http_inspector_t *insp,
		struct http_inspect_ctx_common *c, const unsigned char *data,
		int len, void *user, bool is_client)
{
	int n;
	const unsigned char *ptr;

	switch (c->minor_state) {
	case MINOR_STATE_INIT:
		ptr = memmem(data, len, "\r\n", 2);
		if (ptr) {
			ptr += 2;
			c->state = HTTP_STATE_MSG_HDR;
			n = ptr - data;
			if (http_inspect_ctx_common_add_line(c, data, n - 2))
				goto err;
			if (is_client) {
				if (http_parse_request_line(insp, c->line,
						user))
					goto err;
			}
			c->line_len = 0;
			break;
		}
		if (data[len - 1] == '\r')
			c->minor_state = MINOR_STATE_CR;
		n = len;
		if (http_inspect_ctx_common_add_line(c, data, n))
			goto err;
		break;
	case MINOR_STATE_CR:
		c->minor_state = MINOR_STATE_INIT;
		if (data[0] == '\n') {
			c->state = HTTP_STATE_MSG_HDR;
			n = 1;
			c->line[--c->line_len] = '\0';
			if (is_client) {
				if (http_parse_request_line(insp, c->line,
						user))
					goto err;
			}
			c->line_len = 0;
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
static int http_parse_header_field(http_inspector_t *insp,
		struct http_inspect_ctx_common *c, char *hdr, void *user,
		bool is_client)
{
	char *fv = strchr(hdr, ':');

	if (!fv)
		return -1;
	*fv++ = '\0';
	while (*fv == ' ' || *fv == '\t')
		fv++;

	if (strcasecmp(hdr, "Content-Length") == 0)
		c->body_len = strtoull(fv, NULL, 0);

	if (is_client)
		call_request_header_field_handler(insp, hdr, fv, user);

	return 0;
}

static int http_handle_state_msg_hdr(http_inspector_t *insp,
		struct http_inspect_ctx_common *c, const unsigned char *data,
		int len, void *user, bool is_client)
{
	int n;
	const unsigned char *ptr;

	switch (c->minor_state) {
	case MINOR_STATE_INIT:
		ptr = memmem(data, len, "\r\n", 2);
		if (ptr) {
			ptr += 2;
			n = ptr - data;
			if (n + c->line_len == 2) {
header_body_delimiter:
				if (is_client) {
					call_request_header_field_handler(insp,
						NULL, NULL, user);
				}
				if (c->body_len == 0) {
					http_inspect_ctx_common_init(c);
					if (!is_client) {
						call_response_body_handler(insp,
							NULL, 0, user);
					}
				} else {
					c->state = HTTP_STATE_MSG_BODY;
					c->line_len = 0;
				}
				break;
			}
			if (ptr == data + len) {
				if (http_inspect_ctx_common_add_line(c, data,
								     n))
					goto err;
				c->minor_state = MINOR_STATE_CRLF;
				break;
			}
			if (*ptr == ' ' || *ptr == '\t') {
				/* LWS */
				n++;
				if (http_inspect_ctx_common_add_line(c, data,
								     n))
					goto err;
				break;
			}
			if (http_inspect_ctx_common_add_line(c, data, n - 2))
				goto err;
			if (http_parse_header_field(insp, c, c->line,
					user, is_client))
				goto err;
			c->line_len = 0;
			break;
		}
		if (data[len - 1] == '\r')
			c->minor_state = MINOR_STATE_CR;
		n = len;
		if (http_inspect_ctx_common_add_line(c, data, n))
			goto err;
		break;
	case MINOR_STATE_CR:
		if (data[0] == '\n') {
			if (c->line_len == 1) {
				n = 1;
				c->minor_state = MINOR_STATE_INIT;
				goto header_body_delimiter;
			}
			c->minor_state = MINOR_STATE_CRLF;
			n = 1;
			if (http_inspect_ctx_common_add_line(c, data, n))
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
			if (http_inspect_ctx_common_add_line(c, data, n))
				goto err;
			break;
		}
		c->line_len -= 2;
		c->line[c->line_len] = '\0';
		n = 0;
		if (http_parse_header_field(insp, c, c->line, user, is_client))
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

/* return -1 on fatal, and callers should not call it again.
 * return 0 if all the data is consumed or bufferd. */
static int __http_inspect_x_data(http_inspector_t *insp,
		struct http_inspect_ctx_common *c, const unsigned char *data,
		int len, void *user, bool is_client)
{
	int n;

	switch (c->state) {
	case HTTP_STATE_START_LINE:
		n = http_handle_state_start_line(insp, c, data, len, user,
				is_client);
		if (n < 0)
			goto err;
		break;
	case HTTP_STATE_MSG_HDR:
		n = http_handle_state_msg_hdr(insp, c, data, len, user,
				is_client);
		if (n < 0)
			goto err;
		break;
	case HTTP_STATE_MSG_BODY:
		assert(c->body_len > 0);
		n = MIN(len, c->body_len);
		c->body_len -= n;
		if (!is_client)
			call_response_body_handler(insp, data, len, user);
		if (c->body_len == 0) {
			if (!is_client)
				call_response_body_handler(insp, NULL, 0, user);
			http_inspect_ctx_common_init(c);
		}
		break;
	default:
		abort();
	}

	return n;
err:
	return -1;
}

static int http_inspect_x_data(http_inspector_t *insp,
		http_inspect_ctx_t *ctx, const unsigned char *data, int len,
		void *user, bool is_client)
{
	struct http_inspect_ctx_common *c;
	int n;

	c = is_client ? &ctx->clnt : &ctx->serv;
	while (len > 0) {
		n = __http_inspect_x_data(insp, c, data, len, user,
					  is_client);
		if (n < 0)
			return -1;
		data += n;
		len -= n;
	}

	return 0;
}

/*
       HTTP-Version   = "HTTP" "/" 1*DIGIT "." 1*DIGIT
       DIGIT          = <any US-ASCII digit "0".."9">
*/
int http_inspect_client_data(http_inspector_t *insp, http_inspect_ctx_t *ctx,
		const unsigned char *data, int len, void *user)
{
	return http_inspect_x_data(insp, ctx, data, len, user, 1);
}

/*
       Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
*/
int http_inspect_server_data(http_inspector_t *insp, http_inspect_ctx_t *ctx,
		const unsigned char *data, int len, void *user)
{
	return http_inspect_x_data(insp, ctx, data, len, user, 0);
}

#ifdef TEST
#include <stdio.h>

void print_body(const unsigned char *data, int len, void *user)
{
	if (data) {
		int *poff = user;
		const char *exp = " 1234\n";

		if (!poff) {
			assert(len == 6 && memcmp(data, " 1234\n", 6) == 0);
		} else {
			assert(len == 1 && exp[*poff] == *data);
			*poff += 1;
		}
	}
}

void print_hdr(const char *name, const char *value, void *user)
{
	if (name) {
		if (strcasecmp(name, "Host") == 0)
			assert(strcmp(value, "www.test.com") == 0);
		else if (strcasecmp(name, "Test") == 0)
			assert(strcmp(value, "multi\r\n line") == 0);
	}
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
	http_inspector_t *insp;
	http_inspect_ctx_t *c;
	int off = 0;

	insp = http_inspector_alloc();
	assert(insp);
	assert(http_inspector_add_request_line_handler(insp, print_path) == 0);
	assert(http_inspector_add_request_header_field_handler(insp,
			print_hdr) == 0);
	assert(http_inspector_add_response_body_handler(insp, print_body) == 0);

	c = http_inspect_ctx_alloc();
	assert(c);

	assert(http_inspect_client_data(insp, c, req, strlen(req), NULL) == 0);
	assert(http_inspect_server_data(insp, c, res, strlen(res), NULL) == 0);
	for (i = 0; i < strlen(req); i++) {
		assert(http_inspect_client_data(insp, c, req + i, 1,
				NULL) == 0);
	}
	for (i = 0; i < strlen(res); i++) {
		assert(http_inspect_server_data(insp, c, res + i, 1,
				&off) == 0);
	}
	http_inspector_free(insp);
	http_inspect_ctx_free(c);

	return EXIT_SUCCESS;
}
#endif /* TEST */