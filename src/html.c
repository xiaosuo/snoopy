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

#include "html.h"
#include "utils.h"
#include "ctab.h"
#include <assert.h>
#include <iconv.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>

/* See: http://www.w3.org/MarkUp/html-spec/html-spec_toc.html */

/**
 * The length of a name is limited to 72 characters by the `NAMELEN' parameter
 * in the SGML declaration for HTML, section SGML Declaration for HTML.
 */
#define HTML_NAME_SIZE (72 + 1)

/**
 * The `NAMELEN' parameter in the SGML declaration (section SGML Declaration
 * for HTML) limits the length of an attribute value to 1024 characters. 
 */
#define HTML_ATTR_VAL_SIZE (1024 + 1)

struct html_stat g_html_stat = { 0 };

void html_stat_show(void)
{
	printf("html malformed: %" PRIu64 "\n", g_html_stat.malformed);
	printf("html unknown encoding: %" PRIu64 "\n",
	       g_html_stat.unknown_encoding);
	printf("html no encoding: %" PRIu64 "\n", g_html_stat.no_encoding);
	printf("html good: %" PRIu64 "\n", g_html_stat.good);
}

/* See http://www.w3.org/TR/html5/tokenization.html */

enum html_state {
	HTML_STATE_DATA,
	HTML_STATE_TAG_OPEN,		/* < */
	HTML_STATE_TAG_NAME,		/* <[a-z][A-Z] */
	HTML_STATE_BFOR_ATTR_NAME,
	HTML_STATE_ATTR_NAME,
	HTML_STATE_AFTR_ATTR_NAME,
	HTML_STATE_BFOR_ATTR_VAL,
	HTML_STATE_ATTR_VAL_UQ,
	HTML_STATE_ATTR_VAL_SQ,
	HTML_STATE_ATTR_VAL_DQ,
	HTML_STATE_SELF_CLS_START_TAG,
	HTML_STATE_END_TAG_OPEN,	/* </ */
	HTML_STATE_PI,			/* <? */
	HTML_STATE_DECL_OPEN,		/* <! */
	HTML_STATE_MARKD_SEC,		/* <![ */
	HTML_STATE_MARKD_SEC_BRAC,
	HTML_STATE_MARKD_SEC_BRAC2,
	HTML_STATE_CMNT_SUSP,		/* <!- */
	HTML_STATE_CMNT,		/* <!-- */
	HTML_STATE_BOGUS_CMNT,
	HTML_STATE_CMNT_DASH,
	HTML_STATE_CMNT_END,
	HTML_STATE_CDATA,
	HTML_STATE_CDATA_TAG_OPEN,
	HTML_STATE_CDATA_END_TAG_OPEN,
	HTML_STATE_CDATA_END_TAG_NAME,
	HTML_STATE_CDATA_END_TAG_CLS,
};

/**
 * The max length of one UTF-8 char is 6, and we round it up to the nearest
 * 2^3 = 8 here.
 */
#define HTML_IN_BUF_SIZE 8

struct html_parse_ctx {
	enum html_state	state;
	char		tag_name[HTML_NAME_SIZE];	/* case insensitive */
	char		attr_name[HTML_NAME_SIZE];	/* case insensitive */
	char		attr_val[HTML_ATTR_VAL_SIZE];
	char		cdata_elem[sizeof("script")];
	bool		got_space;
	char		charset[HTML_CHARSET_SIZE];
	iconv_t		cd;
	unsigned char	in_buf[HTML_IN_BUF_SIZE];
	size_t		in_buf_len;
	bool		is_utf8;
	bool		failed_to_parse;
};

static void html_set_charset(html_parse_ctx_t *ctx, const char *charset,
		int len)
{
	strlncpy(ctx->charset, sizeof(ctx->charset), charset, len);
	strtolower(ctx->charset);
	if (strcmp(ctx->charset, "utf-8") == 0 ||
	    strcmp(ctx->charset, "utf8") == 0) {
		ctx->is_utf8 = true;
		ctx->charset[0] = '\0';
	}
	if (ctx->cd != (iconv_t)-1) {
		iconv_close(ctx->cd);
		ctx->cd = (iconv_t)-1;
	}
	ctx->in_buf_len = 0;
}

html_parse_ctx_t *html_parse_ctx_alloc(const char *charset)
{
	html_parse_ctx_t *ctx = malloc(sizeof(*ctx));

	if (!ctx)
		goto err;
	ctx->state = HTML_STATE_DATA;
	ctx->tag_name[0] = '\0';
	ctx->attr_name[0] = '\0';
	ctx->attr_val[0] = '\0';
	ctx->cdata_elem[0] = '\0';
	ctx->got_space = false;
	if (!charset)
		charset = "";
	ctx->cd = (iconv_t)-1;
	html_set_charset(ctx, charset, strlen(charset));
	if (charset[0] == '\0')
		ctx->is_utf8 = false;
	ctx->failed_to_parse = false;
err:
	return ctx;
}

void html_parse_ctx_free(html_parse_ctx_t *ctx)
{
	if (ctx->cd != (iconv_t)-1)
		iconv_close(ctx->cd);
	if (!ctx->failed_to_parse) {
		if (ctx->charset == '\0' && !ctx->is_utf8)
			g_html_stat.no_encoding++;
		else
			g_html_stat.good++;
	}
	free(ctx);
}

static void html_cdata_start(html_parse_ctx_t *ctx)
{
	if (strcasecmp(ctx->tag_name, "script") == 0 ||
	    strcasecmp(ctx->tag_name, "style") == 0) {
		ctx->state = HTML_STATE_CDATA;
		strcpy(ctx->cdata_elem, ctx->tag_name);
	} else {
		ctx->state = HTML_STATE_DATA;
	}
}

static void html_cdata_end(html_parse_ctx_t *ctx)
{
	if (strcasecmp(ctx->tag_name, ctx->cdata_elem) == 0)
		ctx->state = HTML_STATE_DATA;
	else
		ctx->state = HTML_STATE_CDATA;
}

/* i.e. <?xml version="1.0" encoding="utf-8"?> */
static void html_parse_pi(html_parse_ctx_t *ctx)
{
	char *ptr = strstr(ctx->attr_val, "encoding");
	char *enc;

	if (!ptr)
		goto err;
	ptr = __skip_space(ptr + 8);
	if (*ptr != '=')
		goto err;
	ptr = __skip_space(ptr + 1);
	if (*ptr != '"')
		goto err;
	enc = ptr + 1;
	ptr = strchr(enc, '"');
	if (!ptr)
		goto err;
	if (ptr == enc)
		goto err;
	html_set_charset(ctx, enc, ptr - enc);
err:
	return;
}

/* i.e. <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/> */
static void html_handle_attr(html_parse_ctx_t *ctx)
{
	char *ptr;

	if (strcasecmp(ctx->tag_name, "meta") != 0)
		goto err;
	if (strcasecmp(ctx->attr_name, "content") != 0)
		goto err;
	ptr = strcasestr(ctx->attr_val, "charset");
	if (!ptr)
		goto err;
	ptr = __skip_space(ptr + 7);
	if (*ptr != '=')
		goto err;
	ptr = __skip_space(ptr + 1);
	if (*ptr == '"') {
		char *enc;

		enc = ptr + 1;
		ptr = strchr(enc, '"');
		if (!ptr)
			goto err;
		if (ptr == enc)
			goto err;
		html_set_charset(ctx, enc, ptr - enc);
	} else {
		int len = __token_len(ptr);

		if (len == 0)
			goto err;
		html_set_charset(ctx, ptr, len);
	}
err:
	return;
}

static int html_handle_data(html_parse_ctx_t *ctx, const unsigned char *data,
		int len, html_data_handler h, void *user)
{
	if (ctx->charset[0] == '\0') {
		h(data, len, user);
		goto out;
	}
	if (ctx->cd == (iconv_t)-1 &&
	    (ctx->cd = iconv_open("UTF-8//IGNORE",
				  ctx->charset)) == (iconv_t)-1)
		goto err;
	if (ctx->in_buf_len > 0) {
		unsigned char outbuf[HTML_IN_BUF_SIZE * 2];
		char *inptr, *outptr;
		size_t inbytesleft, outbytesleft, retval;
		size_t copied = sizeof(ctx->in_buf) - ctx->in_buf_len;
		int error;

		if (copied > len)
			copied = len;
		memcpy(ctx->in_buf + ctx->in_buf_len, data, copied);
		ctx->in_buf_len += copied;
		data += copied;
		len -= copied;

		inptr = (char *)(ctx->in_buf);
		inbytesleft = ctx->in_buf_len;
		outptr = (char *)outbuf;
		outbytesleft = sizeof(outbuf);
		retval = iconv(ctx->cd, &inptr, &inbytesleft, &outptr,
			       &outbytesleft);
		error = errno;
		if (outbytesleft != sizeof(outbuf))
			h(outbuf, sizeof(outbuf) - outbytesleft, user);
		if (inptr == (char *)ctx->in_buf) {
			assert(retval == (size_t)-1);
			switch (error) {
			case EINVAL:
				/* So long multibyte char? */
				if (ctx->in_buf_len == sizeof(ctx->in_buf))
					goto err;
				break;
			case E2BIG: /* I don't think so */
			case EILSEQ:
			default:
				goto err;
				break;
			}
		} else {
			assert(inbytesleft < copied);
			data -= inbytesleft;
			len += inbytesleft;
			ctx->in_buf_len = 0;
		}

		if (len == 0)
			goto out;
	}

	while (1) {
		unsigned char outbuf[2048];
		char *inptr, *outptr;
		size_t inbytesleft, outbytesleft, retval;
		int error;

		inptr = (char *)data;
		inbytesleft = len;
		outptr = (char *)outbuf;
		outbytesleft = sizeof(outbuf);
		retval = iconv(ctx->cd, &inptr, &inbytesleft, &outptr,
			       &outbytesleft);
		error = errno;
		if (outbytesleft != sizeof(outbuf))
			h(outbuf, sizeof(outbuf) - outbytesleft, user);
		data += (len - inbytesleft);
		len = inbytesleft;
		if (len == 0)
			break;
		assert(retval == (size_t)-1);
		switch (error) {
		case EINVAL:
			/* So long multibyte char? */
			if (len >= sizeof(ctx->in_buf))
				goto err;
			memcpy(ctx->in_buf, data, len);
			ctx->in_buf_len = len;
			goto out;
			break;
		case E2BIG:
			break;
		case EILSEQ:
		default:
			goto err;
			break;
		}
	}
out:
	return 0;
err:
	g_html_stat.unknown_encoding++;

	return -1;
}

static int __html_parse(html_parse_ctx_t *ctx, const unsigned char *data,
		int len, html_data_handler h, void *user)
{
	const unsigned char *ptr;
	int n;

	switch (ctx->state) {
	case HTML_STATE_DATA:
		ptr = memchr(data, '<', len);
		if (!ptr) {
			if (html_handle_data(ctx, data, len, h, user))
				n = -1;
			else
				n = len;
			break;
		}
		ctx->state = HTML_STATE_TAG_OPEN;
		if (ptr != data &&
		    html_handle_data(ctx, data, ptr - data, h, user))
			n = -1;
		else
			n = ptr - data + 1;
		break;
	case HTML_STATE_TAG_OPEN: /* < */
		n = 1;
		if (is_alpha(*data)) { /* <[a-zA-Z] */
			ctx->state = HTML_STATE_TAG_NAME;
			strlncpy(ctx->tag_name, sizeof(ctx->tag_name),
				 (const char *)data, 1);
			break;
		}
		switch (*data) {
		case '/': /* </ */
			ctx->state = HTML_STATE_END_TAG_OPEN;
			break;
		case '!': /* <! */
			ctx->state = HTML_STATE_DECL_OPEN;
			break;
		case '?': /* <? */
			ctx->state = HTML_STATE_PI;
			ctx->attr_val[0] = '\0';
			break;
		default:
			ctx->state = HTML_STATE_DATA;
			if (html_handle_data(ctx, (const unsigned char *)"<", 1,
					h, user))
				n = -1;
			else
				n = 0;
			break;
		}
		break;
	case HTML_STATE_TAG_NAME: /* <[a-zA-Z] */
		n = tag_name_len((const char *)data, len);
		if (n > 0)
			strlncat(ctx->tag_name, sizeof(ctx->tag_name),
				 (const char *)data, n);
		if (n == len)
			break;
		switch (data[n++]) {
		case '/':
			ctx->state = HTML_STATE_SELF_CLS_START_TAG;
			break;
		case '>':
			html_cdata_start(ctx);
			break;
		default:
			if (is_space(data[n - 1]))
				ctx->state = HTML_STATE_BFOR_ATTR_NAME;
			else
				goto malformed;
			break;
		}
		break;
	case HTML_STATE_BFOR_ATTR_NAME: /* <TAG_NAME */
		n = 1;
		if (is_attr_name(*data)) {
			ctx->state = HTML_STATE_ATTR_NAME;
			strlncpy(ctx->attr_name, sizeof(ctx->attr_name),
				 (const char *)data, 1);
			break;
		}
		switch (*data) {
		case '/':
			ctx->state = HTML_STATE_SELF_CLS_START_TAG;
			break;
		case '>':
			html_cdata_start(ctx);
			break;
		default:
			if (is_space(*data))
				break;
			else
				goto malformed;
			break;
		}
		break;
	case HTML_STATE_ATTR_NAME:
		n = attr_name_len((const char *)data, len);
		if (n > 0)
			strlncat(ctx->attr_name, sizeof(ctx->attr_name),
				 (const char *)data, n);
		if (n == len)
			break;
		switch (data[n++]) {
		case '/':
			ctx->state = HTML_STATE_SELF_CLS_START_TAG;
			break;
		case '=':
			ctx->state = HTML_STATE_BFOR_ATTR_VAL;
			break;
		case '>':
			html_cdata_start(ctx);
			break;
		default:
			if (is_space(data[n - 1]))
				ctx->state = HTML_STATE_AFTR_ATTR_NAME;
			else
				goto malformed;
			break;
		}
		break;
	case HTML_STATE_AFTR_ATTR_NAME:
		n = 1;
		if (is_attr_name(*data)) {
			ctx->state = HTML_STATE_ATTR_NAME;
			strlncpy(ctx->attr_name, sizeof(ctx->attr_name),
				 (const char *)data, 1);
			break;
		}
		switch (*data) {
		case '/':
			ctx->state = HTML_STATE_SELF_CLS_START_TAG;
			break;
		case '=':
			ctx->state = HTML_STATE_BFOR_ATTR_VAL;
			break;
		case '>':
			html_cdata_start(ctx);
			break;
		default:
			if (!is_space(*data))
				goto malformed;
			break;
		}
		break;
	case HTML_STATE_BFOR_ATTR_VAL:
		n = 1;
		switch (*data) {
		case '"':
			ctx->state = HTML_STATE_ATTR_VAL_DQ;
			ctx->attr_val[0] = '\0';
			break;
		case '\'':
			ctx->state = HTML_STATE_ATTR_VAL_SQ;
			ctx->attr_val[0] = '\0';
			break;
		default:
			if (is_attr_val(*data)) {
				ctx->state = HTML_STATE_ATTR_VAL_UQ;
				strlncpy(ctx->attr_val, sizeof(ctx->attr_val),
					 (const char *)data, 1);
				break;
			}
			if (!is_space(*data))
				goto malformed;
			break;
		}
		break;
	case HTML_STATE_ATTR_VAL_UQ:
		n = attr_val_len((const char *)data, len);
		if (n > 0)
			strlncat(ctx->attr_val, sizeof(ctx->attr_val),
				 (const char *)data, n);
		if (n == len)
			break;
		switch (data[n++]) {
		case '>':
			html_handle_attr(ctx);
			html_cdata_start(ctx);
			break;
		default:
			if (is_space(data[n - 1])) {
				html_handle_attr(ctx);
				ctx->state = HTML_STATE_BFOR_ATTR_NAME;
			} else {
				goto malformed;
			}
			break;
		}
		break;
	case HTML_STATE_ATTR_VAL_SQ:
		ptr = memchr(data, '\'', len);
attr_val_xq:
		if (!ptr) {
			n = len;
			strlncat(ctx->attr_val, sizeof(ctx->attr_val),
				 (const char *)data, n);
			break;
		}
		ctx->state = HTML_STATE_BFOR_ATTR_NAME;
		if (ptr != data)
			strlncat(ctx->attr_val, sizeof(ctx->attr_val),
				 (const char *)data, ptr - data);
		html_handle_attr(ctx);
		n = ptr - data + 1;
		break;
	case HTML_STATE_ATTR_VAL_DQ:
		ptr = memchr(data, '"', len);
		goto attr_val_xq;
		break;
	case HTML_STATE_SELF_CLS_START_TAG: /* <[a-z][A-Z].../ */
		if (*data == '>') {
			ctx->state = HTML_STATE_DATA;
			n = 1;
			break;
		}
		goto malformed;
		break;
	case HTML_STATE_END_TAG_OPEN: /* </ */
		ptr = memchr(data, '>', len);
		if (!ptr) {
			n = len;
			break;
		}
		ctx->state = HTML_STATE_DATA;
		n = ptr - data + 1;
		break;
	case HTML_STATE_PI: /* <? */
		ptr = memchr(data, '>', len);
		if (!ptr) {
			n = len;
			strlncat(ctx->attr_val, sizeof(ctx->attr_val),
				 (const char *)data, n);
			break;
		}
		if (ptr != data)
			strlncat(ctx->attr_val, sizeof(ctx->attr_val),
				 (const char *)data, ptr - data);
		html_parse_pi(ctx);
		ctx->state = HTML_STATE_DATA;
		n = ptr - data + 1;
		break;
	case HTML_STATE_DECL_OPEN: /* <! */
		n = 1;
		switch (*data) {
		case '-': /* <!- */
			ctx->state = HTML_STATE_CMNT_SUSP;
			break;
		case '[': /* <![ */
			ctx->state =  HTML_STATE_MARKD_SEC;
			break;
		default:
			/**
			 * We don't need to interpret the declarations, so we
			 * treat them as bogus comment.
			 */
			ctx->state = HTML_STATE_BOGUS_CMNT;
			n = 0;
			break;
		}
		break;
	case HTML_STATE_CMNT_SUSP: /* <!- */
		switch (*data) {
		case '-': /* <!-- */
			ctx->state = HTML_STATE_CMNT;
			n = 1;
			break;
		default:
			ctx->state = HTML_STATE_BOGUS_CMNT;
			n = 0;
			break;
		}
		break;
	case HTML_STATE_MARKD_SEC: /* <![ */
		ptr = memchr(data, ']', len);
		if (!ptr) {
			n = len;
			break;
		}
		ctx->state = HTML_STATE_MARKD_SEC_BRAC;
		n = ptr - data + 1;
		break;
	case HTML_STATE_MARKD_SEC_BRAC: /* <![.*]\s* */
		n = 1;
		switch (*data) {
		case ']':
			ctx->state = HTML_STATE_MARKD_SEC_BRAC2;
			break;
		default:
			if (!is_space(*data))
				ctx->state = HTML_STATE_MARKD_SEC;
			break;
		}
		break;
	case HTML_STATE_MARKD_SEC_BRAC2: /* <![.*]\s*]\s*]\s* */
		n = 1;
		switch (*data) {
		case '>':
			ctx->state = HTML_STATE_DATA;
			break;
		case ']':
			break;
		default:
			if (!is_space(*data))
				ctx->state = HTML_STATE_MARKD_SEC;
			break;
		}
		break;
	case HTML_STATE_BOGUS_CMNT: /* <!|</ */
		ptr = memchr(data, '>', len);
		if (!ptr) {
			n = len;
			break;
		}
		ctx->state = HTML_STATE_DATA;
		n = ptr - data + 1;
		break;
	case HTML_STATE_CMNT: /* <!--.* */
		n = 1;
		if (*data == '-')
			ctx->state = HTML_STATE_CMNT_DASH;
		break;
	case HTML_STATE_CMNT_DASH: /* <!-- - */
		n = 1;
		if (*data == '-') {
			ctx->got_space = false;
			ctx->state = HTML_STATE_CMNT_END;
		} else {
			ctx->state = HTML_STATE_CMNT;
		}
		break;
	case HTML_STATE_CMNT_END: /* <!-- -\s* */
		n = 1;
		switch (*data) {
		case '>':
			ctx->state = HTML_STATE_DATA;
			break;
		case '-':
			if (ctx->got_space)
				ctx->state = HTML_STATE_CMNT_DASH;
			break;
		default:
			if (is_space(*data)) {
				if (!ctx->got_space)
					ctx->got_space = true;
			} else {
				ctx->state = HTML_STATE_CMNT;
			}
			break;
		}
		break;
	case HTML_STATE_CDATA:
		ptr = memchr(data, '<', len);
		if (!ptr) {
			n = len;
			break;
		}
		ctx->state = HTML_STATE_CDATA_TAG_OPEN;
		n = ptr - data + 1;
		break;
	case HTML_STATE_CDATA_TAG_OPEN: /* < */
		switch (*data) {
		case '/':
			ctx->state = HTML_STATE_CDATA_END_TAG_OPEN;
			n = 1;
			break;
		default:
			ctx->state = HTML_STATE_CDATA;
			n = 0;
			break;
		}
		break;
	case HTML_STATE_CDATA_END_TAG_OPEN: /* </ */
		n = 1;
		if (is_alpha(*data)) {
			ctx->state = HTML_STATE_CDATA_END_TAG_NAME;
			strlncpy(ctx->tag_name, sizeof(ctx->tag_name),
				 (const char *)data, 1);
		} else if (!is_space(*data)) {
			ctx->state = HTML_STATE_CDATA;
			n = 0;
		}
		break;
	case HTML_STATE_CDATA_END_TAG_NAME: /* </\s*[a-zA-Z] */
		n = alpha_len((const char *)data, len);
		if (n > 0)
			strlncat(ctx->tag_name, sizeof(ctx->tag_name),
				 (const char *)data, n);
		if (n == len)
			break;
		switch (data[n++]) {
		case '>':
			html_cdata_end(ctx);
			break;
		default:
			if (is_space(data[n - 1])) {
				ctx->state = HTML_STATE_CDATA_END_TAG_CLS;
			} else {
				ctx->state = HTML_STATE_CDATA;
				--n;
			}
			break;
		}
		break;
	case HTML_STATE_CDATA_END_TAG_CLS:
		n = 1;
		switch (*data) {
		case '>':
			html_cdata_end(ctx);
			break;
		default:
			if (!is_space(*data)) {
				ctx->state = HTML_STATE_CDATA;
				n = 0;
			}
			break;
		}
		break;
	}

	return n;
malformed:
	g_html_stat.malformed++;

	return -1;
}

int html_parse(html_parse_ctx_t *ctx, const unsigned char *data, int len,
		html_data_handler h, void *user)
{
	while (len > 0) {
		int n = __html_parse(ctx, data, len, h, user);

		if (n < 0) {
			ctx->failed_to_parse = true;
			return -1;
		}
		data += n;
		len -= n;
	}

	return 0;
}

#ifdef TEST
#include <assert.h>

static char buf[2048];

static void cb(const unsigned char *data, int len, void *user)
{
	strlncat(buf, sizeof(buf), data, len);
}

int main(void)
{
	const char *ptr;
	html_parse_ctx_t *ctx = html_parse_ctx_alloc("utf-8");

#define TEST_ONE(data, exp_data) \
	buf[0] = '\0'; \
	assert(html_parse(ctx, data, strlen(data), cb, NULL) == 0); \
	assert(ctx->state == HTML_STATE_DATA); \
	assert(strcmp(buf, exp_data) == 0); \
	buf[0] = '\0'; \
	for (ptr = data; *ptr; ptr++) \
		assert(html_parse(ctx, ptr, 1, cb, NULL) == 0); \
	assert(ctx->state == HTML_STATE_DATA); \
	assert(strcmp(buf, exp_data) == 0)
	TEST_ONE("<?>", "");
	TEST_ONE("<!>", "");
	TEST_ONE("</>", "");
	TEST_ONE("</$>", "");
	TEST_ONE("<a href=xxx>", "");
	TEST_ONE("<a href='xx\"x'>", "");
	TEST_ONE("<a href=\"xx'x\">", "");
	TEST_ONE("<a>", "");
	TEST_ONE("<br />", "");
	TEST_ONE("</div>", "");
	TEST_ONE("<![CDATA[<</<'\"]]xx]o]  ]  ]  >", "");
	TEST_ONE("<script></style></Script>", "");
	TEST_ONE("<script><!-- not comment --></Script>", "");
	TEST_ONE("<STYLE></script></Style>", "");
	TEST_ONE("<!---t--->", "");
	TEST_ONE("<!--t-- -> --  >", "");
	TEST_ONE("<a href=\"tt\">link</a>", "link");
	TEST_ONE("<a href=/test/ >", "");
	TEST_ONE("<a href=/test/>", "");
	TEST_ONE("<<a>", "<");
	TEST_ONE("<a b  =  'v'  c = \"v\"  d  =  v e>", "");
	TEST_ONE("<a\nb\n=\n'v'\nc = \n\"v\"\n  \nd \n =  v\n e>", "");
	TEST_ONE("<e a=rgb(1,2,3)>", "");
	TEST_ONE("<a href=mailto:xyz@example.com>", "");
	TEST_ONE("<a a.b='v' c:d=v e-f=v>", "");
	TEST_ONE("<!spacer type='block'>", "");
	TEST_ONE("<a b='<'>", "");
	TEST_ONE("<a b='>'>", "");
	TEST_ONE("<p/>", "");
	TEST_ONE("<p></p>", "");
	TEST_ONE("<p><img src='foo' /></p>", "");
	TEST_ONE("<input value=abc/ name=path>", "");
	TEST_ONE("<p>I <em>Love</em> You</p>", "I Love You");
	TEST_ONE("<?xml version=\"1.0\" encoding=\"gb18030\" ?>", "");
	TEST_ONE("<img src='xxx'alt=ok>", "");
	TEST_ONE("<a href=a'\"`=</>", "");
	assert(strcmp(ctx->attr_val, "a'\"`=</") == 0);
	assert(strcmp(ctx->charset, "gb18030") == 0);
	ctx->charset[0] = '\0';
	TEST_ONE("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=GB2312\"/>", "");
	assert(strcmp(ctx->charset, "gb2312") == 0);
	ctx->charset[0] = '\0';
	TEST_ONE("<META http-equiv=\"Content-Type\" CONTENT='text/html; charset=\"GBK\"'>", "");
	assert(strcmp(ctx->charset, "gbk") == 0);
	ctx->charset[0] = '\0';
	TEST_ONE("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=GB2312\" /><h1>\xc4\xe3\xba\xc3</h1>", "\xe4\xbd\xa0\xe5\xa5\xbd");
	assert(strcmp(ctx->charset, "gb2312") == 0);
	ctx->charset[0] = '\0';

	return 0;
}
#endif
