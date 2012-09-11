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
#include <string.h>

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

/**
 * The following limit is got with the following command: ("//" at the end
 * of the codeset is a delimiter)
 *
 * $ iconv -l | awk 'BEGIN { len = 0; charset="" } { if (length($0) > len) {len = length($0); charset=$0} } END { print len; print charset }'
 * 24
 * CSISO11SWEDISHFORNAMES//
 * ICONV
 */
#define HTML_CHARSET_SIZE 24

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
	HTML_STATE_AFTR_ATTR_VAL,
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

#define HTML_BUF_SIZE	16

struct html_parse_ctx {
	enum html_state	state;
	char		tag_name[HTML_NAME_SIZE];	/* case insensitive */
	char		attr_name[HTML_NAME_SIZE];	/* case insensitive */
	char		attr_val[HTML_ATTR_VAL_SIZE];
	char		cdata_elem[sizeof("script")];
	char		charset[HTML_CHARSET_SIZE];
	bool		got_space;
};

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
	if (charset)
		strlncpy(ctx->charset, sizeof(ctx->charset), charset,
			 strlen(charset));
	else
		ctx->charset[0] = '\0';
	ctx->got_space = false;
err:
	return ctx;
}

void html_parse_ctx_free(html_parse_ctx_t *ctx)
{
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

static int __html_parse(html_parse_ctx_t *ctx, const unsigned char *data,
		int len, html_data_handler h, void *user)
{
	const unsigned char *ptr;
	int n;

	switch (ctx->state) {
	case HTML_STATE_DATA:
		ptr = memchr(data, '<', len);
		if (!ptr) {
			h(data, len, user);
			n = len;
			break;
		}
		ctx->state = HTML_STATE_TAG_OPEN;
		if (ptr != data)
			h(data, ptr - data, user);
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
			break;
		default:
			ctx->state = HTML_STATE_DATA;
			h((const unsigned char *)"<", 1, user);
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
				n = -1;
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
				n = -1;
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
				n = -1;
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
				n = -1;
			break;
		}
		break;
	case HTML_STATE_BFOR_ATTR_VAL:
		n = 1;
		if (is_attr_val(*data)) {
			ctx->state = HTML_STATE_ATTR_VAL_UQ;
			strlncpy(ctx->attr_val, sizeof(ctx->attr_val),
				 (const char *)data, 1);
			break;
		}
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
			if (!is_space(*data))
				n = -1;
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
			html_cdata_start(ctx);
			break;
		default:
			if (is_space(data[n - 1]))
				ctx->state = HTML_STATE_BFOR_ATTR_NAME;
			else
				n = -1;
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
		ctx->state = HTML_STATE_AFTR_ATTR_VAL;
		if (ptr != data)
			strlncat(ctx->attr_val, sizeof(ctx->attr_val),
				 (const char *)data, ptr - data);
		n = ptr - data + 1;
		break;
	case HTML_STATE_ATTR_VAL_DQ:
		ptr = memchr(data, '"', len);
		goto attr_val_xq;
		break;
	case HTML_STATE_AFTR_ATTR_VAL:
		n = 1;
		switch (*data) {
		case '/':
			ctx->state = HTML_STATE_SELF_CLS_START_TAG;
			break;
		case '>':
			html_cdata_start(ctx);
			break;
		default:
			if (is_space(*data))
				ctx->state = HTML_STATE_BFOR_ATTR_NAME;
			else
				n = -1;
		}
		break;
	case HTML_STATE_SELF_CLS_START_TAG: /* <[a-z][A-Z].../ */
		if (*data == '>') {
			ctx->state = HTML_STATE_DATA;
			n = 1;
			break;
		}
		n = -1;
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
			break;
		}
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
}

int html_parse(html_parse_ctx_t *ctx, const unsigned char *data, int len,
		html_data_handler h, void *user)
{
	while (len > 0) {
		int n = __html_parse(ctx, data, len, h, user);

		if (n < 0)
			return -1;
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
	html_parse_ctx_t *ctx = html_parse_ctx_alloc("test");

#define TEST_ONE(data, exp_data) \
	buf[0] = '\0'; \
	assert(html_parse(ctx, data, strlen(data), cb, NULL) == 0); \
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

	return 0;
}
#endif