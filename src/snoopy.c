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

#include "utils.h"
#include "types.h"
#include "buf.h"
#include "flow.h"
#include "patn.h"
#include "rule.h"
#include "log.h"
#include "http.h"
#include "snoopy.h"
#include "time.h"
#include "list.h"
#include "ctab.h"
#include "html.h"
#include "unitest.h"
#include "pcap_list.h"
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include <net/ethernet.h>
#ifndef __APPLE__
#include <net/ppp_defs.h>
#endif

#ifdef NDEBUG
# define pr_debug(fmt, args...) do {} while (0)
# define pr_ip(ip) do { } while (0)
#else
# define pr_debug(fmt, args...) do {} while (0)
//# define pr_debug(fmt, args...) printf(fmt, ##args)
static inline void pr_ip(const struct ip *ip)
{
	const struct tcphdr *th;

	th = (const struct tcphdr *)(((const char *)ip) + ip->ip_hl * 4);
	printf(NIPQUAD_FMT ":%hu->" NIPQUAD_FMT ":%hu\n",
	       NIPQUAD(ip->ip_src), ntohs(th->th_sport),
	       NIPQUAD(ip->ip_dst), ntohs(th->th_dport));
}
#endif /* NDEBUG */

static void usage(FILE *out)
{
	fputs("Usage: snoopy [options] pcap-program\n", out);
	fputs("Options:\n", out);
	fputs("  -a       inspect all contents\n", out);
	fputs("  -b       run as a background daemon\n", out);
	fputs("  -h       show this message\n", out);
	fputs("  -i NIC   specify the NIC interface\n", out);
	fputs("  -k FN    specify the keyword file\n", out);
	fputs("  -l FN    specify the log file\n", out);
	fputs("  -m SZ    specify the pcap buffer size to SZ MB\n", out);
	fputs("  -r FILE  specify the pcap file\n", out);
	fputs("  -s LEN   specify the snap length\n", out);
	fputs("  -R FN    specify the rule file\n", out);
	fputs("  -z       switch to lazy mode\n", out);
}

static struct snoopy_stat {
	uint64_t		pkts;
	uint64_t		frags;
} snoopy_stat = { 0 };

static void show_snoopy_stat(void)
{
	printf("packets: %" PRIu64 "\n", snoopy_stat.pkts);
	printf("fragments: %" PRIu64 "\n", snoopy_stat.frags);
}

enum http_content_type {
	HTTP_CT_UNSUP,
	HTTP_CT_PLAIN,
	HTTP_CT_HTML,
};

struct http_req {
	char				*path;
	char				*host;
	html_parse_ctx_t		*html_ctx;
	enum http_content_type		ct;
	bool				ignore;
	stlist_entry(struct http_req)	link;
	char				charset[HTML_CHARSET_SIZE];
	int				status_code;
};

static struct http_req *http_req_alloc()
{
	return calloc(1, sizeof(struct http_req));
}

static void http_req_free(struct http_req *r)
{
	free(r->path);
	free(r->host);
	if (r->html_ctx)
		html_parse_ctx_free(r->html_ctx);
	free(r);
}

struct snoopy_ctx {
	rule_list_t	*rule_list;
	http_parser_t	*pasr;
	patn_list_t	*patn_list;
	bool		is_lazy;
	bool		inspect_all;
	bool		live;
};

struct flow_ctx {
	stlist_head( , struct http_req)	req_list;
	struct http_req			*req_part;
	patn_sch_ctx_t			*sch_ctx;
	http_parse_ctx_t		*http_ctx;
	bool				stop_inspect;
	struct snoopy_ctx		*snoopy;
};

static void flow_ctx_free_data(struct flow_ctx *fc)
{
	struct http_req *r;

	while ((r = stlist_first(&fc->req_list))) {
		stlist_del_head(&fc->req_list, r, link);
		http_req_free(r);
	}
	if (fc->sch_ctx)
		patn_sch_ctx_free(fc->sch_ctx);
	if (fc->http_ctx)
		http_parse_ctx_free(fc->http_ctx);
}

static void flow_ctx_free(struct flow_ctx *fc)
{
	flow_ctx_free_data(fc);
	free(fc);
}

static struct flow_ctx *flow_ctx_alloc(struct snoopy_ctx *snoopy)
{
	struct flow_ctx *fc = calloc(1, sizeof(*fc));

	if (!fc)
		goto err;
	stlist_head_init(&fc->req_list);
	fc->snoopy = snoopy;

	return fc;
err:
	return NULL;
}

static void flow_ctx_reset(struct flow_ctx *fc)
{
	struct snoopy_ctx *snoopy = fc->snoopy;

	flow_ctx_free_data(fc);
	memset(fc, 0, sizeof(*fc));
	stlist_head_init(&fc->req_list);
	fc->snoopy = snoopy;
}

#define FLOW_TAG_ID	0

struct http_user {
	struct flow_ctx		*fc;
	struct ip		*ip;
};

struct flow_user {
	struct snoopy_ctx	*sc;
	struct ip		*ip;
};

static void stream_inspect(flow_t *f, int dir, const unsigned char *data,
		int len, void *user)
{
	struct flow_ctx *fc;
	struct flow_user *fu = user;
	struct http_user hu;

	fc = flow_get_tag(f, FLOW_TAG_ID);
	if (!fc) {
		fc = flow_ctx_alloc(fu->sc);
		if (!fc)
			goto err;
		if (flow_add_tag(f, FLOW_TAG_ID, fc,
				(void (*)(void *))flow_ctx_free))
			goto err2;
	}

	if (fc->stop_inspect)
		goto err;

	hu.fc = fc;
	hu.ip = fu->ip;
	if (!fc->http_ctx && !(fc->http_ctx = http_parse_ctx_alloc()))
		goto stop_inspect;
	if (http_parse(fu->sc->pasr, fc->http_ctx, dir, data, len, &hu) ||
	    fc->stop_inspect) {
		pr_ip(hu.ip);
stop_inspect:
		flow_ctx_reset(fc);
		fc->stop_inspect = true;
		goto err;
	}

	return;
err2:
	flow_ctx_free(fc);
err:
	return;
}

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

#ifndef ETHERTYPE_PPPOE
#define ETHERTYPE_PPPOE 0x8864
#endif

#ifndef PPP_IP
#define PPP_IP	0x21
#endif

struct pppoe_hdr {
	uint8_t	vertype;
	uint8_t	code;
	be16_t	sid;
	be16_t	len;
} __attribute__((packed));

struct pppoe_ses_hdr {
	struct pppoe_hdr	ph;
	be16_t			proto;
} __attribute__((packed));

static void ip_handler(struct snoopy_ctx *sc, const uint8_t *bytes, int len)
{
	struct ip *iph;
	struct tcphdr *tcph;
	int hl;
	struct flow_user fu;

	/* ip */
	if (len < sizeof(*iph))
		goto err;
	iph = (struct ip *)bytes;
	/* strip out the padding bytes if any */
	hl = ntohs(iph->ip_len);
	if (hl > len) {
		goto err;
	} else if (hl < len) {
		if (hl < sizeof(*iph))
			goto err;
		len = hl;
	}
	hl = iph->ip_hl * 4;
	if (hl < sizeof(*iph) || hl > len)
		goto err;
	bytes += hl;
	len -= hl;

	/* tcp */
	if (iph->ip_p != IPPROTO_TCP)
		goto err;
	/* TODO: support IP defragment */
	if (ntohs(iph->ip_off) & (IP_MF | IP_OFFMASK)) {
		snoopy_stat.frags++;
		goto err;
	}
	if (len < sizeof(*tcph))
		goto err;
	tcph = (struct tcphdr *)bytes;
	if (!rule_list_match(sc->rule_list, iph->ip_src.s_addr,
			tcph->th_sport) &&
	    !rule_list_match(sc->rule_list, iph->ip_dst.s_addr,
			tcph->th_dport))
		goto err;
	hl = tcph->th_off * 4;
	if (hl < sizeof(*tcph) || hl > len)
		goto err;
	bytes += hl;
	len -= hl;

	/* flow */
	fu.sc = sc;
	fu.ip = iph;
	flow_inspect(iph, tcph, bytes, len, stream_inspect, &fu);
err:
	return;
}

static void ethernet_demux(struct snoopy_ctx *sc, const uint8_t *bytes, int len,
		int proto)
{
	struct vlan_hdr *vlan;
	struct pppoe_ses_hdr *pppoe_ses;
again:
	switch (proto) {
	case ETHERTYPE_IP:
		break;
	case ETHERTYPE_VLAN:
		if (len < sizeof(*vlan))
			goto err;
		vlan = (struct vlan_hdr *)bytes;
		bytes += sizeof(*vlan);
		len -= sizeof(*vlan);
		proto = ntohs(vlan->encapsulated_proto);
		goto again;
		break;
	case ETHERTYPE_PPPOE:
		if (len < sizeof(*pppoe_ses))
			goto err;
		pppoe_ses = (struct pppoe_ses_hdr *)bytes;
		bytes += sizeof(*pppoe_ses);
		len -= sizeof(*pppoe_ses);
		if (ntohs(pppoe_ses->proto) != PPP_IP)
			goto err;
		break;
	default:
		goto err;
	}
	ip_handler(sc, bytes, len);
err:
	return;
}

static void check_pkthdr(const struct pcap_pkthdr *h)
{
	if (h->caplen != h->len) {
		fprintf(stderr, "truncated packet: %u(%u)\n", h->len,
			h->caplen);
		exit(EXIT_FAILURE);
	}

	time_update(&h->ts);

	snoopy_stat.pkts++;
}

static void ethernet_handler(u_char *user, const struct pcap_pkthdr *h,
		const u_char *bytes)
{
	struct ether_header *eth;

	check_pkthdr(h);

	/* ethernet */
	if (h->len < sizeof(*eth))
		goto err;
	eth = (struct ether_header *)bytes;
	ethernet_demux((struct snoopy_ctx *)user, bytes + sizeof(*eth),
			h->len - sizeof(*eth), ntohs(eth->ether_type));
err:
	return;
}

static void linux_sll_handler(u_char *user, const struct pcap_pkthdr *h,
		const u_char *bytes)
{
	struct sll_header *sll;

	check_pkthdr(h);

	if (h->len < sizeof(*sll))
		goto err;
	sll = (struct sll_header *)bytes;
	ethernet_demux((struct snoopy_ctx *)user, bytes + sizeof(*sll),
			h->len - sizeof(*sll), ntohs(sll->sll_protocol));
err:
	return;
}

static void raw_handler(u_char *user, const struct pcap_pkthdr *h,
		const u_char *bytes)
{
	check_pkthdr(h);

	ip_handler((struct snoopy_ctx *)user, bytes, h->len);
}

static void save_path(const char *method, const char *path,
		int minor_ver, void *user)
{
	struct http_user *hu = user;
	struct flow_ctx *fc = hu->fc;

	if (!fc->req_part) {
		fc->req_part = http_req_alloc();
		if (!fc->req_part)
			goto err;
		stlist_add_tail(&fc->req_list, fc->req_part, link);
	}

	assert(fc->req_part->path == NULL);

	pr_debug("path: %s\n", path);
	fc->req_part->path = strdup(path);
err:
	return;
}

static void save_status_code(int minor_ver, int status_code,
		const char *reason_phase, void *user)
{
	struct http_user *hu = user;
	struct flow_ctx *fc = hu->fc;
	struct http_req *r;

	if ((r = stlist_first(&fc->req_list)))
		r->status_code = status_code;
}

static void save_host(const char *name, int name_len,
		const char *value, int value_len, void *user)
{
	struct http_user *hu = user;
	struct flow_ctx *fc = hu->fc;
	struct http_req *r;

	if (!(r = fc->req_part))
		goto err;
	if (name_len == 4 && strcasecmp(name, "Host") == 0) {
		int i;

		for (i = 0; i < value_len; i++) {
			if (is_space(value[i]))
				goto err;
		}
		if (r->host)
			free(r->host);
		pr_debug("host: %s\n", value);
		r->host = strdup(value);
	}
err:
	return;
}

static void end_req(void *user)
{
	struct http_user *hu = user;
	struct flow_ctx *fc = hu->fc;

	if (fc->req_part)
		fc->req_part = NULL;
}

/*
 * media-type     = type "/" subtype *( ";" parameter )
 * type           = token
 * subtype        = token
 * parameter               = attribute "=" value
 * attribute               = token
 * value                   = token | quoted-string
 */
static int parse_content_type(struct http_req *r, const char *value,
		int value_len)
{
	const char *type, *subtype, *ptr;
	int type_len, subtype_len;

	type = value;
	type_len = __token_len(type);
	if (type_len == 0)
		goto err;
	if (type[type_len] != '/')
		goto err;
	subtype = type + type_len + 1;
	subtype_len = __token_len(subtype);
	if (subtype_len == 0)
		goto err;

	/*
	 * The type, subtype, and parameter attribute names are case-
	 * insensitive.
	 */
	if (type_len == 4 && strncasecmp_c(type, "text") == 0) {
		if ((subtype_len == 4 && strncasecmp_c(subtype, "html") == 0) ||
		    (subtype_len == 3 && strncasecmp_c(subtype, "xml") == 0))
			r->ct = HTTP_CT_HTML;
		else
			r->ct = HTTP_CT_PLAIN;
	} else if (type_len == 11 &&
		   strncasecmp_c(type, "application") == 0 &&
		   ((subtype_len == 3 && strncasecmp_c(subtype, "xml") == 0) ||
		    (subtype_len > 4 &&
		     strncasecmp_c(subtype + subtype_len - 4, "+xml") == 0))) {
			r->ct = HTTP_CT_HTML;
	} else {
		goto err;
	}

	ptr = subtype + subtype_len;
	while (1) {
		const char *attr_name, *attr_val;
		int attr_name_len, attr_val_len;

		ptr = __skip_space(ptr);
		if (*ptr == '\0')
			break;
		if (*ptr != ';')
			goto err;
		attr_name = __skip_space(ptr + 1);
		attr_name_len = __token_len(attr_name);
		if (attr_name_len == 0)
			goto err;
		ptr = __skip_space(attr_name + attr_name_len);
		if (*ptr != '=')
			goto err;
		attr_val = __skip_space(ptr + 1);
		if (*attr_val == '"') {
			attr_val_len = get_quoted_str_len(attr_val,
					value_len - (attr_val - value));
			if (attr_val_len == 0)
				goto err;
			ptr = attr_val + attr_val_len;
			attr_val++;
			attr_val_len--;
		} else {
			attr_val_len = __token_len(attr_val);
			if (attr_val_len == 0)
				goto err;
			ptr = attr_val + attr_val_len;
		}
		if (attr_name_len == 7 &&
		    strncasecmp_c(attr_name, "charset") == 0 &&
		    attr_val_len > 0) {
			strlncpy(r->charset, sizeof(r->charset),
				 attr_val, attr_val_len);
			strtolower(r->charset);
		}
	}

	return 0;
err:
	return -1;
}

static void parse_res_hdr_fild(const char *name, int name_len,
		const char *value, int value_len, void *user)
{
	struct http_user *hu = user;
	struct flow_ctx *fc = hu->fc;
	struct http_req *r;

	if (!name || !(r = stlist_first(&fc->req_list)))
		goto err;
	if (name_len == 12 && strcasecmp(name, "Content-Type") == 0) {
		if (parse_content_type(r, value, value_len))
			goto err;
	} else if (name_len == 13 && strcasecmp(name, "Content-Range") == 0) {
		const char *ptr;

		/*
		 * Content-Range = "Content-Range" ":" content-range-spec
		 * content-range-spec      = byte-content-range-spec
		 * byte-content-range-spec = bytes-unit SP
		 * 			     byte-range-resp-spec "/"
		 * 			     ( instance-length | "*" )
		 * byte-range-resp-spec = (first-byte-pos "-" last-byte-pos) |
		 *                         "*"
		 * instance-length           = 1*DIGIT
		 * range-unit       = bytes-unit | other-range-unit
		 * bytes-unit       = "bytes"
		 * other-range-unit = token
		 */
		/* skip bytes-unit */
		ptr = __skip_token(value);
		if (ptr == value)
			goto err;
		value = __skip_space(ptr);
		if (value == ptr)
			goto err;
		/* we can NOT recover from partial contents */
		if (strtoull(value, NULL, 10) != 0ULL)
			r->ignore = true;
	}
err:
	return;
}

struct patn_user {
	struct ip		*ip;
	struct http_req		*r;
	struct flow_ctx		*fc;
};

static int log_keyword(const unsigned char *k, void *user)
{
	struct patn_user *pu = user;
	struct flow_ctx *fc = pu->fc;
	int r;

	r = log_write(&g_time, pu->ip->ip_dst.s_addr, pu->ip->ip_src.s_addr,
		      pu->r->host, pu->r->path, (const char *)k);
	if (r < 0)
		return r;
	if (fc->snoopy->is_lazy) {
		fc->stop_inspect = true;
		return 1;
	}

	return 0;
}

static void inspect_text(const unsigned char *data, int len, void *user)
{
	struct http_user *hu = user;
	struct flow_ctx *fc = hu->fc;

	if (fc->stop_inspect)
		goto err;
	if (!fc->sch_ctx && !(fc->sch_ctx = patn_sch_ctx_alloc()))
		goto err;
#ifndef NDEBUG
	if (write(STDOUT_FILENO, data, len) != len)
		exit(EXIT_FAILURE);
#endif
	struct patn_user pn = {
		.ip	= hu->ip,
		.r	= stlist_first(&fc->req_list),
		.fc	= fc,
	};
	patn_sch(fc->snoopy->patn_list, fc->sch_ctx, data, len, log_keyword,
		 &pn);
err:
	return;
}

static void inspect_body(const unsigned char *data, int len, void *user)
{
	struct http_user *hu = user;
	struct flow_ctx *fc = hu->fc;
	struct http_req *r;

	if (!(r = stlist_first(&fc->req_list)))
		goto err;
	if (r->host && r->path && !fc->stop_inspect && !r->ignore) {
		if (r->ct == HTTP_CT_HTML) {
			if (!r->html_ctx &&
			    !(r->html_ctx = html_parse_ctx_alloc(r->charset)))
				goto err;
			if (html_parse(r->html_ctx, data, len, inspect_text,
				       hu)) {
				pr_ip(hu->ip);
				r->ignore = true;
				goto err;
			}
		} else if (r->ct != HTTP_CT_UNSUP ||
			   fc->snoopy->inspect_all) {
			inspect_text(data, len, user);
		}
	}
err:
	return;
}

static void end_res(void *user)
{
	struct http_user *hu = user;
	struct flow_ctx *fc = hu->fc;
	struct http_req *r;

	if (!(r = stlist_first(&fc->req_list)))
		goto err;
	if ((r->status_code / 100) != 1) {
		stlist_del_head(&fc->req_list, r, link);
		http_req_free(r);
		if (fc->sch_ctx)
			patn_sch_ctx_reset(fc->sch_ctx);
	}
err:
	return;
}

static pcap_list_t *pl;
static bool caught_sigint = false;
static bool background = false;

static void handle_sigint(int signo)
{
	if (!background) {
		pcap_list_breakloop(pl);
		caught_sigint = 1;
	}
}

static void handle_sigquit(int signo)
{
	pcap_list_breakloop(pl);
}

static void show_pcap_stat(pcap_list_t *pl)
{
	struct pcap_stat st;

	if (pcap_list_stats(pl, &st)) {
		fprintf(stderr, "failed to obtain the statistics: %s\n",
			pcap_list_geterr(pl));
		exit(EXIT_FAILURE);
	}
	printf("pcap-received: %u\n", st.ps_recv);
	printf("pcap-dropped: %u\n", st.ps_drop);
}

static void show_stat(struct snoopy_ctx *ctx)
{
	fputs("\n", stdout);
	if (ctx->live)
		show_pcap_stat(pl);
	show_snoopy_stat();
	flow_stat_show();
	http_stat_show();
	html_stat_show();
}

int main(int argc, char *argv[])
{
	int o;
	const char *file = NULL;
	int snap_len = 0;
	pcap_handler handler;
	struct snoopy_ctx ctx = { 0 };
	const char *rule_fn = SNOOPY_RULE_FN;
	const char *key_fn = SNOOPY_KEY_FN;
	const char *log_fn = SNOOPY_LOG_FN;
	int buf_size = 0;

#ifndef NDEBUG
	if (strlen(argv[0]) >= 4 &&
	    strcmp(argv[0] + strlen(argv[0]) - 4, "unit") == 0) {
		unitest_run_all();
		exit(EXIT_SUCCESS);
	}
#endif

	pl = pcap_list_alloc();
	if (!pl)
		die("failed to allocate a pcap list\n");

	/* parse the options */
	while ((o = getopt(argc, argv, "abhi:k:l:m:r:s:zR:")) != -1) {
		switch (o) {
		case 'a':
			ctx.inspect_all = true;
			break;
		case 'b':
			background = true;
			break;
		case 'h':
			usage(stdout);
			goto out;
			break;
		case 'i':
			if (file)
				die("FILE and NIC are exclusive\n");
			ctx.live = true;
			if (pcap_list_add(pl, optarg))
				die("failed to add a NIC to monitor\n");
			break;
		case 'k':
			key_fn = optarg;
			break;
		case 'l':
			log_fn = optarg;
			break;
		case 'm':
			buf_size = atoi(optarg);
			break;
		case 'r':
			if (file)
				die("duplicate file specified\n");
			if (ctx.live)
				die("FILE and NIC are exclusive\n");
			if (pcap_list_add(pl, optarg))
				die("failed to add a file to read\n");
			file = optarg;
			break;
		case 's':
			snap_len = atoi(optarg);
			if (snap_len <= 0)
				die("invalid snap length %s\n", optarg);
			break;
		case 'z':
			ctx.is_lazy = true;
			break;
		case 'R':
			rule_fn = optarg;
			break;
		default:
			usage(stderr);
			goto err;
			break;
		}
	}
	if (!ctx.live && !file)
		die("FILE or NIC must be given\n");

	/* initialize snoopy ctx */
	if (flow_init())
		die("failed to initialize flow service\n");
	if (log_open(log_fn))
		die("failed to open log file %s\n", log_fn);
	ctx.rule_list = rule_list_load(rule_fn);
	if (!ctx.rule_list)
		die("failed to load rules in %s\n", rule_fn);
	ctx.pasr = http_parser_alloc();
	if (!ctx.pasr)
		die("failed to allocate a http parser\n");
	http_parser_set_request_line_handler(ctx.pasr, save_path);
	http_parser_set_status_line_handler(ctx.pasr, save_status_code);
	http_parser_set_header_field_handler(ctx.pasr, PKT_DIR_C2S, save_host);
	http_parser_set_header_field_handler(ctx.pasr, PKT_DIR_S2C,
			parse_res_hdr_fild);
	http_parser_set_body_handler(ctx.pasr, PKT_DIR_S2C, inspect_body);
	http_parser_set_msg_end_handler(ctx.pasr, PKT_DIR_C2S, end_req);
	http_parser_set_msg_end_handler(ctx.pasr, PKT_DIR_S2C, end_res);
	ctx.patn_list = patn_list_load(key_fn);
	if (!ctx.patn_list)
		die("failed to load keywords in %s\n", key_fn);
	if (signal(SIGINT, handle_sigint) == SIG_ERR)
		die("failed to install the SIGINT handler\n");
	if (signal(SIGQUIT, handle_sigquit) == SIG_ERR)
		die("failed to install the SIGQUIT handler\n");
	if (signal(SIGTERM, handle_sigquit) == SIG_ERR)
		die("failed to install the SIGTERM handler\n");

	/* open the pcap handler */
	if (ctx.live) {
		if (pcap_list_open_live(pl, snap_len, buf_size))
			die("failed to open pcap_list: %s\n",
			    pcap_list_geterr(pl));
	} else {
		if (pcap_list_open_offline(pl, file))
			die("failed to open pcap_list: %s\n",
			    pcap_list_geterr(pl));
	}

	/* set the filter if requested */
	if (optind < argc) {
		char buf[LINE_MAX];
		int len = 0, r;

		/* concat the remain arguments */
		while (optind < argc) {
			r = snprintf(buf + len, sizeof(buf) - len,
				     (len == 0) ? "%s" : " %s",
				     argv[optind++]);
			if (r < 0 || r >= sizeof(buf) - len)
				die("insufficent buffer for pcap-program\n");
			len += r;
		}

		if (pcap_list_setfilter(pl, buf))
			die("failed to set the pcap-program: %s\n",
			    pcap_list_geterr(pl));
	}

	/* start the pcap loop */
	switch (pcap_list_datalink(pl)) {
	case DLT_EN10MB:
		handler = ethernet_handler;
		break;
	case DLT_LINUX_SLL:
		handler = linux_sll_handler;
		break;
	case DLT_RAW:
		handler = raw_handler;
		break;
	case -1:
		die("invalid data link\n");
		break;
	default:
		die("unsupported datalnk: %s\n",
		    pcap_datalink_val_to_name(pcap_list_datalink(pl)));
		break;
	}
	if (background && daemon(0, 0))
		die("failed to become a background daemon\n");
	while (1) {
		if (pcap_list_loop(pl, handler, (u_char *)&ctx) == -1)
			die("pcap_list_loop() exits with error: %s\n",
			    pcap_list_geterr(pl));
		if (!caught_sigint)
			break;
		caught_sigint = false;
		if (!background)
			show_stat(&ctx);
	}

	/* output the statistics if possible */
	if (!background)
		show_stat(&ctx);

	/* close the pcap handler */
	pcap_list_free(pl);

	patn_list_free(ctx.patn_list);
	http_parser_free(ctx.pasr);
	rule_list_free(ctx.rule_list);
	log_close();
	flow_exit();
out:
	return EXIT_SUCCESS;
err:
	return EXIT_FAILURE;
}
