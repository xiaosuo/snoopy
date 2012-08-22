
#include "utils.h"
#include "types.h"
#include "buf.h"
#include "flow.h"
#include "patn.h"
#include "rule.h"
#include "log.h"
#include "http.h"
#include "snoopy.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#ifndef __APPLE__
#include <net/ppp_defs.h>
#endif

#ifdef NDEBUG
# define pr_debug(fmt, args...) do {} while (0)
#else
# define pr_debug(fmt, args...) printf(fmt, ##args)
#endif /* NDEBUG */

static void usage(FILE *out)
{
	fputs("Usage: snoopy [options] pcap-program\n", out);
	fputs("Options:\n", out);
	fputs("  -b       run as a background daemon\n", out);
	fputs("  -h       show this message\n", out);
	fputs("  -i NIC   specify the NIC interface\n", out);
	fputs("  -k FN    specify the keyword file\n", out);
	fputs("  -l FN    specify the log file\n", out);
	fputs("  -r FILE  specify the pcap file\n", out);
	fputs("  -s LEN   specify the snap length\n", out);
	fputs("  -R FN    specify the rule file\n", out);
	fputs("  -z       switch to lazy mode\n", out);
}

#define die(fmt, args...) \
do { \
	fprintf(stderr, fmt, ##args); \
	goto err; \
} while (0)

struct http_req {
	char		*path;
	char		*host;
	struct http_req	*next;
};

static struct http_req *http_req_alloc()
{
	return calloc(1, sizeof(struct http_req));
}

static void http_req_free(struct http_req *r)
{
	free(r->path);
	free(r->host);
	free(r);
}

struct snoopy_context {
	rule_list_t		*rule_list;
	http_inspector_t	*insp;
	patn_list_t		*patn_list;
	bool			is_lazy;
};

struct flow_context {
	struct http_req		*req_head;
	struct http_req		**req_ptail;
	struct http_req		*req_part;
	patn_sch_ctx_t		*sch_ctx;
	http_inspect_ctx_t	*http_ctx;
	bool			stop_inspect;
	struct snoopy_context	*snoopy;
};

static void flow_context_free_data(struct flow_context *fc)
{
	struct http_req *r;

	while ((r = fc->req_head)) {
		fc->req_head = r->next;
		http_req_free(r);
	}
	if (fc->req_part)
		http_req_free(fc->req_part);
	if (fc->sch_ctx)
		patn_sch_ctx_free(fc->sch_ctx);
	if (fc->http_ctx)
		http_inspect_ctx_free(fc->http_ctx);
}

static void flow_context_free(struct flow_context *fc)
{
	flow_context_free_data(fc);
	free(fc);
}

static struct flow_context *flow_context_alloc(struct snoopy_context *snoopy)
{
	struct flow_context *fc = calloc(1, sizeof(*fc));

	if (!fc)
		goto err;
	fc->req_ptail = &fc->req_head;
	fc->snoopy = snoopy;

	return fc;
err:
	return NULL;
}

static void flow_context_reset(struct flow_context *fc)
{
	struct snoopy_context *snoopy = fc->snoopy;

	flow_context_free_data(fc);
	memset(fc, 0, sizeof(*fc));
	fc->req_ptail = &fc->req_head;
	fc->snoopy = snoopy;
}

#define FLOW_TAG_ID	0

struct http_user {
	struct flow_context	*fc;
	struct ip		*ip;
	const struct timeval	*ts;
};

struct flow_user {
	struct snoopy_context	*sc;
	struct ip		*ip;
};

static void stream_inspect(flow_t *f, int dir, const struct timeval *ts,
		const unsigned char *data, int len, void *user)
{
	struct flow_context *fc;
	struct flow_user *fu = user;
	struct http_user hu;

	fc = flow_get_tag(f, FLOW_TAG_ID);
	if (!fc) {
		fc = flow_context_alloc(fu->sc);
		if (!fc)
			goto err;
		if (flow_add_tag(f, FLOW_TAG_ID, fc,
				(void (*)(void *))flow_context_free))
			goto err2;
	}

	if (fc->stop_inspect)
		goto err;

	hu.fc = fc;
	hu.ip = fu->ip;
	hu.ts = ts;
	if (!fc->http_ctx && !(fc->http_ctx = http_inspect_ctx_alloc()))
		goto stop_inspect;
	if (http_inspect_data(fu->sc->insp, fc->http_ctx, dir, data, len,
			&hu)) {
stop_inspect:
		flow_context_reset(fc);
		fc->stop_inspect = true;
		goto err;
	}

	return;
err2:
	flow_context_free(fc);
err:
	return;
}

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100
#endif

struct vlan_hdr {
	be16_t	tci;
	be16_t	encapsulated_proto;
};

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

void ethernet_handler(u_char *user, const struct pcap_pkthdr *h,
		      const u_char *bytes)
{
	struct ether_header *eth;
	struct ip *iph;
	struct tcphdr *tcph;
	int len, hl, proto;
	struct snoopy_context *sc = (struct snoopy_context *)user;
	struct flow_user fu;
	struct vlan_hdr *vlan;
	struct pppoe_ses_hdr *pppoe_ses;

	if (h->caplen != h->len) {
		fprintf(stderr, "truncated packet: %u(%u)\n", h->len,
			h->caplen);
		exit(EXIT_FAILURE);
	}
	len = h->len;

	/* ethernet */
	if (len < sizeof(*eth))
		goto err;
	eth = (struct ether_header *)bytes;
	bytes += sizeof(*eth);
	len -= sizeof(*eth);
	proto = ntohs(eth->ether_type);
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
	if (ntohs(iph->ip_off) & (IP_MF | IP_OFFMASK))
		goto err;
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
	flow_inspect(&h->ts, iph, tcph, bytes, len, stream_inspect, &fu);
err:
	return;
}

static void save_path(const char *method, const char *path,
		const char *http_version, void *user)
{
	struct http_user *hu = user;
	struct flow_context *fc = hu->fc;

	if (!fc->req_part && !(fc->req_part = http_req_alloc()))
		goto err;

	assert(fc->req_part->path == NULL);

	pr_debug("path: %s\n", path);
	fc->req_part->path = strdup(path);
err:
	return;
}

static void save_host(const char *name, const char *value, void *user)
{
	struct http_user *hu = user;
	struct flow_context *fc = hu->fc;
	struct http_req *r;

	if (!(r = fc->req_part))
		goto err;
	if (!name) {
		fc->req_part = NULL;
		*(fc->req_ptail) = r;
		fc->req_ptail = &r->next;
	} else if (strcasecmp(name, "Host") == 0) {
		if (r->host)
			free(r->host);
		pr_debug("host: %s\n", value);
		r->host = strdup(value);
	}
err:
	return;
}

struct patn_user {
	const struct timeval	*ts;
	struct ip		*ip;
	struct http_req		*r;
	struct flow_context	*fc;
};

static int log_keyword(const char *k, void *user)
{
	struct patn_user *pu = user;
	struct flow_context *fc = pu->fc;
	int r;

	r = log_write(pu->ts, pu->ip->ip_dst.s_addr,
			pu->ip->ip_src.s_addr, pu->r->host, pu->r->path, k);
	if (r < 0)
		return r;
	if (fc->snoopy->is_lazy) {
		flow_context_reset(fc);
		fc->stop_inspect = true;
		return 1;
	}

	return 0;
}

static void inspect_body(const unsigned char *data, int len, void *user)
{
	struct http_user *hu = user;
	struct flow_context *fc = hu->fc;
	struct http_req *r;

	if (!(r = fc->req_head))
		goto err;
	if (!data) {
		fc->req_head = r->next;
		if (!fc->req_head)
			fc->req_ptail = &fc->req_head;
		http_req_free(r);
		if (fc->sch_ctx)
			patn_sch_ctx_reset(fc->sch_ctx);
	} else {
		if (r->host && r->path) {
			struct patn_user pn = {
				.ts	= hu->ts,
				.ip	= hu->ip,
				.r	= r,
				.fc	= fc,
			};
			if (!fc->sch_ctx &&
			    !(fc->sch_ctx = patn_sch_ctx_alloc()))
				goto err;
#ifndef NDEBUG
			if (write(STDOUT_FILENO, data, len) != len)
				exit(EXIT_FAILURE);
#endif
			patn_sch(fc->snoopy->patn_list, fc->sch_ctx, data, len,
					log_keyword, &pn);
		}
	}
err:
	return;
}

int main(int argc, char *argv[])
{
	pcap_t *p;
	int o;
	const char *nic = NULL;
	const char *file = NULL;
	int snap_len = 0;
	char err_buf[PCAP_ERRBUF_SIZE];
	pcap_handler handler;
	struct snoopy_context ctx = { 0 };
	const char *rule_fn = SNOOPY_RULE_FN;
	const char *key_fn = SNOOPY_KEY_FN;
	const char *log_fn = SNOOPY_LOG_FN;
	bool background = false;

	/* parse the options */
	while ((o = getopt(argc, argv, "bhi:k:l:r:s:zR:")) != -1) {
		switch (o) {
		case 'b':
			background = true;
			break;
		case 'h':
			usage(stdout);
			goto out;
			break;
		case 'i':
			if (file || nic)
				die("FILE and NIC are exclusive\n");
			nic = optarg;
			break;
		case 'k':
			key_fn = optarg;
			break;
		case 'l':
			log_fn = optarg;
			break;
		case 'r':
			if (file || nic)
				die("FILE and NIC are exclusive\n");
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
	if (!file && !nic)
		die("FILE or NIC must be given\n");

	/* open the pcap handler */
	if (nic) {
		if (!snap_len) {
			snap_len = if_get_mtu(nic);
			if (snap_len < 0)
				die("failed to get the mtu of %s\n", nic);
			snap_len += sizeof(struct ether_header) +
					sizeof(struct vlan_hdr);
			printf("determined snap length: %d\n", snap_len);
		}
		err_buf[0] = '\0';
		p = pcap_open_live(nic, snap_len, 1, 1, err_buf);
		if (!p)
			die("failed to open %s: %s\n", nic, err_buf);
		if (err_buf[0] != '\0')
			printf("warning: %s\n", err_buf);
	} else {
		p = pcap_open_offline(file, err_buf);
		if (!p)
			die("failed to open %s: %s\n", file, err_buf);
	}

	/* set the filter if requested */
	if (optind < argc) {
		char buf[LINE_MAX];
		int len = 0, r;
		struct bpf_program fp;

		/* concat the remain arguments */
		while (optind < argc) {
			r = snprintf(buf + len, sizeof(buf) - len,
				     (len == 0) ? "%s" : " %s",
				     argv[optind++]);
			if (r < 0 || r >= sizeof(buf) - len)
				die("insufficent buffer for pcap-program\n");
			len += r;
		}
		if (pcap_compile(p, &fp, buf, 1, 0))
			die("failed to compile the pcap-program: %s\n",
			    pcap_geterr(p));
		if (pcap_setfilter(p, &fp))
			die("failed to set the bpf filer: %s\n",
			    pcap_geterr(p));
		pcap_freecode(&fp);
	}

	/* start the pcap loop */
	switch (pcap_datalink(p)) {
	case DLT_EN10MB:
		handler = ethernet_handler;
		break;
	default:
		die("unsupported datalnk: %s\n",
		    pcap_datalink_val_to_name(pcap_datalink(p)));
		break;
	}
	if (flow_init())
		die("failed to initialize flow service\n");
	if (log_open(log_fn))
		die("failed to open log file %s\n", log_fn);
	ctx.rule_list = rule_list_load(rule_fn);
	if (!ctx.rule_list)
		die("failed to load rules in %s\n", rule_fn);
	ctx.insp = http_inspector_alloc();
	if (!ctx.insp)
		die("failed to allocate a http inspector\n");
	if (http_inspector_add_request_line_handler(ctx.insp, save_path))
		die("failed to add the request line handler\n");
	if (http_inspector_add_request_header_field_handler(ctx.insp,
			save_host))
		die("failed to add the request header field handler\n");
	if (http_inspector_add_response_body_handler(ctx.insp, inspect_body))
		die("failed to add the response body handler\n");
	ctx.patn_list = patn_list_load(key_fn);
	if (!ctx.patn_list)
		die("failed to load keywords in %s\n", key_fn);
	if (background && daemon(0, 0))
		die("failed to become a background daemon\n");
	if (pcap_loop(p, -1, handler, (u_char *)&ctx) == -1)
		die("pcap_loop(3PCAP) exits with error: %s\n",
		    pcap_geterr(p));

	/* output the statistics if possible */
	if (nic) {
		struct pcap_stat st;

		if (pcap_stats(p, &st))
			die("failed to obtain the statistics: %s\n",
			    pcap_geterr(p));
		printf("received: %u\n", st.ps_recv);
		printf("dropped: %u\n", st.ps_drop);
	}

	/* close the pcap handler */
	pcap_close(p);
out:
	return EXIT_SUCCESS;
err:
	return EXIT_FAILURE;
}
