
#include "utils.h"
#include "types.h"
#include "buf.h"
#include "flow.h"
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

static void usage(FILE *out)
{
	fputs("Usage: snoopy [options] pcap-program\n", out);
	fputs("Options:\n", out);
	fputs("  -h       show this message\n", out);
	fputs("  -i NIC   specify the NIC interface\n", out);
	fputs("  -r FILE  specify the pcap file\n", out);
	fputs("  -s LEN   specify the snap length\n", out);
}

#define die(fmt, args...) \
do { \
	fprintf(stderr, fmt, ##args); \
	goto err; \
} while (0)

static void write_data(flow_t *f, bool is_clnt, const struct timeval *ts,
		const unsigned char *data, int line, void *user)
{
	if (!is_clnt)
		write(1, data, line);
}

void ethernet_handler(u_char *user, const struct pcap_pkthdr *h,
		      const u_char *bytes)
{
	struct ether_header *eth;
	struct ip *iph;
	struct tcphdr *tcph;
	int len, hl;

	if (h->caplen != h->len) {
		fprintf(stderr, "truncated packets\n");
		exit(EXIT_FAILURE);
	}
	len = h->len;

	/* ethernet */
	if (len < sizeof(*eth))
		goto err;
	eth = (struct ether_header *)bytes;
	if (ntohs(eth->ether_type) != ETHERTYPE_IP)
		goto err;
	bytes += sizeof(*eth);
	len -= sizeof(*eth);

	/* ip */
	if (len < sizeof(*iph))
		goto err;
	iph = (struct ip *)bytes;
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
	hl = tcph->th_off * 4;
	if (hl < sizeof(*tcph) || hl > len)
		goto err;
	bytes += hl;
	len -= hl;

	/* flow */
	flow_inspect(&h->ts, iph, tcph, bytes, len, write_data, NULL);
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

	/* parse the options */
	while ((o = getopt(argc, argv, "hi:r:s:")) != -1) {
		switch (o) {
		case 'h':
			usage(stdout);
			goto out;
			break;
		case 'i':
			if (file || nic)
				die("FILE and NIC are exclusive\n");
			nic = optarg;
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
			snap_len += 12 + 2 + 4;
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
	if (pcap_loop(p, -1, handler, NULL) == -1)
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
