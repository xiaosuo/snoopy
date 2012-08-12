
#include "utils.h"
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <pcap/pcap.h>

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

struct snoopy_ctx {
	pcap_t	*p;
	int	n;
};

void em10mb_handler(u_char *user, const struct pcap_pkthdr *h,
		    const u_char *bytes)
{
	struct snoopy_ctx *c = (struct snoopy_ctx *)user;

	printf("got one pkt\n");
	if (++(c->n) == 10)
		pcap_breakloop(c->p);
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
	struct snoopy_ctx ctx;

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
		handler = em10mb_handler;
		break;
	default:
		die("unsupported datalnk: %s\n",
		    pcap_datalink_val_to_name(pcap_datalink(p)));
		break;
	}
	ctx.p = p;
	ctx.n = 0;
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
