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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

static void usage(void)
{
	puts("Usage: eth2raw input output");
	exit(EXIT_FAILURE);
}

#define die(fmt, args...) \
do { \
	fprintf(stderr, fmt, ##args); \
	exit(EXIT_FAILURE); \
} while (0)

struct my_pcap_pkthdr {
	uint32_t	sec;
	uint32_t	usec;
	uint32_t	caplen;
	uint32_t	len;
};

static void dump_in_raw(u_char *user, const struct pcap_pkthdr *h,
		const u_char *bytes)
{
	FILE *fp = (FILE *)user;
	struct ether_header *eth;
	struct my_pcap_pkthdr ph;

	if (h->caplen < sizeof(*eth))
		return;
	eth = (struct ether_header *)bytes;
	if (ntohs(eth->ether_type) != ETHERTYPE_IP)
		return;
	ph.sec = h->ts.tv_sec;
	ph.usec = h->ts.tv_usec;
	ph.len = h->len - sizeof(*eth);
	ph.caplen = h->caplen - sizeof(*eth);
	printf("%u\n", ph.caplen);
	if (fwrite(&ph, sizeof(ph), 1, fp) != 1 ||
	    (ph.caplen > 0 &&
	     fwrite(bytes + sizeof(*eth), ph.caplen, 1, fp) != 1))
		die("failed to dump\n");
}

static uint16_t my_bswap16(uint16_t v)
{
	uint8_t t;
	uint8_t *p = (uint8_t *)&v;

	t = p[0];
	p[0] = p[1];
	p[1] = t;

	return v;
}

int main(int argc, char *argv[])
{
	pcap_t *in;
	char err_buf[PCAP_ERRBUF_SIZE];
	FILE *fp;
	struct pcap_file_header fh;

	if (argc != 3)
		usage();

	in = pcap_open_offline(argv[1], err_buf);
	if (!in)
		die("failed to open %s: %s\n", argv[1], err_buf);
	if (pcap_datalink(in) != DLT_EN10MB)
		die("%s's data linktype is not ethernet\n", argv[1]);

	fp = fopen(argv[1], "r");
	if (!fp)
		die("failed to open %s\n", argv[1]);
	if (fread(&fh, sizeof(fh), 1, fp) != 1)
		die("failed to read %s\n", argv[1]);
	fclose(fp);
#ifndef LINKTYPE_RAW
#define LINKTYPE_RAW 101
#endif
	if (fh.magic != 0xa1b2c3d4) {
		if (fh.magic != 0xd4c3b2a1)
			die("%s isn't a pcap file\n", argv[1]);
		fh.magic = __builtin_bswap32(fh.magic);
		fh.version_major = my_bswap16(fh.version_major);
		fh.version_minor = my_bswap16(fh.version_minor);
		fh.thiszone = __builtin_bswap32(fh.thiszone);
		fh.sigfigs = __builtin_bswap32(fh.sigfigs);
		fh.snaplen = __builtin_bswap32(fh.snaplen);
		fh.linktype = __builtin_bswap32(fh.linktype);
	}
	fh.linktype = LINKTYPE_RAW;

	fp = fopen(argv[2], "w");
	if (!fp)
		die("failed to open %s\n", argv[2]);
	if (fwrite(&fh, sizeof(fh), 1, fp) != 1)
		die("failed to write %s\n", argv[2]);

	if (pcap_loop(in, -1, dump_in_raw, (u_char *)fp) == -1)
		die("failed to read %s\n", argv[1]);
	pcap_close(in);
	fclose(fp);

	return EXIT_SUCCESS;
}
