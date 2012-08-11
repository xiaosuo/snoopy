
#include "rule.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

void rule_list_init(struct rule_list *l)
{
	l->first = NULL;
	l->ptail = &l->first;
}

static int rule_parse_port_rule(struct rule *r, char *line)
{
	char *ptr = strchr(line, '-');

	if (ptr) {
		*ptr++ = '\0';
		r->start_port = atoi(line);
		r->end_port = atoi(ptr);
		if (r->start_port > r->end_port)
			return -1;
	} else {
		r->end_port = r->start_port = atoi(line);
	}

	return 0;
}

static int rule_parse_ip(uint32_t *ip, char *line)
{
	if (!inet_pton(AF_INET, line, ip))
		return -1;
	*ip = ntohl(*ip);

	return 0;
}

static int rule_parse_ip_rule(struct rule *r, char *line)
{
	char *ptr = strchr(line, '/');

	if (ptr) {
		uint32_t net;
		uint32_t mask;
		int plen;

		*ptr++ = '\0';
		if (rule_parse_ip(&net, line))
			goto err;
		plen = atoi(ptr);
		if (plen < 0 || plen > 32)
			goto err;
		if (plen == 0)
			mask = 0;
		else
			mask = ~((1u << (32 - plen)) - 1);
		r->start_ip = net & mask;
		r->end_ip = r->start_ip | (~mask);
	} else if ((ptr = strchr(line, '-'))) {
		*ptr++ = '\0';
		if (rule_parse_ip(&r->start_ip, line) ||
		    rule_parse_ip(&r->end_ip, ptr) ||
		    r->start_ip > r->end_ip)
			goto err;
	} else {
		if (rule_parse_ip(&r->start_ip, line))
			goto err;
		r->end_ip = r->start_ip;
	}

	return 0;
err:
	return -1;
}

static struct rule *rule_parse(char *line)
{
	struct rule *r = malloc(sizeof(*r));
	char *ptr;

	if (!r)
		goto err;
	ptr = strchr(line, ':');
	if (!ptr)
		goto err2;
	*ptr++ = '\0';
	if (rule_parse_ip_rule(r, line) || rule_parse_port_rule(r, ptr))
		goto err2;

	return r;
err2:
	free(r);
err:
	return NULL;
}

int rule_list_load(struct rule_list *l, const char *fn)
{
	FILE *fp = fopen(fn, "r");
	char buf[LINE_MAX];

	assert(l->first == NULL);
	if (!fp)
		goto err;
	while (fgets(buf, sizeof(buf), fp)) {
		struct rule *r;
		int n = strspn(buf, " \t\n");

		/* skip empty lines */
		if (buf[n] == '\0')
			continue;
		r = rule_parse(buf + n);
		if (!r)
			goto err2;
		r->next = NULL;
		*(l->ptail) = r;
		l->ptail = &r->next;
	}
	if (!feof(fp) || ferror(fp))
		goto err2;
	fclose(fp);

	return 0;
err2:
	fclose(fp);
err:
	return -1;
}

bool rule_list_match(struct rule_list *h, be32_t _ip, be16_t _port)
{
	struct rule *r;
	uint32_t ip = ntohl(_ip);
	uint16_t port = ntohs(_port);

	for (r = h->first; r; r = r->next) {
		if (ip >= r->start_ip && ip <= r->end_ip &&
		    port >= r->start_port && port <= r->end_port)
			return true;
	}

	return false;
}

void rule_list_free(struct rule_list *h)
{
	struct rule *r;

	while ((r = h->first) != NULL) {
		h->first = r->next;
		free(r);
	}
	h->ptail = &h->first;
}

int rule_list_dump(struct rule_list *l, const char *fn)
{
	const struct rule *r;
	FILE *fp = fopen(fn, "w");

	if (!fp)
		goto err;
	for (r = l->first; r; r = r->next) {
		be32_t ip;
		char start[INET_ADDRSTRLEN];
		char end[INET_ADDRSTRLEN];

		ip = htonl(r->start_ip);
		inet_ntop(AF_INET, &ip, start, INET_ADDRSTRLEN);
		ip = htonl(r->end_ip);
		inet_ntop(AF_INET, &ip, end, INET_ADDRSTRLEN);
		fprintf(fp, "%s-%s:%hd-%hu\n", start, end, r->start_port,
			r->end_port);
	}
	fclose(fp);

	return 0;
err:
	return -1;
}

#ifdef TEST
int main(void)
{
	struct rule_list l;

	rule_list_init(&l);
	assert(rule_list_load(&l, "../test/rules.conf") == 0);
	assert(rule_list_dump(&l, "rules.conf") == 0);
	assert(rule_list_match(&l, inet_addr("192.168.1.2"), htons(80)));
	rule_list_free(&l);
}
#endif
