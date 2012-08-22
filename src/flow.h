
#ifndef __FLOW_H
#define __FLOW_H

#include <netinet/ip.h>
#include <sys/time.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>

enum {
	PKT_DIR_C2S,
	PKT_DIR_S2C,
	PKT_DIR_NUM,
};

typedef struct flow flow_t;

int flow_add_tag(flow_t *f, int id, void *data, void (*free)(void *data));
void *flow_get_tag(flow_t *f, int id);
void flow_del_tag(flow_t *f, int id);

typedef void (*flow_data_handler)(flow_t *f, int dir,
		const struct timeval *ts, const unsigned char *data, int len,
		void *user);

int flow_init(void);
int flow_inspect(const struct timeval *ts, struct ip *ip, struct tcphdr *tcph,
		const unsigned char *data, int len, flow_data_handler h,
		void *user);

#endif /* __FLOW_H */
