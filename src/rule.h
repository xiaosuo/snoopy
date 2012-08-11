
#ifndef __RULE_H
#define __RULE_H

#include "types.h"
#include <stdbool.h>

struct rule {
	uint32_t	start_ip;
	uint32_t	end_ip;
	uint16_t	start_port;
	uint16_t	end_port;
	struct rule	*next;
};

struct rule_list {
	struct rule	*first;
	struct rule	**ptail;
};

void rule_list_init(struct rule_list *l);
int rule_list_load(struct rule_list *l, const char *fn);
bool rule_list_match(struct rule_list *l, be32_t _ip, be16_t _port);
void rule_list_free(struct rule_list *l);
int rule_list_dump(struct rule_list *l, const char *fn);

#endif /* __RULE_H */
