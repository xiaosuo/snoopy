
#ifndef __RULE_H
#define __RULE_H

#include "types.h"
#include <stdbool.h>

typedef struct rule_list rule_list_t;

rule_list_t *rule_list_load(const char *fn);
bool rule_list_match(rule_list_t *l, be32_t _ip, be16_t _port);
void rule_list_free(rule_list_t *l);
int rule_list_dump(rule_list_t *l, const char *fn);

#endif /* __RULE_H */
