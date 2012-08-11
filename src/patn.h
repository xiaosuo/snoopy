
#ifndef __PATN_H
#define __PATN_H

typedef struct patn_list patn_list_t;
typedef struct patn_sch_ctx patn_sch_ctx_t;

patn_list_t *patn_list_load(const char *fn);
void patn_list_free(patn_list_t *l);

patn_sch_ctx_t *patn_sch_ctx_alloc(void);
void patn_sch_ctx_free(patn_sch_ctx_t *ctx);
void patn_sch_ctx_reset(patn_sch_ctx_t *c);
int patn_sch(patn_list_t *l, patn_sch_ctx_t *c, const unsigned char *buf,
	     int len, int (*cb)(const char *patn, void *data), void *data);

#endif /* __PATN_H */
