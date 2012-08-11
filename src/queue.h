
#ifndef __QUEUE_H
#define __QUEUE_H

typedef struct queue queue_t;

queue_t *queue_alloc(void);
void queue_free(queue_t *q);
int queue_add(queue_t *q, void *data);
void *queue_del(queue_t *q);

#endif /* __QUEUE_H */
