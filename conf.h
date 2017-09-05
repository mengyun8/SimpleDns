#ifndef __CONF_H
#define __CONF_H

#define MAXLINE		1024

typedef struct value_t val_t;

struct value_t {
	char 	val[MAXLINE];
	struct value_t *next;
};

void val_init(val_t *val);
int  val_insert(val_t *head, const char *msg);
void val_print(val_t *head);
int  val_free(val_t *head);
int  buffer_get_key(const char *confbuf, val_t *val);
#endif
