#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "conf.h"

void val_init(val_t *val)
{
	memset(val, 0, sizeof(val_t));
	val->next = NULL;
}

int val_insert(val_t *head, const char *msg)
{
	val_t 	*p = head;

	if (!msg || strcmp(msg, "\n") == 0 || *msg == '\0')
		return -1;
	
	while (p->next) 
	{
		p = p->next;
	}
	p->next =  malloc(sizeof(val_t));
	p = p->next;

	memset(p, 0, sizeof(val_t));
	strcpy(p->val, msg);
	p->next = NULL;
	return 0;
}

void val_print(val_t *head)
{
	int 	i = 0;
	val_t 	*p = head->next;
	while (p) {
		printf("debug--%d--[%s]\n", i++, p->val);
		p = p->next;
	}
}

int val_free(val_t *head) 
{
	val_t 	*tmp = NULL;
	val_t	*p = head;

	if (!p)
		return -1;

	while (p->next) {
		tmp = p->next;
		p->next = p->next->next;
		free(tmp);
	}
	head->next = NULL;
	return 0;
}

/* Return parse line len */
int buffer_get_key(const char *confbuf, val_t *val)
{
	int	len = 0;
	char 	*start = NULL;
	char 	*end = NULL;
	char	*p = (char *)confbuf;
	char	buffer[MAXLINE] = {0};

	while (*p != '\n' && *p != '\0')
	{
		memset(buffer, 0, sizeof(buffer));
		while (*p == ' ' || *p == '\t' || *p == '\r') p++;
		if (*p == '\n' || *p == ';' || *p == '#' || *p == '\0')
			return 0;
		
		start = p;
		while (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n' && *p != '\0') p++;
		end = p;
		strncpy(buffer, start, end - start);
		val_insert(val, buffer);
		len ++;
	}
	return len;
}

