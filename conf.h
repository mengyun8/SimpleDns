#ifndef __CONF_H
#define __CONF_H

#include "list.h"

#define 	IPLEN	16
#define		EXLINES	1024	
#define		MAXLINE 1024

typedef struct env_data_type {
	char		logfile[MAXLINE];
	FILE		*logfp;
	char		workdir[MAXLINE];
	unsigned int	daemon;
	/* distory */
	unsigned int	shutdown;
} env_t;

int  env_init(env_t *env);
void env_clean(env_t *env);
void env_show(env_t *env);

#endif
