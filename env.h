#ifndef __ENV_H
#define __ENV_H

#include "list.h"
#include "Dns.h"

#define 	IPLEN	16
#define		EXLINES	1024	
#define		MAXLINE 1024

int  env_init(env_t *env);
void env_clean(env_t *env);
void env_show(env_t *env);


#endif
