#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "conf.h"
#include "log.h"

#define CONF_LOGFILE 	"logfile:"
#define LOGFILE		"/var/log/SimpleDns.log"
#define CONFILE		"/etc/SimpleDns.conf"

env_t	env;


char *strget(char *string)
{
	char	*p = string;
	char	*q = NULL;
	while (*p == ' ' || *p == '\t') p++;
	q = p;
	while (*q != '\n' && *q != ' ' && *q != '\t' && *q != '\0') q++;
	*q = '\0';
	return p;
}


int env_parse_line(env_t *env, const char *line)
{
	char 		*p = (char *)line, *q = NULL; 
	char		*str = NULL, *pstr = NULL;
	char		buf[MAXLINE] = {0};
	char		tmp[MAXLINE] = {0};

	while (*p == ' ' || *p == '\t' ) p++;
	if (*p == '#' || *p == ';' || *p == '\n')
		return 0;

	p[strlen(p) - 1] = '\0';

	if (strncasecmp(p, CONF_LOGFILE, strlen(CONF_LOGFILE)) == 0)
	{
		p += strlen(CONF_LOGFILE);
		strcpy(env->logfile, strget(p));
	}
	return 0;
}

int env_init(env_t *env)
{
	FILE	*fp = NULL;
	char	buf[MAXLINE] = {0};
	memset(env, 0, sizeof(env_t));


	if ((fp = fopen(CONFILE, "r")) == NULL)
	{
		fprintf(stderr, "Load conf: %s %s", CONFILE, strerror(errno));
		return -1;
	}

	while (fgets(buf, MAXLINE, fp))
	{
		env_parse_line(env, buf);
		memset(buf, 0, MAXLINE);
	}
	fclose(fp);

	if (*env->logfile == '\0')
	{
		strcpy(env->logfile, LOGFILE);
	}

	log_init(env->logfile);

	return 0;
}

void env_clean(env_t *env)
{
	struct list_head        *pos  = NULL, *p = NULL;

}

void env_show(env_t *env)
{
	printf("--> %s\n", env->logfile);
}
