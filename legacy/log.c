#include<stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#define MAXLINE	1024

#define LOGLINE	(16 * MAXLINE)

char level[4][2] = {"I","D","W","E"};

FILE	*log_fp = NULL;

/* Init Log */
int log_init(const char *file)
{
	log_fp = fopen(file, "a+");
	if (!log_fp)
		return -1;
	return 0;
}

/* Log info of dns manage */
int log_info(const char *fmt, ...)
{
	time_t timep;
  	struct tm *p;
	char msg[LOGLINE] = {0};
	va_list arg;

	va_start(arg, fmt);
	vsnprintf(msg, LOGLINE, fmt, arg);
	va_end(arg);

	time (&timep);
	p = localtime (&timep);
	if (!log_fp)
		return -1;

	fprintf(log_fp, "%d/%d/%d %d:%d:%d [I] %s\n", (p->tm_year + 1900), (p->tm_mon + 1), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, msg);
	fflush(log_fp);
	return 0;
}

/* Log error of dns manage */
int log_error(const char *fmt, ...)
{
	time_t timep;
  	struct tm *p;
	char msg[LOGLINE] = {0};
	va_list arg;

	va_start(arg, fmt);
	vsnprintf(msg, LOGLINE, fmt, arg);
	va_end(arg);

	time (&timep);
	p = localtime (&timep);

	if (!log_fp)
		return -1;
	fprintf(log_fp, "%d/%d/%d %d:%d:%d [E] %s\n", (p->tm_year + 1900), (p->tm_mon + 1), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, msg);
	fflush(log_fp);
	return 0;
}
