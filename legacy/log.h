#ifndef __LOG_H
#define __LOG_H

enum LEVET{
	LOG_INFO,
	LOG_WARN,
	LOG_ERR,
};

extern FILE     *log_fp;

#define log(level, format, args...) do{if(level == LOG_INFO){log_info("[%s:%d] "format, __func__, __LINE__,##args);}else{log_error("[%s:%d] "format, __func__, __LINE__,##args);}}while(0)

int log_init(const char *file);
int log_info(const char *fmt, ...);
int log_error(const char *fmt, ...);

#endif
