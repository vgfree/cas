#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "cas_logger.h"

static CAS_LOGGER_IMPL g_logger_cb = NULL;
static short g_logger_lv = LOG_DEBUG;

#define MSGFMT_MAX 1024
#ifdef DEBUG
static int _default_logger_cb(short syslv, const char *func, const char *file, int line, const char *format, va_list ap)
{
	time_t now;
	time(&now);
	struct tm *tm = localtime(&now);
	char ts[64] = {};
	strftime(ts, sizeof(ts), "%Y-%m-%d_%H:%M:%S", tm);

	char _g_LogFmt[MSGFMT_MAX] = {};
	static char *_g_LogLvl[] = {"EMERG","ALERT","CRIT","ERROR","WARNING","NOTICE","INFO","DEBUG"};

	assert(syslv < (sizeof(_g_LogLvl) / sizeof(char *)));
	snprintf(_g_LogFmt, sizeof(_g_LogFmt), "%s|%s|%s()|%s:%4d|%s\n", ts, _g_LogLvl[syslv], func, file, line, format);
	return vdprintf(STDOUT_FILENO, _g_LogFmt, ap);
}
#else
static int _default_logger_cb(short syslv, const char *func, const char *file, int line, const char *format, va_list ap)
{
	char _g_LogFmt[MSGFMT_MAX] = {};

	snprintf(_g_LogFmt, sizeof(_g_LogFmt), "|%s()|%s:%4d|%s\n", func, file, line, format);
	vsyslog(syslv, _g_LogFmt, ap);
	return 0;
}
#endif

int cas_logger_printf(short syslv, const char *func, const char *file, int line, const char *format, ...)
{
	int ret = 0;

	if (syslv > g_logger_lv)
		return ret;

	va_list ap;

	va_start(ap, format);
	if (g_logger_cb) {
		ret = g_logger_cb(syslv, func, file, line, format, ap);
	} else {
		ret = _default_logger_cb(syslv, func, file, line, format, ap);
	}
	va_end(ap);

	return ret;
}

int cas_logger_vprintf(short syslv, const char *func, const char *file, int line, const char *format, va_list ap)
{
	int ret = 0;

	if (syslv > g_logger_lv)
		return ret;

	if (g_logger_cb) {
		ret = g_logger_cb(syslv, func, file, line, format, ap);
	} else {
		ret = _default_logger_cb(syslv, func, file, line, format, ap);
	}

	return ret;
}

int cas_logger_setup(CAS_LOGGER_IMPL lcb, short llv)
{
	g_logger_cb = lcb;
	g_logger_lv = llv;
	return 0;
}

