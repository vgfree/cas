#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

#if defined(__LINUX__) || defined(__linux__)
  #include <syslog.h>
#else
  #define LOG_EMERG     0	/* system is unusable */
  #define LOG_ALERT     1	/* action must be taken immediately */
  #define LOG_CRIT      2	/* critical conditions */
  #define LOG_ERR       3	/* error conditions */
  #define LOG_WARNING   4	/* warning conditions */
  #define LOG_NOTICE    5	/* normal but significant condition */
  #define LOG_INFO      6	/* informational */
  #define LOG_DEBUG     7	/* debug-level messages */
#endif

#if !defined(LOCAL)
  #define __LOCAL(var, line)    __ ## var ## line
  #define _LOCAL(var, line)     __LOCAL(var, line)
  #define LOCAL(var)            _LOCAL(var, __LINE__)
#endif

#ifndef __FILENAME__
  #define __FILENAME__ ({ const char *LOCAL(p) = strrchr(__FILE__, '/'); LOCAL(p) ? LOCAL(p) + 1 : __FILE__; })
#endif

typedef int (*CAS_LOGGER_IMPL)(short syslv, const char *func, const char *file, int line, const char *format, va_list ap);

int cas_logger_setup(CAS_LOGGER_IMPL lcb, short llv);

int cas_logger_printf(short syslv, const char *func, const char *file, int line, const char *format, ...);

#define cas_printf(syslv, fmt, ...) \
	cas_logger_printf(syslv, __FUNCTION__, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__)

int cas_logger_vprintf(short syslv, const char *func, const char *file, int line, const char *format, va_list ap);

#define cas_vprintf(syslv, fmt, ap) \
	cas_logger_vprintf(syslv, __FUNCTION__, __FILENAME__, __LINE__, fmt, ap)

