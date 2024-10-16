/*
* Copyright(c) 2012-2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#include <execinfo.h>
#include <syslog.h>
#include "ocf/ocf_logger.h"
#include "cas_cache.h"
#include "context.h"
#include "threads.h"

#include "volume/vol_blk_bottom.h"


#define CAS_LOG_RATELIMIT HZ * 5
/* High burst limit to ensure cache init logs are printed properly */

/* *** CONTEXT DATA OPERATIONS *** */
static void *xvalloc(size_t size)
{
        void    *ret = NULL;
        int     err = posix_memalign((void **)&ret, getpagesize(), size);

        if (unlikely(err)) {
                assert(0);
        }   

        memset(ret, 0, size);
        return ret;
}

ctx_data_t *cas_ctx_data_alloc(uint32_t pages)
{
	struct cas_data *data = env_malloc(sizeof(*data), 0);
	if (!data) {
		syslog(LOG_ERR, "Couldn't allocate ctx_data.\n");
		return NULL;
	}
	data->my_vec.iov_len = pages * PAGE_SIZE;
	data->my_vec.iov_base = env_malloc(pages * PAGE_SIZE, 0);
	if (!data->my_vec.iov_base) {
		env_free(data);
		syslog(LOG_ERR, "Couldn't allocate my_vec.\n");
		return NULL;
	}

	data->io_vec = data->my_vec;
	data->io_offset = 0;
	data->io_length = 0;
	return data;
}


/*
 *
 */
void cas_ctx_data_free(ctx_data_t *ctx_data)
{
	struct cas_data *data = ctx_data;

	if (!data)
		return;

	env_free(data->my_vec.iov_base);
	env_free(data);
}

static int _cas_ctx_data_mlock(ctx_data_t *ctx_data)
{
	return 0;
}

static void _cas_ctx_data_munlock(ctx_data_t *ctx_data)
{
}

void cas_ctx_data_secure_erase(ctx_data_t *ctx_data)
{
	struct cas_data *data = ctx_data;
	memset(data->io_vec.iov_base, 0, data->io_vec.iov_len);
}

/*
 *
 */
static uint32_t _cas_ctx_read_data(void *dst, ctx_data_t *src, uint32_t size)
{
	struct cas_data *data = src;

	memcpy(dst, data->io_vec.iov_base + data->io_offset, size);
        data->io_offset += size;

        return size;
}

/*
 *
 */
static uint32_t _cas_ctx_write_data(ctx_data_t *dst, const void *src, uint32_t size)
{
	struct cas_data *data = dst;

	memcpy(data->io_vec.iov_base + data->io_offset, src, size);
        data->io_offset += size;

        return size;
}

/*
 *
 */
static uint32_t _cas_ctx_zero_data(ctx_data_t *dst, uint32_t size)
{
	struct cas_data *data = dst;

	memset(data->io_vec.iov_base + data->io_offset, 0, size);
        data->io_offset += size;

        return size;
}

/*
 *
 */
static uint32_t _cas_ctx_seek_data(ctx_data_t *dst,
		ctx_data_seek_t seek, uint32_t offset)
{
	struct cas_data *data = dst;

	switch (seek) {
	case ctx_data_seek_begin:
		data->io_offset = offset;
		break;

	case ctx_data_seek_current:
		data->io_offset += offset;
		break;

	default:
		ENV_BUG();
		return 0;
	}

	return offset;
}

/*
 *
 */
static uint64_t _cas_ctx_data_copy(ctx_data_t *dst, ctx_data_t *src,
		uint64_t to, uint64_t from, uint64_t bytes)
{
	struct cas_data *data_src = src, *data_dst = dst;

        memcpy(data_dst->io_vec.iov_base + to, data_src->io_vec.iov_base + from, bytes);

        return bytes;
}

static int _cas_ctx_cleaner_init(ocf_cleaner_t c)
{
	ocf_cache_t cache = ocf_cleaner_get_cache(c);
	const char *cache_num = ocf_cache_get_name(cache) + 5;
	char name[48] = {};
	snprintf(name, sizeof(name), "cas_cleaner_%s", cache_num);

	return cleaner_thread_init(c, name);
}

static void _cas_ctx_cleaner_kick(ocf_cleaner_t c)
{
	cleaner_thread_kick(c);
}

static void _cas_ctx_cleaner_stop(ocf_cleaner_t c)
{
	cleaner_thread_stop(c);
}

static int _cas_ctx_logger_open(ocf_logger_t logger)
{
	ocf_logger_set_priv(logger, NULL);

	return 0;
}

static void _cas_ctx_logger_close(ocf_logger_t logger)
{
	void *priv = ocf_logger_get_priv(logger);
}

/*
 *
 */
static int _cas_ctx_logger_print(ocf_logger_t logger, ocf_logger_lvl_t lvl,
		const char *fmt, va_list args)
{
	static const int level[] =  {
		[log_emerg] = LOG_EMERG,
		[log_alert] = LOG_ALERT,
		[log_crit] = LOG_CRIT,
		[log_err] = LOG_ERR,
		[log_warn] = LOG_WARNING,
		[log_notice] = LOG_NOTICE,
		[log_info] = LOG_INFO,
		[log_debug] = LOG_DEBUG,
	};

	if (((unsigned)lvl) >= sizeof(level)/sizeof(level[0]))
		return -EINVAL;

	void *priv = ocf_logger_get_priv(logger);

	vsyslog(level[lvl], fmt, args);

	return 0;
}

#define CTX_LOG_TRACE_DEPTH	16
/*
 *
 */
static int _cas_ctx_logger_dump_stack(ocf_logger_t logger)
{
	void *trace[CTX_LOG_TRACE_DEPTH];
	int size = backtrace(trace, CTX_LOG_TRACE_DEPTH);
	char **messages = backtrace_symbols(trace, size);

	syslog(LOG_INFO, "[stack trace]>>>");
	int i;
	for (i = 0; i < size; ++i)
		syslog(LOG_INFO, "%s", messages[i]);
	syslog(LOG_INFO, "<<<[stack trace]");
	free(messages);

	return 0;
}

static const struct ocf_ctx_config ctx_cfg = {
	.name = "CAS Linux Kernel",
	.ops = {
		.data = {
			.alloc = cas_ctx_data_alloc,
			.free = cas_ctx_data_free,
			.mlock = _cas_ctx_data_mlock,
			.munlock = _cas_ctx_data_munlock,
			.read = _cas_ctx_read_data,
			.write = _cas_ctx_write_data,
			.zero = _cas_ctx_zero_data,
			.seek = _cas_ctx_seek_data,
			.copy = _cas_ctx_data_copy,
			.secure_erase = cas_ctx_data_secure_erase,
		},

		.cleaner = {
			.init = _cas_ctx_cleaner_init,
			.kick = _cas_ctx_cleaner_kick,
			.stop = _cas_ctx_cleaner_stop,
		},

		.logger = {
			.open = _cas_ctx_logger_open,
			.close = _cas_ctx_logger_close,
			.print = _cas_ctx_logger_print,
			.dump_stack = _cas_ctx_logger_dump_stack,
		},
	},
};

/* *** CONTEXT INITIALIZATION *** */

int cas_initialize_context(void)
{
	int ret;

	ret = ocf_ctx_create(&cas_ctx, &ctx_cfg);
	if (ret < 0)
		return ret;

	ret = load_btm_driver();
	if (ret) {
		syslog(LOG_ERR, "Cannot initialize block device layer\n");
		goto err_ctx;

	}

	return 0;

err_ctx:
	ocf_ctx_put(cas_ctx);

	return ret;
}

void cas_cleanup_context(void)
{
	ocf_ctx_put(cas_ctx);
}

