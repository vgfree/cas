/*
 * Copyright(c) 2012-2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __CAS_CACHE_H__
#define __CAS_CACHE_H__

#include "ocf/ocf.h"
#include "ocf/env/ocf_env.h"

#include <cas_ioctl_codes.h>

#include "control.h"
#include "layer_cache_management.h"
#include "service_ui_ioctl.h"
#include "volume/vol_blk_utils.h"
#include "classifier.h"
#include "context.h"

#define CAS_KERN_EMERG KERN_EMERG OCF_PREFIX_SHORT
#define CAS_KERN_ALERT KERN_ALERT OCF_PREFIX_SHORT
#define CAS_KERN_CRIT KERN_CRIT OCF_PREFIX_SHORT
#define CAS_KERN_ERR KERN_ERR OCF_PREFIX_SHORT
#define CAS_KERN_WARNING KERN_WARNING OCF_PREFIX_SHORT
#define CAS_KERN_NOTICE KERN_NOTICE OCF_PREFIX_SHORT
#define CAS_KERN_INFO KERN_INFO OCF_PREFIX_SHORT
#define CAS_KERN_DEBUG KERN_DEBUG OCF_PREFIX_SHORT

#define MAX_LINES_PER_IO	16

struct cas_classifier;

struct cache_priv {
	uint64_t core_id_bitmap[DIV_ROUND_UP(OCF_CORE_MAX, 8*sizeof(uint64_t))];
	struct cas_classifier *classifier;
	struct _cache_mngt_stop_context *stop_context;
	env_atomic flush_interrupt_enabled;
	ocf_queue_t mngt_queue;
	void *attach_context;
	bool cache_exported_object_initialized;
	struct {
		ocf_queue_t worker_queue;
		ocf_queue_t porter_queue;
	} queues[];
};

extern ocf_ctx_t cas_ctx;

static inline void cache_name_from_id(char *name, uint32_t id)
{
	int result;

	result = snprintf(name, OCF_CACHE_NAME_SIZE, "cache%"PRIu32, id);
	ENV_BUG_ON(result >= OCF_CACHE_NAME_SIZE);
}

static inline void core_name_from_id(char *name, uint16_t id)
{
	int result;

	result = snprintf(name, OCF_CORE_NAME_SIZE, "core%d", id);
	ENV_BUG_ON(result >= OCF_CORE_NAME_SIZE);
}

static inline int cache_id_from_name(uint32_t *cache_id, const char *name)
{
	const char *id_str;
	char *endptr;
	unsigned long res;

	if (strnlen(name, OCF_CACHE_NAME_SIZE) < sizeof("cache") - 1)
		return -EINVAL;

	id_str = name + sizeof("cache") - 1;

	res = strtoul(id_str, &endptr, 10);

	if (id_str == endptr)
		return -EINVAL;

	*cache_id = res;
	return 0;
}

static inline int core_id_from_name(uint16_t *core_id, const char *name)
{
	const char *id_str;
	char *endptr;
	long res;

	if (strnlen(name, OCF_CORE_NAME_SIZE) < sizeof("core") - 1)
		return -EINVAL;

	id_str = name + sizeof("core") - 1;

	res = strtol(id_str, &endptr, 10);

	if (id_str == endptr)
		return -EINVAL;

	*core_id = res;
	return 0;
}

static inline int mngt_get_cache_by_id(ocf_ctx_t ctx, uint32_t id,
		ocf_cache_t *cache)
{
	char cache_name[OCF_CACHE_NAME_SIZE];

	cache_name_from_id(cache_name, id);

	return ocf_mngt_cache_get_by_name(ctx, cache_name,
					OCF_CACHE_NAME_SIZE, cache);
}

static inline int get_core_by_id(ocf_cache_t cache, uint16_t id,
		ocf_core_t *core)
{
	char core_name[OCF_CORE_NAME_SIZE];

	core_name_from_id(core_name, id);

	return ocf_core_get_by_name(cache, core_name, OCF_CORE_NAME_SIZE, core);
}


#endif
