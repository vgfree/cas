/*
* Copyright(c) 2012-2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#include "volume/vol_blk_utils.h"
#include "volume/vol_blk_top.h"
#include "cas_logger.h"
#include "context.h"
#include "cas_cache.h"
#include "task_inflight.h"

#define MAX_CAS_LOCK_MAP	1024

/* Layer information. */
uint32_t max_writeback_queue_size = 65536;
//"Max cache writeback queue size (65536)"

uint32_t writeback_queue_unblock_size = 60000;
//"Cache writeback queue size (60000) at which queue is unblocked when blocked"

uint32_t use_io_scheduler = 1;
//"Configure how IO shall be handled. 0 - in make request function, 1 - in request function"

uint32_t unaligned_io = 1;
//"Define how to handle I/O requests unaligned to 4 kiB, 0 - apply PT, 1 - handle by cache"

uint32_t seq_cut_off_mb = 1;
//"Sequential cut off threshold in MiB. 0 - disable"

/* globals */
ocf_ctx_t cas_ctx;

env_rwlock g_cas_lock_map[MAX_CAS_LOCK_MAP];

struct task_inflight_info g_load_inflight_info;

static inline bool cache_load_overlap(struct task_inflight_node *a, struct task_inflight_node *b)
{
	return (a->data == b->data);
}


int cas_init_module(void)
{
	int result = 0;

	if (!writeback_queue_unblock_size || !max_writeback_queue_size) {
		cas_printf(LOG_ERR, OCF_PREFIX_SHORT
				"Invalid module parameter.\n");
		return -EINVAL;
	}

	if (writeback_queue_unblock_size >= max_writeback_queue_size) {
		cas_printf(LOG_ERR, OCF_PREFIX_SHORT
				"parameter writeback_queue_unblock_size"
				" must be less than max_writeback_queue_size\n");
		return -EINVAL;
	}

	if (unaligned_io != 0 && unaligned_io != 1) {
		cas_printf(LOG_ERR, OCF_PREFIX_SHORT
				"Invalid value for unaligned_io parameter\n");
		return -EINVAL;
	}

	if (use_io_scheduler != 0 && use_io_scheduler != 1) {
		cas_printf(LOG_ERR, OCF_PREFIX_SHORT
				"Invalid value for use_io_scheduler parameter\n");
		return -EINVAL;
	}

	result = cas_initialize_context();
	if (result) {
		cas_printf(LOG_ERR, OCF_PREFIX_SHORT
				"Cannot initialize cache library\n");
		return result;
	}

	result = cas_ctrl_init();
	if (result) {
		cas_printf(LOG_ERR, OCF_PREFIX_SHORT
				"Cannot initialize control device\n");
		goto error_init_ctrl;
	}

	task_inflight_init(&g_load_inflight_info, cache_load_overlap);
	for (int i = 0; i < MAX_CAS_LOCK_MAP; i++) {
		env_rwlock_init(&g_cas_lock_map[i]);
	}

	cas_printf(LOG_INFO, "%s Version %s loaded successfully\n",
		OCF_PREFIX_LONG, CAS_VERSION);

	return 0;

error_init_ctrl:
	cas_cleanup_context();

	return result;
}

void cas_exit_module(void)
{
	cas_ctrl_deinit();
	cas_cleanup_context();
	task_inflight_destroy(&g_load_inflight_info);
	for (int i = 0; i < MAX_CAS_LOCK_MAP; i++) {
		env_rwlock_destroy(&g_cas_lock_map[i]);
	}
}

extern int cache_mngt_lock_sync(ocf_cache_t cache);

static struct vb_object *_lookup_vb_obj(uint32_t cache_id, uint16_t core_id)
{
	ocf_cache_t cache;
	ocf_core_t core;

	int result = mngt_get_cache_by_id(cas_ctx, cache_id, &cache);
	if (result)
		return NULL;

	result = cache_mngt_lock_sync(cache);
	if (result) {
		ocf_mngt_cache_put(cache);
		return NULL;
	}

	result = get_core_by_id(cache, core_id, &core);
	if (result) {
		ocf_mngt_cache_unlock(cache);
		ocf_mngt_cache_put(cache);
		return NULL;
	}

	ocf_volume_t volume = ocf_core_get_volume(core);
	struct vb_object *obj = cas_volume_get_vb_object(volume);

	ocf_mngt_cache_unlock(cache);
	ocf_mngt_cache_put(cache);
	return obj;
}

bool cas_lookup_vb_obj(uint32_t cache_id, uint16_t core_id)
{
	struct vb_object *obj = _lookup_vb_obj(cache_id, core_id);
	return !!obj;
}

int cas_submit_vb_aio(uint32_t cache_id, uint16_t core_id, struct cas_aio *aio)
{
	int idx = cache_id % MAX_CAS_LOCK_MAP;
	env_rwlock_read_lock(&g_cas_lock_map[idx]);
	struct vb_object *obj = _lookup_vb_obj(cache_id, core_id);
	int ret = cas_top_obj_submit_aio(obj, aio);
	env_rwlock_read_unlock(&g_cas_lock_map[idx]);
	return ret;
}

uint64_t cas_obtain_vb_len(uint32_t cache_id, uint16_t core_id)
{
	uint64_t length = 0;
	int idx = cache_id % MAX_CAS_LOCK_MAP;
	env_rwlock_read_lock(&g_cas_lock_map[idx]);
	struct vb_object *obj = _lookup_vb_obj(cache_id, core_id);
	if (obj)
		length = obj->top_obj->length;
	env_rwlock_read_unlock(&g_cas_lock_map[idx]);
	return length;
}

struct name_to_val_mapping {
	const char* short_name;
	const char* long_name;
	int value;
};

static struct name_to_val_mapping cache_mode_names[] = {
	{ .short_name = "wt", .long_name = "Write-Through", .value = ocf_cache_mode_wt },
	{ .short_name = "wb", .long_name = "Write-Back", .value = ocf_cache_mode_wb },
	{ .short_name = "wf", .long_name = "Write-Force", .value = ocf_cache_mode_wf },
	{ .short_name = "wa", .long_name = "Write-Around", .value = ocf_cache_mode_wa },
	{ .short_name = "pt", .long_name = "Pass-Through", .value = ocf_cache_mode_pt },
#ifdef WI_AVAILABLE
	{ .short_name = "wi", .long_name = "Write-Invalidate", .value = ocf_cache_mode_wi },
#endif
	{ .short_name = "wo", .long_name = "Write-Only", .value = ocf_cache_mode_wo },
	{ NULL }
};

static int validate_str_val_mapping(const char* s,
				    const struct name_to_val_mapping* mappings,
				    int invalid_value)
{
	int i;

	if (!s || !strlen(s)) {
		return invalid_value;
	}

	for (i = 0; NULL != mappings[i].short_name; ++i) {
		if (0 == strncmp(mappings[i].short_name, s, MAX_STR_LEN)) {
			return mappings[i].value;
		}
	}

	return invalid_value;
}

int cas_format_cache(uint32_t cache_id, char *path, uint16_t line_shift, char *mode_name)
{
	int cache_mode = validate_str_val_mapping(mode_name, cache_mode_names, -1);
	if (cache_mode < 0)
		return -OCF_ERR_INVAL;

	struct kcas_start_cache cmd_info = {};
	struct ocf_mngt_cache_config cfg;
	struct ocf_mngt_cache_attach_config attach_cfg;

	snprintf(cmd_info.cache_path_name, sizeof(cmd_info.cache_path_name), "%s", path);
	cmd_info.caching_mode = cache_mode;
	cmd_info.init_cache = CACHE_INIT_NEW;
	cmd_info.cache_id = cache_id;
	cmd_info.force = 1;
	cmd_info.line_size = 1ULL << line_shift;

	int ret = cache_mngt_create_cache_cfg(&cfg, &attach_cfg, &cmd_info);
	if (!ret) {
		ret = cache_mngt_init_instance(&cfg, &attach_cfg, &cmd_info);
	}
	return ret;
}

int cas_append_core_to_cache(uint32_t cache_id, uint16_t core_id, char *path)
{
	struct kcas_insert_core cmd_info = {};
	struct ocf_mngt_core_config cfg;
	char cache_name[OCF_CACHE_NAME_SIZE];

	if (core_id > OCF_CORE_ID_MAX)
		return -EINVAL;
	snprintf(cmd_info.core_path_name, sizeof(cmd_info.core_path_name), "%s", path);
	cmd_info.cache_id = cache_id;
	cmd_info.core_id = core_id;

	cache_name_from_id(cache_name, cmd_info.cache_id);

	int ret = cache_mngt_prepare_core_cfg(&cfg, &cmd_info);
	if (!ret) {
		ret = cache_mngt_add_core_to_cache(cache_name,
				OCF_CACHE_NAME_SIZE, &cfg, &cmd_info);
	}
	return ret;
}

int cas_cache_add_core(uint32_t cache_id, uint16_t *core_id, char *path)
{
	struct kcas_insert_core cmd_info = {};
	struct ocf_mngt_core_config cfg;
	char cache_name[OCF_CACHE_NAME_SIZE];

	snprintf(cmd_info.core_path_name, sizeof(cmd_info.core_path_name), "%s", path);
	cmd_info.cache_id = cache_id;
	cmd_info.core_id = OCF_CORE_MAX;

	cache_name_from_id(cache_name, cmd_info.cache_id);

	int ret = cache_mngt_prepare_core_cfg(&cfg, &cmd_info);
	if (!ret) {
		ret = cache_mngt_add_core_to_cache(cache_name,
				OCF_CACHE_NAME_SIZE, &cfg, &cmd_info);
		if (ret == -OCF_ERR_CORE_UUID_EXISTS) {
			ret = 0;
		}
		if (!ret) {
			*core_id = cmd_info.core_id;
		}
	}
	return ret;
}

int cas_cache_del_core(uint32_t cache_id, uint16_t core_id, uint8_t flush_data)
{
	struct kcas_remove_core cmd_info = {};
	cmd_info.cache_id = cache_id;
	cmd_info.core_id = core_id;
	cmd_info.force_no_flush = flush_data;
	cmd_info.detach = false;

	int ret = cache_mngt_remove_core_from_cache(&cmd_info);
	return ret;
}

int cas_stop_cache(uint32_t cache_id, uint8_t flush_data)
{
	char cache_name[OCF_CACHE_NAME_SIZE];

	cache_name_from_id(cache_name, cache_id);

	int idx = cache_id % MAX_CAS_LOCK_MAP;
	env_rwlock_write_lock(&g_cas_lock_map[idx]);
	int ret = cache_mngt_exit_instance(cache_name, OCF_CACHE_NAME_SIZE, flush_data);
	if (ret == -OCF_ERR_CACHE_NOT_EXIST)
		ret = 0;
	env_rwlock_write_unlock(&g_cas_lock_map[idx]);
	return ret;
}

static int apply_load_cache(char *path)
{
	struct kcas_start_cache cmd_info = {};
	struct ocf_mngt_cache_config cfg;
	struct ocf_mngt_cache_attach_config attach_cfg;

	snprintf(cmd_info.cache_path_name, sizeof(cmd_info.cache_path_name), "%s", path);
	cmd_info.caching_mode = ocf_cache_mode_none;
	cmd_info.init_cache = CACHE_INIT_LOAD;
	cmd_info.cache_id = OCF_CACHE_ID_INVALID;
	cmd_info.force = 0;
	cmd_info.line_size = ocf_cache_line_size_none;

	int ret = cache_mngt_create_cache_cfg(&cfg, &attach_cfg, &cmd_info);
	if (!ret) {
		ret = cache_mngt_init_instance(&cfg, &attach_cfg, &cmd_info);
	}
	return ret;
}

int cas_load_cache(uint32_t cache_id, char *path)
{
	struct task_inflight_node my = {};
	my.data = (void *)(uintptr_t)cache_id;

	task_inflight_block(&g_load_inflight_info, &my);

	int idx = cache_id % MAX_CAS_LOCK_MAP;
	env_rwlock_write_lock(&g_cas_lock_map[idx]);

	ocf_cache_t cache;
	int result = mngt_get_cache_by_id(cas_ctx, cache_id, &cache);
	if (result)
		result = apply_load_cache(path);
	else
		ocf_mngt_cache_put(cache);

	env_rwlock_write_unlock(&g_cas_lock_map[idx]);

	task_inflight_wakeup(&g_load_inflight_info, &my);

	return result;
}

int cas_resume_cache(uint32_t cache_id)
{
	ocf_cache_t cache;

	int idx = cache_id % MAX_CAS_LOCK_MAP;
	env_rwlock_write_lock(&g_cas_lock_map[idx]);

	int result = mngt_get_cache_by_id(cas_ctx, cache_id, &cache);
	if (result)
		goto out;

	result = cache_mngt_lock_sync(cache);
	if (result) {
		ocf_mngt_cache_put(cache);
		goto out;
	}

	ocf_metadata_error_resume(cache);

	ocf_mngt_cache_unlock(cache);
	ocf_mngt_cache_put(cache);

out:
	env_rwlock_write_unlock(&g_cas_lock_map[idx]);
	return result;
}

int cas_hook_cache_submit_set(uint32_t cache_id, int (*func)(void *args), void *args)
{
	ocf_cache_t cache;

	int idx = cache_id % MAX_CAS_LOCK_MAP;
	env_rwlock_write_lock(&g_cas_lock_map[idx]);

	int result = mngt_get_cache_by_id(cas_ctx, cache_id, &cache);
	if (result)
		goto out;

	result = cache_mngt_lock_sync(cache);
	if (result) {
		ocf_mngt_cache_put(cache);
		goto out;
	}

	ocf_cache_set_hook_submit(cache, func, args);

	ocf_mngt_cache_unlock(cache);
	ocf_mngt_cache_put(cache);

out:
	env_rwlock_write_unlock(&g_cas_lock_map[idx]);
	return result;
}

int cas_hook_cache_submit_get(uint32_t cache_id, int (**func)(void *args), void **args)
{
	ocf_cache_t cache;

	int idx = cache_id % MAX_CAS_LOCK_MAP;
	env_rwlock_read_lock(&g_cas_lock_map[idx]);

	int result = mngt_get_cache_by_id(cas_ctx, cache_id, &cache);
	if (result)
		goto out;

	result = cache_mngt_lock_sync(cache);
	if (result) {
		ocf_mngt_cache_put(cache);
		goto out;
	}

	ocf_cache_get_hook_submit(cache, func, args);

	ocf_mngt_cache_unlock(cache);
	ocf_mngt_cache_put(cache);

out:
	env_rwlock_read_unlock(&g_cas_lock_map[idx]);
	return result;
}

int cas_snapshot_cache(uint32_t volume_cache_id, uint32_t snapshot_cache_id, char snapshot_cache_path_name[PATH_MAX])
{
	/* stop io */
	int idx = volume_cache_id % MAX_CAS_LOCK_MAP;
	env_rwlock_write_lock(&g_cas_lock_map[idx]);

	int result = cache_mngt_snapshot(volume_cache_id, snapshot_cache_id, snapshot_cache_path_name);

	env_rwlock_write_unlock(&g_cas_lock_map[idx]);
	return result;
}

int cas_usage_cache(uint32_t cache_id, struct cas_usage *usage)
{
	struct kcas_get_stats cache_stats = {};

	cache_stats.cache_id = cache_id;
	cache_stats.core_id = OCF_CORE_ID_INVALID;
	cache_stats.part_id = OCF_IO_CLASS_INVALID;

	int result = cache_mngt_get_stats(&cache_stats);
	if (!result) {
		usage->occupancy = cache_stats.usage.occupancy.value;
		usage->free = cache_stats.usage.free.value;
		usage->clean = cache_stats.usage.clean.value;
		usage->dirty = cache_stats.usage.dirty.value;
	}
	return result;
}

int cas_set_cache_param(uint32_t cache_id, enum cas_cache_param_id param_id, uint32_t param_value)
{
	struct kcas_set_cache_param cache_param = {};

	cache_param.cache_id = cache_id;
	cache_param.param_value = param_value;
	switch (param_id) {
		case cas_cache_param_cleaner_policy_control:
			cache_param.param_id = cache_param_cleaner_policy_control;
			break;
		case cas_cache_param_cleaning_policy_type:
			cache_param.param_id = cache_param_cleaning_policy_type;
			break;
		case cas_cache_param_cleaning_alru_wake_up_time:
			cache_param.param_id = cache_param_cleaning_alru_wake_up_time;
			break;
		case cas_cache_param_cleaning_alru_flush_split_unit:
			cache_param.param_id = cache_param_cleaning_alru_flush_split_unit;
			break;
		case cas_cache_param_cleaning_alru_flush_max_buffers:
			cache_param.param_id = cache_param_cleaning_alru_flush_max_buffers;
			break;
		case cas_cache_param_cleaning_alru_activity_threshold:
			cache_param.param_id = cache_param_cleaning_alru_activity_threshold;
			break;
		case cas_cache_param_cleaning_alru_dirty_overflow_threshold:
			cache_param.param_id = cache_param_cleaning_alru_dirty_overflow_threshold;
			break;
		case cas_cache_param_cleaning_acp_wake_up_time:
			cache_param.param_id = cache_param_cleaning_acp_wake_up_time;
			break;
		case cas_cache_param_cleaning_acp_flush_split_unit:
			cache_param.param_id = cache_param_cleaning_acp_flush_split_unit;
			break;
		case cas_cache_param_cleaning_acp_flush_max_buffers:
			cache_param.param_id = cache_param_cleaning_acp_flush_max_buffers;
			break;
		case cas_cache_param_cleaning_acp_activity_threshold:
			cache_param.param_id = cache_param_cleaning_acp_activity_threshold;
			break;
		case cas_cache_param_cleaning_acp_dirty_overflow_threshold:
			cache_param.param_id = cache_param_cleaning_acp_dirty_overflow_threshold;
			break;
		case cas_cache_param_promotion_policy_type:
			cache_param.param_id = cache_param_promotion_policy_type;
			break;
		case cas_cache_param_promotion_nhit_insertion_threshold:
			cache_param.param_id = cache_param_promotion_nhit_insertion_threshold;
			break;
		case cas_cache_param_promotion_nhit_trigger_threshold:
			cache_param.param_id = cache_param_promotion_nhit_trigger_threshold;
			break;
		default:
			return -EINVAL;
	}

	return cache_mngt_set_cache_params(&cache_param);
}
