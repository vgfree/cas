/*
* Copyright(c) 2012-2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#include <syslog.h>
#include "volume/vol_blk_utils.h"
#include "volume/vol_blk_top.h"
#include "volume/vol_blk_bottom.h"
#include "context.h"
#include "cas_cache.h"

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

int cas_init_module(void)
{
	int result = 0;

	if (!writeback_queue_unblock_size || !max_writeback_queue_size) {
		syslog(LOG_ERR, OCF_PREFIX_SHORT
				"Invalid module parameter.\n");
		return -EINVAL;
	}

	if (writeback_queue_unblock_size >= max_writeback_queue_size) {
		syslog(LOG_ERR, OCF_PREFIX_SHORT
				"parameter writeback_queue_unblock_size"
				" must be less than max_writeback_queue_size\n");
		return -EINVAL;
	}

	if (unaligned_io != 0 && unaligned_io != 1) {
		syslog(LOG_ERR, OCF_PREFIX_SHORT
				"Invalid value for unaligned_io parameter\n");
		return -EINVAL;
	}

	if (use_io_scheduler != 0 && use_io_scheduler != 1) {
		syslog(LOG_ERR, OCF_PREFIX_SHORT
				"Invalid value for use_io_scheduler parameter\n");
		return -EINVAL;
	}

	result = cas_initialize_context();
	if (result) {
		syslog(LOG_ERR, OCF_PREFIX_SHORT
				"Cannot initialize cache library\n");
		return result;
	}

	result = cas_ctrl_init();
	if (result) {
		syslog(LOG_ERR, OCF_PREFIX_SHORT
				"Cannot initialize control device\n");
		goto error_init_ctrl;
	}

	syslog(LOG_INFO, "%s Version %s loaded successfully\n",
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
}

void *cas_lookup_vb_obj(uint16_t cache_id, uint16_t core_id)
{
	ocf_cache_t cache;
	ocf_core_t core;
	char cache_name[OCF_CACHE_NAME_SIZE];
	char core_name[OCF_CORE_NAME_SIZE];

	cache_name_from_id(cache_name, cache_id);
	core_name_from_id(core_name, core_id);
	int result = ocf_mngt_cache_get_by_name(cas_ctx, cache_name, OCF_CACHE_NAME_SIZE, &cache);
	if (result)
		return NULL;
	result = ocf_core_get_by_name(cache, core_name, OCF_CORE_NAME_SIZE, &core);
	if (result)
		return NULL;

	ocf_volume_t volume = ocf_core_get_volume(core);
	return (void *)cas_volume_get_vb_object(volume);
}

int cas_submit_vb_aio(void *obj, struct cas_aio *aio)
{
	return cas_top_obj_submit_aio((struct vb_object *)obj, aio);
}

uint64_t cas_obtain_vb_len(void *obj)
{
	return ((struct vb_object *)obj)->top_obj->length;
}
