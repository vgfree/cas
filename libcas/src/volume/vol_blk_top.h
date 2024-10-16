/*
* Copyright(c) 2012-2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef __VOL_BLOCK_DEV_TOP_H__
#define __VOL_BLOCK_DEV_TOP_H__

#include "../cas_cache.h"

struct cas_top_obj_ops {
	/**
	 * @brief Set geometry of exported object (top) block device.
	 *	Could be NULL.
	 */
	int (*set_geometry)(struct vb_object *dsk, void *private);

	/**
	 * @brief submit_aio of exported object (top) block device.
	 *
	 */
	void (*submit_aio)(struct vb_object *dsk,
			       struct cas_aio *aio, void *private);
};

struct cas_top_obj {
	uint64_t length;

	bool activated;

	struct cas_top_obj_ops *ops;

	const char *dev_name;

	void *private;
};

/**
 * @brief Create exported object (top device)
 * @param dsk Pointer to cas_disk structure representing a block device
 * @param dev_name Name of exported object (top device)
 * @param owner Pointer to cas module
 * @param ops Pointer to structure with callback functions
 * @param priv Private data
 * @return 0 if success, errno if failure
 */
int cas_top_obj_create(struct vb_object *dsk, const char *dev_name, struct cas_top_obj_ops *ops, void *priv);

int cas_top_obj_submit_aio(struct vb_object *dsk, struct cas_aio *aio);

/**
 * @brief Destroy exported object
 * @param dsk Pointer to cas_disk structure representing a block device
 * @return 0 if success, errno if failure
 */
int cas_top_obj_destroy(struct vb_object *dsk);

int kcas_core_create_exported_object(ocf_core_t core);
int kcas_core_destroy_exported_object(ocf_core_t core);

int kcas_cache_destroy_all_core_exported_objects(ocf_cache_t cache);

int kcas_cache_create_exported_object(ocf_cache_t cache);
int kcas_cache_destroy_exported_object(ocf_cache_t cache);

#endif /* __VOL_BLOCK_DEV_TOP_H__ */
