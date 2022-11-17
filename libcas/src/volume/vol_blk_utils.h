/*
* Copyright(c) 2012-2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef __VOL_BLK_UTILS_H__
#define __VOL_BLK_UTILS_H__

#include "context.h"

/**
 * cache/core object types */
enum {
	BLOCK_DEVICE_VOLUME = 1,	/**< block device volume */
/** \cond SKIP_IN_DOC */
	OBJECT_TYPE_MAX,
/** \endcond */
};

struct cas_top_obj;

struct vb_object {
	char *path;
	void *btm_obj;
	struct cas_top_obj *top_obj;

	void *private;

	uint32_t expobj_valid : 1;//TODO
		/*!< Bit indicates that exported object was created */

	env_atomic64 pending_rqs;//TODO
		/*!< This fields describes in flight IO requests */

	ocf_volume_t front_volume;
		/*< Cache/core front volume */
};

static inline struct vb_object *cas_volume_get_vb_object(ocf_volume_t vol)
{
	return ocf_volume_get_priv(vol);
}


struct vb_io {
	int error;
	env_atomic rq_remaning;

	struct cas_data *data; /* IO data buffer */
	uint32_t data_offset;//TODO: needed?
};

static inline struct vb_io *cas_io_to_blkio(struct ocf_io *io)
{
	return ocf_io_get_priv(io);
}

struct vol_btm_driver {
	struct ocf_volume_properties *properties;
	uint8_t type;
	struct list_head list;
};

struct vol_btm_driver *find_btm_driver(uint8_t type);

void make_btm_driver(struct vol_btm_driver *driver);

#define register_btm_driver(driver)						\
	static void __attribute__((constructor(101))) regist_ ## driver(void)	\
	{									\
		printf("%s...\n", __FUNCTION__);				\
		make_btm_driver(&driver);					\
	}

int load_btm_driver(void);

int cas_blk_identify_type(const char *path, uint8_t *type);

#endif /* __VOL_BLK_UTILS_H__ */
