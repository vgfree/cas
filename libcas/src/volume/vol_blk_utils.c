/*
* Copyright(c) 2012-2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/

#include <sys/stat.h>
#include "vol_blk_utils.h"
#include "../cas_cache.h"


//LIST_HEAD(g_vol_btm_drivers);
struct list_head g_vol_btm_drivers = {
	.prev = &g_vol_btm_drivers,
	.next = &g_vol_btm_drivers,
};

#define FOR_EACH_CLUSTER_DRIVER(driver) \
        list_for_each_entry(driver, &g_vol_btm_drivers, list)

struct vol_btm_driver *find_btm_driver(uint8_t type)
{
        struct vol_btm_driver *driver = NULL;

        FOR_EACH_CLUSTER_DRIVER(driver)
        {
                if (driver->type == type) {
                        return driver;
                }
        }

        return NULL;
}

void make_btm_driver(struct vol_btm_driver *driver)
{
	list_add(&driver->list, &g_vol_btm_drivers);
}

int load_btm_driver(void)
{
	int ret;
        struct vol_btm_driver *driver = NULL;

        FOR_EACH_CLUSTER_DRIVER(driver)
	{    
		ret = ocf_ctx_register_volume_type(cas_ctx, driver->type,
				driver->properties);
		if (ret < 0)
			return ret;
	}    

	return 0;
}


int cas_blk_identify_type(const char *path, uint8_t *type)
{
	struct stat st;
	int result = stat(path, &st);
	if (result < 0)
		return -OCF_ERR_INVAL_VOLUME_TYPE;

	if (S_ISBLK(st.st_mode))
		*type = BLOCK_DEVICE_VOLUME;
	else
		return -OCF_ERR_INVAL_VOLUME_TYPE;

	return 0;
}

