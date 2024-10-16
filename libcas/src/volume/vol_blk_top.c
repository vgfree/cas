/*
* Copyright(c) 2012-2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#include <syslog.h>

#include "cas_err.h"
#include "vol_blk_top.h"

int cas_top_obj_lock(struct vb_object *dsk)
{
	/*FIXME:refine lock function*/
	dsk->expobj_locked = true;

	return 0;
}

void cas_top_obj_unlock(struct vb_object *dsk)
{
	if (dsk->expobj_locked) {
		/*FIXME:refine unlock function*/
		dsk->expobj_locked = false;
	}
}

int cas_top_obj_create(struct vb_object *dsk, const char *dev_name, struct cas_top_obj_ops *ops, void *priv)
{
	int result = 0;
	struct cas_top_obj *top_obj;

	ENV_BUG_ON(!dsk);
	ENV_BUG_ON(!ops);
	ENV_BUG_ON(dsk->top_obj);

	if (strlen(dev_name) >= PATH_MAX)
		return -EINVAL;

	dsk->top_obj = env_zalloc(sizeof(struct cas_top_obj), 0);
	if (!dsk->top_obj) {
		return -ENOMEM;
	}

	top_obj = dsk->top_obj;

	top_obj->dev_name = strdup(dev_name);
	if (!top_obj->dev_name) {
		result = -ENOMEM;
		goto error_strdup;
	}

	top_obj->ops = ops;
	top_obj->private = priv;

	if (top_obj->ops->set_geometry) {
		result = top_obj->ops->set_geometry(dsk, dsk->private);
		if (result)
			goto error_set_geometry;
	}

	return 0;

error_set_geometry:
	env_free(top_obj->dev_name);
error_strdup:
	env_free(top_obj);
	dsk->top_obj = NULL;
	return result;
}


int cas_top_obj_destroy(struct vb_object *dsk)
{
	struct cas_top_obj *top_obj;

	ENV_BUG_ON(!dsk);

	top_obj = dsk->top_obj;

	if (!top_obj)
		return -ENODEV;

	env_free(top_obj->dev_name);
	env_free(top_obj);
	dsk->top_obj = NULL;

	return 0;

}

int cas_top_obj_submit_aio(struct vb_object *dsk, struct cas_aio *aio)
{
	struct cas_top_obj *top_obj;

	ENV_BUG_ON(!aio && !dsk);

	top_obj = dsk->top_obj;
	top_obj->ops->submit_aio(dsk, aio, top_obj->private);

	return 0;
}

/**
 * Map geometry of underlying (core) object geometry (sectors etc.)
 * to geometry of exported object.
 */
static int blkdev_core_set_geometry(struct vb_object *dsk, void *private)
{
	ENV_BUG_ON(!private);
	ocf_core_t core = private;

	ocf_volume_t core_vol = ocf_core_get_volume(core);
	dsk->top_obj->length = ocf_volume_get_length(core_vol);

	return 0;
}


static void blkdev_complete_data(ocf_io_t io, void *priv1, void *priv2,
		int error)
{
	struct cas_data *data = ocf_io_get_data(io);
	struct cas_aio *aio = priv1;

	aio->result = map_cas_err_to_generic(error);
	cas_completion_complete(&aio->cmpl);

	cas_ctx_data_free(data);
	ocf_io_put(io);
}

static void blkdev_handle_data(struct vb_object *bvol, struct cas_aio *aio)
{
	ocf_cache_t cache = ocf_volume_get_cache(bvol->front_volume);
	struct cache_priv *cache_priv = ocf_cache_get_priv(cache);
	ocf_queue_t queue = cache_priv->io_queues[0];//TODO:smp_processor_id()

	if (!aio->vb_length) {
		syslog(LOG_ERR, "Not able to handle empty AIO!\n");
		aio->result = -EINVAL;
		cas_completion_complete(&aio->cmpl);
		return;
	}

	struct cas_data *data = cas_ctx_data_alloc(roundup(aio->vb_length, PAGE_SIZE) / PAGE_SIZE);
	if (!data) {
		syslog(LOG_CRIT, "AIO data vector allocation error\n");
		aio->result = -ENOMEM;
		cas_completion_complete(&aio->cmpl);
		return;
	}
	data->io_vec = aio->vb_vec;

	ocf_io_t io = ocf_volume_new_io(bvol->front_volume, queue,
			aio->vb_offset, aio->vb_length, (aio->type == CAS_AIO_TYPE_READ) ? OCF_READ : OCF_WRITE,
			cas_cls_classify(cache, aio), 0);

	if (!io) {
		syslog(LOG_CRIT, "Out of memory. Ending IO processing.\n");
		cas_ctx_data_free(data);
		aio->result = -ENOMEM;
		cas_completion_complete(&aio->cmpl);
		return;
	}

	int ret = ocf_io_set_data(io, data, 0);
	if (ret < 0) {
		ocf_io_put(io);
		cas_ctx_data_free(data);
		aio->result = -EINVAL;
		cas_completion_complete(&aio->cmpl);
		return;
	}

	ocf_io_set_cmpl(io, aio, NULL, blkdev_complete_data);

	ocf_volume_submit_io(io);

	return;
}

static void blkdev_complete_discard(ocf_io_t io, void *priv1, void *priv2,
		int error)
{
	struct cas_aio *aio = priv1;

	aio->result = map_cas_err_to_generic(error);
	cas_completion_complete(&aio->cmpl);

	ocf_io_put(io);
}

static void blkdev_handle_discard(struct vb_object *bvol, struct cas_aio *aio)
{
	ocf_cache_t cache = ocf_volume_get_cache(bvol->front_volume);
	struct cache_priv *cache_priv = ocf_cache_get_priv(cache);
	ocf_queue_t queue = cache_priv->io_queues[0];//TODO:smp_processor_id()

	ocf_io_t io = ocf_volume_new_io(bvol->front_volume, queue,
			aio->vb_offset, aio->vb_length, OCF_WRITE,
			0, 0);
	if (!io) {
		syslog(LOG_CRIT, "Out of memory. Ending IO processing.\n");
		aio->result = -ENOMEM;
		cas_completion_complete(&aio->cmpl);
		return;
	}

	ocf_io_set_cmpl(io, aio, NULL, blkdev_complete_discard);

	ocf_volume_submit_discard(io);
	return;
}

static void blkdev_complete_flush(ocf_io_t io, void *priv1, void *priv2,
		int error)
{
	struct cas_aio *aio = priv1;

	aio->result = map_cas_err_to_generic(error);
	cas_completion_complete(&aio->cmpl);

	ocf_io_put(io);
}

static void blkdev_handle_flush(struct vb_object *bvol, struct cas_aio *aio)
{
	ocf_cache_t cache = ocf_volume_get_cache(bvol->front_volume);
	struct cache_priv *cache_priv = ocf_cache_get_priv(cache);
	ocf_queue_t queue = cache_priv->io_queues[0];//TODO:smp_processor_id()

	ocf_io_t io = ocf_volume_new_io(bvol->front_volume, queue,
			aio->vb_offset, aio->vb_length, OCF_WRITE,
			0, 0);
	if (!io) {
		syslog(LOG_CRIT, "Out of memory. Ending IO processing.\n");
		aio->result = -ENOMEM;
		cas_completion_complete(&aio->cmpl);
		return;
	}

	ocf_io_set_cmpl(io, aio, NULL, blkdev_complete_flush);

	ocf_volume_submit_flush(io);
	return;
}

static void blkdev_submit_aio(struct vb_object *bvol, struct cas_aio *aio)
{
	switch (aio->type) {
		case CAS_AIO_TYPE_READ:
		case CAS_AIO_TYPE_WRITE:
			blkdev_handle_data(bvol, aio);
			break;
		case CAS_AIO_TYPE_DISCARD:
			blkdev_handle_discard(bvol, aio);
			break;
		case CAS_AIO_TYPE_FLUSH:
			blkdev_handle_flush(bvol, aio);
			break;
		default:
			abort();

	}
}

static void blkdev_core_submit_aio(struct vb_object *dsk,
		struct cas_aio *aio, void *private)
{
	ocf_core_t core = private;

	ENV_BUG_ON(!core);

	struct vb_object *bvol = cas_volume_get_vb_object(ocf_core_get_volume(core));

	blkdev_submit_aio(bvol, aio);
}

static struct cas_top_obj_ops kcas_core_exported_object_ops = {
	.set_geometry = blkdev_core_set_geometry,
	.submit_aio = blkdev_core_submit_aio,
};

static int blkdev_cache_set_geometry(struct vb_object *dsk, void *private)
{
	ENV_BUG_ON(!private);
	ocf_cache_t cache = private;

	ocf_volume_t cache_vol = ocf_cache_get_volume(cache);
	dsk->top_obj->length = ocf_volume_get_length(cache_vol);

	return 0;
}

static void blkdev_cache_submit_aio(struct vb_object *dsk,
		struct cas_aio *aio, void *private)
{
	ocf_cache_t cache = private;

	ENV_BUG_ON(!cache);

	struct vb_object *bvol = cas_volume_get_vb_object(ocf_cache_get_volume(cache));

	blkdev_submit_aio(bvol, aio);
}

static struct cas_top_obj_ops kcas_cache_exported_object_ops = {
	.set_geometry = blkdev_cache_set_geometry,
	.submit_aio = blkdev_cache_submit_aio,
};

/****************************************
 * Exported object management functions *
 ****************************************/


static const char *get_cache_id_string(ocf_cache_t cache)
{
	return ocf_cache_get_name(cache) + sizeof("cache") - 1;
}

static const char *get_core_id_string(ocf_core_t core)
{
	return ocf_core_get_name(core) + sizeof("core") - 1;
}

static int kcas_volume_create_exported_object(ocf_volume_t volume,
		const char *name, void *priv, struct cas_top_obj_ops *ops)
{
	struct vb_object *bvol = cas_volume_get_vb_object(volume);

	bvol->private = priv;

	int result = cas_top_obj_create(bvol, name, ops, priv);
	if (result) {
		syslog(LOG_ERR, "Cannot create exported object %s. Error code %d\n", name, result);
	} else {
		bvol->expobj_valid = true;
	}
	return result;
}

static int kcas_volume_destroy_exported_object(ocf_volume_t volume)
{
	ENV_BUG_ON(!volume);

	const struct ocf_volume_uuid *uuid = ocf_volume_get_uuid(volume);
	struct vb_object *bvol = cas_volume_get_vb_object(volume);
	ENV_BUG_ON(!bvol);

	if (!bvol->expobj_valid)
		return 0;

	int result = cas_top_obj_lock(bvol);
	if (result == -EBUSY)
		return -KCAS_ERR_DEV_PENDING;
	else if (result)
		return result;

	result = cas_top_obj_destroy(bvol);
	if (result) {
		syslog(LOG_ERR, "Cannot destroy exported object %s. Error code %d\n", ocf_uuid_to_str(uuid), result);
	} else {
		bvol->expobj_valid = false;
	}

	cas_top_obj_unlock(bvol);
	return result;
}

int kcas_core_create_exported_object(ocf_core_t core)
{
	ocf_cache_t cache = ocf_core_get_cache(core);
	ocf_volume_t volume = ocf_core_get_volume(core);
	struct vb_object *bvol = cas_volume_get_vb_object(volume);
	char dev_name[PATH_MAX];

	snprintf(dev_name, PATH_MAX, "cas%s-%s",
			get_cache_id_string(cache),
			get_core_id_string(core));

	bvol->front_volume = ocf_core_get_front_volume(core);

	return kcas_volume_create_exported_object(volume, dev_name, core,
			&kcas_core_exported_object_ops);
}

int kcas_core_destroy_exported_object(ocf_core_t core)
{
	ocf_volume_t volume = ocf_core_get_volume(core);

	return kcas_volume_destroy_exported_object(volume);
}

int kcas_cache_create_exported_object(ocf_cache_t cache)
{
	ocf_volume_t volume = ocf_cache_get_volume(cache);
	struct vb_object *bvol = cas_volume_get_vb_object(volume);
	char dev_name[PATH_MAX];

	snprintf(dev_name, PATH_MAX, "cas-cache-%s",
			get_cache_id_string(cache));

	bvol->front_volume = ocf_cache_get_front_volume(cache);

	return kcas_volume_create_exported_object(volume, dev_name, cache,
			&kcas_cache_exported_object_ops);
}

int kcas_cache_destroy_exported_object(ocf_cache_t cache)
{
	ocf_volume_t volume = ocf_cache_get_volume(cache);

	return kcas_volume_destroy_exported_object(volume);
}

static int kcas_core_lock_exported_object(ocf_core_t core, void *cntx)
{
	int result;
	struct vb_object *bvol = cas_volume_get_vb_object(ocf_core_get_volume(core));

	if (!bvol->expobj_valid)
		return 0;

	result = cas_top_obj_lock(bvol);

	if (-EBUSY == result) {
		syslog(LOG_WARNING, "Stopping %s failed - device in use\n",
			bvol->top_obj->dev_name);
		return -KCAS_ERR_DEV_PENDING;
	} else if (result) {
		syslog(LOG_WARNING, "Stopping %s failed - device unavailable\n",
			bvol->top_obj->dev_name);
		return -OCF_ERR_CORE_NOT_AVAIL;
	}

	return 0;
}

static int kcas_core_unlock_exported_object(ocf_core_t core, void *cntx)
{
	struct vb_object *bvol = cas_volume_get_vb_object(ocf_core_get_volume(core));

	cas_top_obj_unlock(bvol);

	return 0;
}

static int _kcas_core_stop_exported_object(ocf_core_t core, void *cntx)
{
	struct vb_object *bvol = cas_volume_get_vb_object(ocf_core_get_volume(core));

	if (bvol->expobj_valid) {
		syslog(LOG_INFO, "Stopping device %s\n", bvol->top_obj->dev_name);

		int ret = cas_top_obj_destroy(bvol);
		if (!ret) {
			bvol->expobj_valid = false;
		}
	}

	return 0;
}

int kcas_cache_destroy_all_core_exported_objects(ocf_cache_t cache)
{
	int result;

	/* Try lock exported objects */
	result = ocf_core_visit(cache, kcas_core_lock_exported_object, NULL, true);
	if (!result) {
		ocf_core_visit(cache, _kcas_core_stop_exported_object, NULL, true);
	}

	/* Unlock already locked exported objects */
	ocf_core_visit(cache, kcas_core_unlock_exported_object, NULL, true);

	return result;
}
