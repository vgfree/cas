/*
* Copyright(c) 2012-2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/file.h>
#include <fcntl.h>

#include "vol_blk_utils.h"
#include "../cas_logger.h"
#include "../../3api/sd_api.h"
#include "../../3api/libevcoro.h"
#include "../../3api/ctask_thread.h"

#define SD_MAX_POOL_NAME_LEN 128
#define CAS_DEBUG_IO 0

#if CAS_DEBUG_IO == 1
#define CAS_DEBUG_TRACE() cas_printf(LOG_DEBUG, \
		"[IO] %s:%d\n", __func__, __LINE__)

#define CAS_DEBUG_MSG(msg) cas_printf(LOG_DEBUG, \
		"[IO] %s:%d - %s\n", __func__, __LINE__, msg)

#define CAS_DEBUG_PARAM(format, ...) cas_printf(LOG_DEBUG, \
		"[IO] %s:%d - "format"\n", __func__, __LINE__, ##__VA_ARGS__)
#else
#define CAS_DEBUG_TRACE()
#define CAS_DEBUG_MSG(msg)
#define CAS_DEBUG_PARAM(format, ...)
#endif

struct sagocycas_access_info {
	struct api_session *session;
	struct volume_item vitem;
	struct ctask_context io_ctx;
};

struct url_info {
	char socket_path[PATH_MAX];
	char pool_name[SD_MAX_POOL_NAME_LEN];
	char volume_name[SD_MAX_VOLUME_NAME_LEN];
};

static int parse_url(const char *filename, struct url_info *ui)
{
	int ret = 0;
	char *tmp_filename = strdup(filename);
	if (!tmp_filename) {
		cas_printf(LOG_ERR, "saving original filename failed");
		return -1;
	}

	/*
	 * expected form of filename:
	 *
	 * sagocycas://host1:port1,host2:port2?pool_name#volume_name
	 */

	char *ptr = tmp_filename;
	char *end = strstr(ptr, "://");
	if (!end || strncmp("sagocycas", ptr, 9)) {
		cas_printf(LOG_ERR, "unknown protocol of jm url: %s", filename);
		ret = -1;
		goto out;
	}
	end[0] = '\0';
	ptr = end + 3;

	end = strchr(ptr, '?');
	if (!end) {
		cas_printf(LOG_ERR, "unknown socket_path of jm url: %s", filename);
		ret = -1;
		goto out;
	}
	end[0] = '\0';
	strncpy(ui->socket_path, ptr, PATH_MAX - 1);
	ptr = end + 1;

	end = strchr(ptr, '#');
	if (!end) {
		cas_printf(LOG_ERR, "unknown pool_name of jm url: %s", filename);
		ret = -1;
		goto out;
	}
	end[0] = '\0';
	strncpy(ui->pool_name, ptr, SD_MAX_POOL_NAME_LEN - 1);
	ptr = end + 1;

	int len = strlen(ptr);
	if (len >= SD_MAX_VOLUME_NAME_LEN || len == 0) {
		cas_printf(LOG_ERR, "VDI name is too long or missing of jm url %s", filename);
		ret = -1;
		goto out;
	}
	strncpy(ui->volume_name, ptr, SD_MAX_VOLUME_NAME_LEN);

out:
	free(tmp_filename);

	return ret;
}

static void switch_for_event(int efd, void *usr)
{
	cotask_event(efd, EV_READ, -1);
}

static int cas_disk_open(struct vb_object *dsk, const char *path, void *private)
{
	ENV_BUG_ON(!dsk);
	ENV_BUG_ON(!path);

	dsk->path = strdup(path);
	if (!dsk->path) {
		cas_printf(LOG_ERR, "no memory!");
		goto error_strdup;
	}

	struct url_info ui = {};
	int ret = parse_url(path, &ui);
	if (ret < 0) {
		goto error_dsk_path;
	}

	struct sagocycas_access_info *ai = env_zalloc(sizeof(*ai), 0);
	if (!ai) {
		cas_printf(LOG_ERR, "no memory!");
		goto error_dsk_path;
	}

	ret = ctask_thread_open(&ai->io_ctx, NULL, NULL, NULL, "%s", "coro io");
	if (ret < 0) {
		goto error_io_ctx;
	}

	ai->session = sd_api_session_get(ui.socket_path);
	if (!ai->session) {
		cas_printf(LOG_ERR, "connect %s failed!", ui.socket_path);
		goto error_get_session;
	}
	cas_printf(LOG_INFO, "session get (%p)", ai->session);
	sd_api_set_pcb(ai->session, NULL, switch_for_event);

	uint32_t vid = 0;
	if (strncmp(ui.volume_name, "0x", 2) == 0) {
		sscanf(ui.volume_name, "%x", &vid);
	}

	if (vid == 0) {
		struct api_volume_list *list = NULL;
		ret = sd_api_volume_list(ai->session, &list, true);
		if (ret) {
			cas_printf(LOG_ERR, "volume list failed! error:%s", sd_strerror(ret));
			goto error_volume_info;
		}

		for (int i = 0; i < list->nr_items; i++) {
			struct volume_item *item = &list->items[i];
			if (!strcmp(item->name, ui.volume_name)) {
				vid = item->vid;
				memcpy(&ai->vitem, item, sizeof(ai->vitem));
				break;
			}
		}
		free(list);

		if (vid == 0) {
			cas_printf(LOG_ERR, "not found volume:%s", ui.volume_name);
			goto error_volume_info;
		}
	} else {
		struct api_volume_info info;
		ret = sd_api_volume_info(ai->session, &info, vid);
		if (ret) {
			cas_printf(LOG_ERR, "volume info failed! error:%s", sd_strerror(ret));
			goto error_volume_info;
		}
		memcpy(&ai->vitem, &info.item, sizeof(ai->vitem));
	}

	dsk->btm_obj = (void *)ai;
	dsk->private = private;

	cas_printf(LOG_DEBUG, "Created (%p)", dsk);
	return 0;

error_volume_info:
	sd_api_session_put(ai->session);
error_get_session:
	ctask_thread_close(&ai->io_ctx);
error_io_ctx:
	env_free(ai);
error_dsk_path:
	env_free(dsk->path);
	dsk->path = NULL;
error_strdup:
	return -1;
}

static void cas_disk_close(struct vb_object *dsk)
{
	ENV_BUG_ON(!dsk);
	ENV_BUG_ON(!dsk->btm_obj);

	cas_printf(LOG_DEBUG, "Destroying (%p)", dsk);

	struct sagocycas_access_info *ai = (struct sagocycas_access_info *)dsk->btm_obj;
	cas_printf(LOG_INFO, "session put (%p)", ai->session);
	sd_api_session_put(ai->session);
	ctask_thread_close(&ai->io_ctx);
	env_free(ai);
	dsk->btm_obj = NULL;

	env_free(dsk->path);
	dsk->path = NULL;
}

int sagocycas_open_object(ocf_volume_t vol, void *volume_params)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(vol);
	const struct ocf_volume_uuid *uuid = ocf_volume_get_uuid(vol);

	int ret = cas_disk_open(bdobj, (const char *)uuid->data, NULL);
	if (ret) {
		int error = errno ?: -EINVAL;

		if (error == -EBUSY)
			error = -OCF_ERR_NOT_OPEN_EXC;

		return error;
	}

	return 0;
}

void sagocycas_close_object(ocf_volume_t vol)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(vol);

	cas_disk_close(bdobj);
}

unsigned int sagocycas_get_max_io_size(ocf_volume_t vol)
{
	return 1 << 30;
}

uint64_t sagocycas_get_byte_length(ocf_volume_t vol)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(vol);
	struct sagocycas_access_info *ai = (struct sagocycas_access_info *)bdobj->btm_obj;

	return ai->vitem.volume_size;
}

int sagocycas_snapshot(ocf_volume_t vol, char snapshot_path[PATH_MAX])
{
	struct vb_object *bdobj = cas_volume_get_vb_object(vol);
	struct sagocycas_access_info *ai = (struct sagocycas_access_info *)bdobj->btm_obj;
	const struct ocf_volume_uuid *uuid = ocf_volume_get_uuid(vol);

	uint32_t nr_vs_id = 0;
	struct vs_id vs_id[SD_MAX_NR_VOLUMES] = {};
	struct api_snapshot_create params = {};
	params.vid = ai->vitem.vid;
	params.feign = true;
	snprintf(params.name, sizeof(params.name), "%s", ocf_uuid_to_str(uuid));
	int result = sd_api_snapshot_create(ai->session, NULL, &params, &nr_vs_id, vs_id);
	if (result) {
		return -EIO;
	}
	assert(nr_vs_id == 1);

	snprintf(snapshot_path, PATH_MAX, "%s:0x%"PRIx32, ocf_uuid_to_str(uuid), vs_id[0].sid);
	return 0;
}


static void sagocycas_forward_flush(ocf_volume_t volume, ocf_forward_token_t token)
{
	ocf_forward_end(token, 0);
}

static void sagocycas_forward_discard(ocf_volume_t volume, ocf_forward_token_t token,
		uint64_t addr, uint64_t bytes)
{
	//TODO
	ocf_forward_end(token, 0);
}

struct vb_io {
	struct vb_object *bdobj;
	ocf_forward_token_t token;
	int dir;
	uint64_t addr;
	uint64_t bytes;
	uint64_t offset;
};

static void run_sagocycas_io(void *user)
{
	struct vb_io *vbio = (struct vb_io *)user;
	struct vb_object *bdobj = vbio->bdobj;
	struct cas_data *data = ocf_forward_get_data(vbio->token);
	uint64_t flags = ocf_forward_get_flags(vbio->token);
	int err = 0;
	int result = 0;
	void *ptrbuf = data->io_vec.iov_base + vbio->offset;
	uint64_t length = vbio->bytes;
	uint64_t offset = vbio->addr;

	CAS_DEBUG_PARAM("Address = %llu, bytes = %u\n", offset, length);

	if (!length) {
		/* Don not accept empty request */
		cas_printf(LOG_ERR, "Invalid zero size IO\n");
		ocf_forward_end(vbio->token, -EINVAL);
		env_free(vbio);
		return;
	}

	assert(vbio->offset < data->io_vec.iov_len);
	/* io */
	struct sagocycas_access_info *ai = (struct sagocycas_access_info *)bdobj->btm_obj;
	//cas_printf(LOG_INFO, "session aio (%p)", ai->session);
	uint32_t vid = ai->vitem.vid;
	switch (vbio->dir) {
		case OCF_READ:
			result = sd_api_volume_read(ai->session, &ai->vitem, vid, ptrbuf, length, offset);
			if (result)
				err = -EIO;
			break;

		case OCF_WRITE:
			result = sd_api_volume_write(ai->session, &ai->vitem, vid, ptrbuf, length, offset);
			if (result)
				err = -EIO;
			break;

		default:
			cas_printf(LOG_ERR, "Invalid dir IO");
			err = -EINVAL;
			break;
	}
	if (err)
		cas_printf(LOG_ERR, "%s (vid: 0x%"PRIx32")", sd_strerror(result), vid);

	ocf_forward_end(vbio->token, err);
	env_free(vbio);
}

/*
 *
 */
static void sagocycas_forward_io(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(volume);
	struct sagocycas_access_info *ai = (struct sagocycas_access_info *)bdobj->btm_obj;

	struct vb_io *io = env_zalloc(sizeof(*io), 0);
	if (!io) {
		cas_printf(LOG_ERR, "no memory!");
		ocf_forward_end(token, -ENOMEM);
		return;
	}
	io->bdobj = bdobj;
	io->token = token;
	io->dir = dir;
	io->addr = addr;
	io->bytes = bytes;
	io->offset = offset;

	int ret = ctask_thread_submit(&ai->io_ctx, run_sagocycas_io, io, 1 << 22);
	assert(ret == 0);
}



static struct ocf_volume_properties btm_sagocycas_properties = {
	.name = "Block_Device",
	.volume_priv_size = sizeof(struct vb_object),
	.caps = {
		.atomic_writes = 0, /* Atomic writes not supported */
	},
	.ops = {
		.forward_io = sagocycas_forward_io,
		.forward_flush = sagocycas_forward_flush,
		.forward_discard = sagocycas_forward_discard,
		.open = sagocycas_open_object,
		.close = sagocycas_close_object,
		.get_max_io_size = sagocycas_get_max_io_size,
		.get_length = sagocycas_get_byte_length,
		.snapshot = sagocycas_snapshot,
	},
	.deinit = NULL,
};

static struct vol_btm_driver btm_sagocycas_driver = {
	.properties = &btm_sagocycas_properties,
	.type = VOLUME_TYPE_BLOCK_SAGOCYCAS,
};

register_btm_driver(btm_sagocycas_driver);
