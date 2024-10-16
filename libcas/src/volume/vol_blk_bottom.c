/*
* Copyright(c) 2012-2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/file.h>
#include <fcntl.h>
#include <syslog.h>
#include "vol_blk_bottom.h"
#include "../cas_cache.h"

#define CAS_DEBUG_IO 0

#if CAS_DEBUG_IO == 1
#define CAS_DEBUG_TRACE() syslog(LOG_DEBUG, \
		"[IO] %s:%d\n", __func__, __LINE__)

#define CAS_DEBUG_MSG(msg) syslog(LOG_DEBUG, \
		"[IO] %s:%d - %s\n", __func__, __LINE__, msg)

#define CAS_DEBUG_PARAM(format, ...) syslog(LOG_DEBUG, \
		"[IO] %s:%d - "format"\n", __func__, __LINE__, ##__VA_ARGS__)
#else
#define CAS_DEBUG_TRACE()
#define CAS_DEBUG_MSG(msg)
#define CAS_DEBUG_PARAM(format, ...)
#endif

static ssize_t _pread(int fd, void *buf, size_t len, off_t offset)
{
        ssize_t nr;
        while (true) {
                nr = pread(fd, buf, len, offset);
                if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
                        continue;
                return nr;
        }
}

static ssize_t xpread(int fd, void *buf, size_t count, off_t offset)
{
        char *p = buf;
        ssize_t total = 0;

        while (count > 0) {
                ssize_t loaded = _pread(fd, p, count, offset);
                if (unlikely(loaded < 0))
                        return -1;
                if (unlikely(loaded == 0))
                        return total;
                count -= loaded;
                p += loaded;
                total += loaded;
                offset += loaded;
        }

        return total;
}

static ssize_t _pwrite(int fd, const void *buf, size_t len, off_t offset)
{
        ssize_t nr;
        while (true) {
                nr = pwrite(fd, buf, len, offset);
                if (unlikely(nr < 0) && (errno == EAGAIN || errno == EINTR))
                        continue;
                return nr; 
        }   
}

static ssize_t xpwrite(int fd, const void *buf, size_t count, off_t offset)
{
        const char *p = buf;
        ssize_t total = 0;

        while (count > 0) {
                ssize_t written = _pwrite(fd, p, count, offset);
                if (unlikely(written < 0)) 
                        return -1; 
                if (unlikely(!written)) {
                        errno = ENOSPC;
                        return -1; 
                }   
                count -= written;
                p += written;
                total += written;
                offset += written;
        }

        return total;
}

static int cas_disk_open(struct vb_object *dsk, const char *path, void *private)
{
	ENV_BUG_ON(!dsk);
	ENV_BUG_ON(!path);

	dsk->path = strdup(path);
	if (!dsk->path) {
		goto error_strdup;
	}

	int fd = open(path, O_RDWR);
	if (fd < 0) {
		syslog(LOG_ERR, "Cannot open %s", path);
		goto error_open_bdev;
	}
	int ret = flock(fd, LOCK_EX);
	if (ret < 0) {
		syslog(LOG_ERR, "Cannot lock %s", path);
		close(fd);
		goto error_open_bdev;
	}

	dsk->btm_obj = (void *)(uintptr_t)fd;
	dsk->private = private;

	syslog(LOG_DEBUG, "Created (%p)", dsk);

	return 0;

error_open_bdev:
	env_free(dsk->path);
error_strdup:
	env_free(dsk);
	return -1;
}

static void cas_disk_close(struct vb_object *dsk)
{
	ENV_BUG_ON(!dsk);
	ENV_BUG_ON(!dsk->btm_obj);

	syslog(LOG_DEBUG, "Destroying (%p)", dsk);

	int fd = (uintptr_t)dsk->btm_obj;
	flock(fd, LOCK_UN);
	close(fd);

	env_free(dsk->path);
}

static int block_dev_open_object(ocf_volume_t vol, void *volume_params)
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

static void block_dev_close_object(ocf_volume_t vol)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(vol);

	cas_disk_close(bdobj);
}

static unsigned int block_dev_get_max_io_size(ocf_volume_t vol)
{
	return 1 << 30;
}

static uint64_t block_dev_get_byte_length(ocf_volume_t vol)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(vol);

	uint64_t size;
	int fd = (uintptr_t)bdobj->btm_obj;
	int ret = ioctl(fd, BLKGETSIZE64, &size);
	if (ret < 0) {
		return 0;
	}
	return size;
}

static void block_dev_forward_flush(ocf_volume_t volume, ocf_forward_token_t token)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(volume);
	struct cas_data *data = ocf_forward_get_data(token);

#if 0
	ocf_cache_t cache = ocf_volume_get_cache(volume);
	if (ocf_cache_is_stopping(cache)) {
		syslog(LOG_INFO, "cache is stopping, ignore io\n");
		ocf_forward_end(token, -EINTR);
		return;
	}
#endif
	int fd = (uintptr_t)bdobj->btm_obj;
	int err = fsync(fd);
	ocf_forward_end(token, err);
}

static void block_dev_forward_discard(ocf_volume_t volume, ocf_forward_token_t token,
		uint64_t addr, uint64_t bytes)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(volume);
	struct cas_data *data = ocf_forward_get_data(token);

#if 0
	ocf_cache_t cache = ocf_volume_get_cache(volume);
	if (ocf_cache_is_stopping(cache)) {
		syslog(LOG_INFO, "cache is stopping, ignore io\n");
		ocf_forward_end(token, -EINTR);
		return;
	}
#endif
	//TODO
	ocf_forward_end(token, 0);
}

/*
 *
 */
static void block_dev_forward_io(ocf_volume_t volume, ocf_forward_token_t token,
		int dir, uint64_t addr, uint64_t bytes, uint64_t offset)
{
	struct vb_object *bdobj = cas_volume_get_vb_object(volume);
	struct cas_data *data = ocf_forward_get_data(token);
	uint64_t flags = ocf_forward_get_flags(token);
	int err = 0;
	int result = 0;
	void *ptrbuf = data->io_vec.iov_base + offset;

	CAS_DEBUG_PARAM("Address = %llu, bytes = %u\n", addr, bytes);

	if (!bytes) {
		/* Don not accept empty request */
		syslog(LOG_ERR, "Invalid zero size IO\n");
		ocf_forward_end(token, -EINVAL);
		return;
	}

	assert(offset < data->io_vec.iov_len);

#if 0
	ocf_cache_t cache = ocf_volume_get_cache(volume);
	if (ocf_cache_is_stopping(cache)) {
		syslog(LOG_INFO, "cache is stopping, ignore io\n");
		ocf_forward_end(token, -EINTR);
		return;
	}
#endif

	/* io */
	int fd = (uintptr_t)bdobj->btm_obj;
	syslog(LOG_DEBUG, "cas io fd %d", fd);
	switch (dir) {
		case OCF_READ:
			result = xpread(fd, ptrbuf, bytes, addr);
			if (result != bytes)
				err = -EIO;
			break;

		case OCF_WRITE:
			result = xpwrite(fd, ptrbuf, bytes, addr);
			if (result != bytes)
				err = -EIO;
			break;

		default:
			syslog(LOG_ERR, "Invalid dir IO\n");
			err = -EINVAL;
			break;
	}
	if (err)
		assert(0);

	ocf_forward_end(token, err);
}

static struct ocf_volume_properties btm_block_dev_properties = {
	.name = "Block_Device",
	.volume_priv_size = sizeof(struct vb_object),
	.caps = {
		.atomic_writes = 0, /* Atomic writes not supported */
	},
	.ops = {
		.forward_io = block_dev_forward_io,
		.forward_flush = block_dev_forward_flush,
		.forward_discard = block_dev_forward_discard,
		.open = block_dev_open_object,
		.close = block_dev_close_object,
		.get_max_io_size = block_dev_get_max_io_size,
		.get_length = block_dev_get_byte_length,
	},
	.deinit = NULL,
};

struct vol_btm_driver cas_blk_driver = {
	.properties = &btm_block_dev_properties,
	.type = BLOCK_DEVICE_VOLUME,
};

register_btm_driver(cas_blk_driver);
