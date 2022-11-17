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

	int fd = open(path, O_RDWR | O_DIRECT);
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

/*
 *
 */
static void cas_bd_io_end(struct ocf_io *io, int error)
{
	struct vb_io *vbio = cas_io_to_blkio(io);

	if (error)
		vbio->error |= error;

	if (env_atomic_dec_return(&vbio->rq_remaning))
		return;

	CAS_DEBUG_MSG("Completion");

	/* Send completion to caller */
	io->end(io, vbio->error);
}


static void block_dev_submit_flush(struct ocf_io *io)
{
	struct vb_io *blkio = cas_io_to_blkio(io);
	struct vb_object *bdobj = cas_volume_get_vb_object(ocf_io_get_volume(io));

	/* Prevent races of completing IO */
	env_atomic_set(&blkio->rq_remaning, 1);

	int fd = (uintptr_t)bdobj->btm_obj;
	int err = fsync(fd);
	cas_bd_io_end(io, err);
}

static void block_dev_submit_discard(struct ocf_io *io)
{
	struct vb_io *blkio = cas_io_to_blkio(io);

	//sector_t start = io->addr >> SECTOR_SHIFT;

	/* Prevent races of completing IO */
	env_atomic_set(&blkio->rq_remaning, 1);
	//TODO

	cas_bd_io_end(io, blkio->error);
}

/*
 *
 */
static void block_dev_submit_io(struct ocf_io *io)
{
	struct vb_io *vbio = cas_io_to_blkio(io);
	struct cas_data *data = vbio->data;
	struct vb_object *bdobj = cas_volume_get_vb_object(ocf_io_get_volume(io));
	int err = 0;
	int bytes = 0;

	CAS_DEBUG_PARAM("Address = %llu, bytes = %u\n", io->addr, io->bytes);

	/* Prevent races of completing IO */
	env_atomic_set(&vbio->rq_remaning, 1);

	if (!io->bytes) {
		/* Don not accept empty request */
		syslog(LOG_ERR, "Invalid zero size IO\n");
		cas_bd_io_end(io, -EINVAL);
		return;
	}

	assert(vbio->data_offset < data->io_vec.iov_len);
	/* io */
	int fd = (uintptr_t)bdobj->btm_obj;
	switch (io->dir) {
		case OCF_READ:
			//bytes = xpread(fd, data->io_vec.iov_base + data->io_offset + vbio->data_offset, io->bytes, io->addr);
			bytes = xpread(fd, data->io_vec.iov_base + vbio->data_offset, io->bytes, io->addr);
			if (bytes != io->bytes)
				err = -EIO;
			break;

		case OCF_WRITE:
			//bytes = xpwrite(fd, data->io_vec.iov_base + data->io_offset + vbio->data_offset, io->bytes, io->addr);
			bytes = xpwrite(fd, data->io_vec.iov_base + vbio->data_offset, io->bytes, io->addr);
			if (bytes != io->bytes)
				err = -EIO;
			break;

		default:
			syslog(LOG_ERR, "Invalid dir IO\n");
			err = -EINVAL;
			break;
	}
	if (err)
		assert(0);

	cas_bd_io_end(io, err);
}

/*
 *
 */
int cas_blk_io_set_data(struct ocf_io *io,
		ctx_data_t *ctx_data, uint32_t offset)
{
	struct vb_io *blkio = cas_io_to_blkio(io);

	blkio->data = ctx_data;
	blkio->data_offset = offset;
	return 0;
}

/*
 *
 */
ctx_data_t *cas_blk_io_get_data(struct ocf_io *io)
{
	struct vb_io *blkio = cas_io_to_blkio(io);

	return blkio->data;
}


struct ocf_volume_properties cas_object_blk_properties = {
	.name = "Block_Device",
	.io_priv_size = sizeof(struct vb_io),
	.volume_priv_size = sizeof(struct vb_object),
	.caps = {
		.atomic_writes = 0, /* Atomic writes not supported */
	},
	.ops = {
		.submit_io = block_dev_submit_io,
		.submit_flush = block_dev_submit_flush,
		.submit_metadata = NULL,
		.submit_discard = block_dev_submit_discard,
		.open = block_dev_open_object,
		.close = block_dev_close_object,
		.get_max_io_size = block_dev_get_max_io_size,
		.get_length = block_dev_get_byte_length,
	},
	.io_ops = {
		.set_data = cas_blk_io_set_data,
		.get_data = cas_blk_io_get_data,
	},
	.deinit = NULL,
};

struct vol_btm_driver cas_blk_driver = {
	.properties = &cas_object_blk_properties,
	.type = BLOCK_DEVICE_VOLUME,
};

register_btm_driver(cas_blk_driver);
