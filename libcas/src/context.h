/*
* Copyright(c) 2012-2022 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdint.h>

#include "ocf/ocf.h"

struct cas_data {
	struct iovec io_vec;
	uint64_t io_offset;
	uint64_t io_length;

	struct iovec my_vec;
};

ctx_data_t *cas_ctx_data_alloc(uint32_t pages);
void cas_ctx_data_free(ctx_data_t *ctx_data);
void cas_ctx_data_secure_erase(ctx_data_t *ctx_data);

int cas_initialize_context(void);
void cas_cleanup_context(void);

#endif /* __CONTEXT_H__ */
