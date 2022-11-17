/*
* Copyright(c) 2012-2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#ifndef __CAS_CONTROL_H__
#define __CAS_CONTROL_H__

#include <stdint.h>
#include <string.h>

struct cas_query_header {
	uint32_t magic;
	uint32_t version;
	uint32_t command;
	uint64_t length;
};

#define CAS_QUERY_MAGIC				0xD13CD13C
#define CAS_QUERY_VERSION			0x00010001
#define CAS_QUERY_QUERY_SOCK_PATH		"cas_query_sock"

static inline void cas_query_init_header(struct cas_query_header *h, int cmd, uint64_t extra_len)
{
	memset(h, 0, sizeof(struct cas_query_header));

	h->magic = CAS_QUERY_MAGIC;
	h->version = CAS_QUERY_VERSION;
	h->length = sizeof(struct cas_query_header) + extra_len;
	h->command = cmd;
}

int cas_ctrl_init(void);
void cas_ctrl_deinit(void);

#endif
