/*
* Copyright(c) 2012-2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/


#ifndef __THREADS_H__
#define __THREADS_H__

#include "ocf/ocf.h"

#define CAS_CPUS_ALL -1

int queue_thread_init(struct ocf_queue *queue, const char *name);

void queue_thread_stop(ocf_queue_t q);

void queue_thread_kick(ocf_queue_t q);

int cleaner_thread_init(ocf_cleaner_t c, const char *name);

void cleaner_thread_stop(ocf_cleaner_t c);

void cleaner_thread_kick(ocf_cleaner_t c);

#endif /* __THREADS_H__ */
