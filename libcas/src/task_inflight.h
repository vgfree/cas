#include <stdint.h>
#include <pthread.h>
#include "ocf/env/ocf_env.h"

struct task_inflight_node {
	struct list_head node;
	bool	wait;
	void *data;
	pthread_cond_t cond;
};

typedef bool (*task_inflight_overlap)(struct task_inflight_node *a, struct task_inflight_node *b);

struct task_inflight_info {
	pthread_mutex_t lock;
	struct list_head head;
	task_inflight_overlap cmp_fcb;
};

void task_inflight_block(struct task_inflight_info *info, struct task_inflight_node *my);

void task_inflight_wakeup(struct task_inflight_info *info, struct task_inflight_node *my);

void task_inflight_init(struct task_inflight_info *info, task_inflight_overlap cmp_fcb);

void task_inflight_destroy(struct task_inflight_info *info);
