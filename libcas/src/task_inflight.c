#include <assert.h>
#include "cas_logger.h"

#include "task_inflight.h"

void task_inflight_block(struct task_inflight_info *info, struct task_inflight_node *my)
{
	struct task_inflight_node *inflight;

	INIT_LIST_HEAD(&my->node);
	pthread_cond_init(&my->cond, NULL);

	pthread_mutex_lock(&info->lock);
	my->wait = false;
	list_add_tail(&my->node, &info->head);

retry:
	list_for_each_entry(inflight, &info->head, node) {
		if (inflight == my) {
			break;
		}
		if (info->cmp_fcb(my, inflight)) {
			my->wait = true;
			cas_printf(LOG_DEBUG, "zone wait %p\n", my);
			pthread_cond_wait(&my->cond, &info->lock);
			cas_printf(LOG_DEBUG, "zone wait done %p\n", my);
			goto retry;
		}
	}
	my->wait = false;
	/*处理请求无重叠*/

	pthread_mutex_unlock(&info->lock);
	cas_printf(LOG_DEBUG, "data waken %p\n", my);
}

void task_inflight_wakeup(struct task_inflight_info *info, struct task_inflight_node *my)
{
	assert(my->wait == false);
	pthread_mutex_lock(&info->lock);

	list_del(&my->node);

	/* wakeup new tasks */
	struct task_inflight_node *inflight = NULL;

	list_for_each_entry(inflight, &info->head, node) {
		if (inflight->wait == false) {
			continue;
		}
		if (info->cmp_fcb(my, inflight)) {
			cas_printf(LOG_DEBUG, "wakeup zone %p\n", inflight);
			pthread_cond_signal(&inflight->cond);
		}
	}

	pthread_mutex_unlock(&info->lock);
	cas_printf(LOG_DEBUG, "wakeup signal done %p\n", my);
}

void task_inflight_init(struct task_inflight_info *info, task_inflight_overlap cmp_fcb)
{
	pthread_mutex_init(&info->lock, NULL);
	INIT_LIST_HEAD(&info->head);
	info->cmp_fcb = cmp_fcb;
}

void task_inflight_destroy(struct task_inflight_info *info)
{
	pthread_mutex_destroy(&info->lock);
}
