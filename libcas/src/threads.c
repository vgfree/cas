/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include <pthread.h>
#include <syslog.h>

#include <ocf/ocf.h>
#include "threads.h"
#include "cas_cache.h"

#define MAX_THREAD_NAME_SIZE 48


/* queue thread main function */
static void *queue_thread_run(void *);

/* helper class to store all synchronization related objects */
struct queue_thread
{
	char name[MAX_THREAD_NAME_SIZE];
	/* thread running the queue */
	pthread_t thread;
	/* kick sets true, queue thread sets to false */
	bool signalled;
	/* request thread to exit */
	bool stop;
	/* conditional variable to sync queue thread and kick thread */
	pthread_cond_t cv;
	/* mutex for variables shared across threads */
	pthread_mutex_t mutex;
	/* associated OCF queue */
	struct ocf_queue *queue;
};

struct queue_thread *queue_thread_create(struct ocf_queue *q, const char *name)
{
	struct queue_thread *qt = malloc(sizeof(*qt));
	int ret;

	if (!qt)
		return NULL;

	pthread_condattr_t attr;
	pthread_condattr_init(&attr);
	/*
	 * pthread_cond_timedwait()默认使用的是CLOCK_REALTIME,
	 * CLOCK_REALTIME容易受系统影响，比如校时操作
	 * 所以条件变量使用的时钟改为CLOCK_MONOTONIC
	 * 参考:https://man7.org/linux/man-pages/man3/pthread_cond_timedwait.3p.html
	 */
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	ret = pthread_cond_init(&qt->cv, &attr);
	pthread_condattr_destroy(&attr);
	if (ret)
		goto err_mem;

	ret = pthread_mutex_init(&qt->mutex, NULL);
	if (ret)
		goto err_cond;

	qt->signalled = false;
	qt->stop = false;
	qt->queue = q;
	snprintf(qt->name, sizeof(qt->name), "%s", name);

	ret = pthread_create(&qt->thread, NULL, queue_thread_run, qt);
	if (ret)
		goto err_mutex;

	return qt;

err_mutex:
	pthread_mutex_destroy(&qt->mutex);
err_cond:
	pthread_cond_destroy(&qt->cv);
err_mem:
	free(qt);

	return NULL;
}

void queue_thread_destroy(struct queue_thread *qt)
{
	pthread_join(qt->thread, NULL);

	pthread_mutex_destroy(&qt->mutex);
	pthread_cond_destroy(&qt->cv);
	free(qt);
}

void queue_thread_signal(struct queue_thread *qt, bool stop)
{
	pthread_mutex_lock(&qt->mutex);
	qt->signalled = true;
	if (!qt->stop)
		qt->stop = stop;
	pthread_cond_signal(&qt->cv);
	pthread_mutex_unlock(&qt->mutex);
}

/* queue thread main function */
static void *queue_thread_run(void *arg)
{
	struct queue_thread *qt = arg;
	struct ocf_queue *q = qt->queue;

	syslog(LOG_INFO, "Thread %s started\n", qt->name);

	pthread_mutex_lock(&qt->mutex);

	while (!qt->stop || qt->signalled) {
		if (qt->signalled) {
			qt->signalled = false;
			pthread_mutex_unlock(&qt->mutex);

			/* execute items on the queue */
			ocf_queue_run(q);

			pthread_mutex_lock(&qt->mutex);
		}

		if (!qt->stop && !qt->signalled)
			pthread_cond_wait(&qt->cv, &qt->mutex);
	}

	pthread_mutex_unlock(&qt->mutex);
	syslog(LOG_DEBUG, "Still pending %d IO requests\n", ocf_queue_pending_io(q));
	syslog(LOG_INFO, "Thread %s stopped\n", qt->name);

	pthread_exit(0);
}

int queue_thread_init(struct ocf_queue *queue, const char *name)
{
	struct queue_thread *qt = queue_thread_create(queue, name);

	if (!qt) {
		queue_thread_signal(qt, true);
		queue_thread_destroy(qt);
		return 1;
	}

	ocf_queue_set_priv(queue, qt);

	return 0;
}

/* callback for OCF to stop the queue thread */
void queue_thread_stop(ocf_queue_t q)
{
	struct queue_thread *qt = ocf_queue_get_priv(q);

	queue_thread_signal(qt, true);
	queue_thread_destroy(qt);

	ocf_queue_set_priv(q, NULL);
}

/* callback for OCF to kick the queue thread */
void queue_thread_kick(ocf_queue_t q)
{
	struct queue_thread *qt = ocf_queue_get_priv(q);

	queue_thread_signal(qt, false);
}

/*========================================================*/

/* queue thread main function */
static void *cleaner_thread_run(void *);

/* helper class to store all synchronization related objects */
struct cleaner_thread
{
	char name[MAX_THREAD_NAME_SIZE];
	/* thread running the queue */
	pthread_t thread;
	/* kick sets true, queue thread sets to false */
	bool signalled;
	/* request thread to exit */
	bool stop;
	/* conditional variable to sync queue thread and kick thread */
	pthread_cond_t cv;
	/* mutex for variables shared across threads */
	pthread_mutex_t mutex;
	/* associated OCF queue */
	ocf_cleaner_t cleaner;
	void *sync_data;
	env_completion sync_compl;
};

struct cleaner_thread *cleaner_thread_create(ocf_cleaner_t c, const char *name)
{
	struct cleaner_thread *ct = malloc(sizeof(*ct));
	int ret;

	if (!ct)
		return NULL;

	ret = pthread_cond_init(&ct->cv, NULL);
	if (ret)
		goto err_mem;

	ret = pthread_mutex_init(&ct->mutex, NULL);
	if (ret)
		goto err_cond;

	ct->signalled = false;
	ct->stop = false;
	ct->cleaner = c;
	snprintf(ct->name, sizeof(ct->name), "%s", name);

	ret = pthread_create(&ct->thread, NULL, cleaner_thread_run, ct);
	if (ret)
		goto err_mutex;

	return ct;

err_mutex:
	pthread_mutex_destroy(&ct->mutex);
err_cond:
	pthread_cond_destroy(&ct->cv);
err_mem:
	free(ct);

	return NULL;
}

void cleaner_thread_destroy(struct cleaner_thread *ct)
{
	pthread_join(ct->thread, NULL);

	pthread_mutex_destroy(&ct->mutex);
	pthread_cond_destroy(&ct->cv);
	free(ct);
}

void cleaner_thread_signal(struct cleaner_thread *ct, bool stop)
{
	pthread_mutex_lock(&ct->mutex);
	ct->signalled = true;
	if (!ct->stop)
		ct->stop = stop;
	pthread_cond_signal(&ct->cv);
	pthread_mutex_unlock(&ct->mutex);
}

static void _cas_cleaner_complete(ocf_cleaner_t c, uint32_t interval)
{
	struct cleaner_thread *ct = ocf_cleaner_get_priv(c);
	uint32_t *ms = ct->sync_data;

	*ms = interval;
	env_completion_complete(&ct->sync_compl);
}

static long long tm_to_ns(struct timespec tm)
{
	return tm.tv_sec * 1000000000 + tm.tv_nsec;
}

static struct timespec ns_to_tm(long long ns)
{
	struct timespec tm;
	tm.tv_sec = ns / 1000000000;
	tm.tv_nsec = ns - (tm.tv_sec * 1000000000);
	return tm;
}

/* queue thread main function */
static void *cleaner_thread_run(void *arg)
{
	struct cleaner_thread *ct = arg;
	ocf_cleaner_t c = ct->cleaner;
	ocf_cache_t cache = ocf_cleaner_get_cache(c);
	struct cache_priv *cache_priv = ocf_cache_get_priv(cache);
	uint32_t ms;

	ENV_BUG_ON(!cache_priv);
	syslog(LOG_INFO, "Thread %s started\n", ct->name);

	ct->sync_data = &ms;
	ocf_cleaner_set_cmpl(c, _cas_cleaner_complete);

	env_completion_init(&ct->sync_compl);
	pthread_mutex_lock(&ct->mutex);

	while (!ct->stop || ct->signalled) {
		if (ct->signalled) {
			ct->signalled = false;
			pthread_mutex_unlock(&ct->mutex);

			env_completion_init(&ct->sync_compl);
			ocf_cleaner_run(c, cache_priv->io_queues[0]);//TODO:smp_processor_id()
			env_completion_wait(&ct->sync_compl);

			pthread_mutex_lock(&ct->mutex);
		}

		if (!ct->stop && !ct->signalled) {
			/*
			 * In case of nop cleaning policy we don't want to perform cleaning
			 * until cleaner_kick() is called.
			 */
			if (ms == OCF_CLEANER_DISABLE) {
				pthread_cond_wait(&ct->cv, &ct->mutex);
			} else {
				struct timespec beg_tm = {};
				struct timespec end_tm = {};
				clock_gettime(CLOCK_MONOTONIC, &beg_tm);
				end_tm = ns_to_tm(tm_to_ns(beg_tm) + ms * 1000000);
				pthread_cond_timedwait(&ct->cv, &ct->mutex, &end_tm);
			}
		}
	}

	pthread_mutex_unlock(&ct->mutex);
	env_completion_destroy(&ct->sync_compl);
	//syslog(LOG_DEBUG, "Still pending %d IO requests\n", ocf_queue_pending_io(c->io_queue));
	syslog(LOG_INFO, "Thread %s stopped\n", ct->name);

	pthread_exit(0);
}
int cleaner_thread_init(ocf_cleaner_t c, const char *name)
{
	struct cleaner_thread *ct = cleaner_thread_create(c, name);

	if (!ct) {
		cleaner_thread_signal(ct, true);
		cleaner_thread_destroy(ct);
		return 1;
	}

	ocf_cleaner_set_priv(c, ct);

	return 0;
}

/* callback for OCF to stop the queue thread */
void cleaner_thread_stop(ocf_cleaner_t c)
{
	struct cleaner_thread *ct = ocf_cleaner_get_priv(c);

	cleaner_thread_signal(ct, true);
	cleaner_thread_destroy(ct);

	ocf_cleaner_set_priv(c, NULL);
}

/* callback for OCF to kick the queue thread */
void cleaner_thread_kick(ocf_cleaner_t c)
{
	struct cleaner_thread *ct = ocf_cleaner_get_priv(c);

	cleaner_thread_signal(ct, false);
}

