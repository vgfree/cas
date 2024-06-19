#pragma once

#include <pthread.h>
#include <sys/prctl.h>
#include <sys/eventfd.h>

#define MAX_EPOLL_SIZE	10240
#define MAX_EPOLL_UNIT	1024
#define MAX_EPOLL_TIME	20	/* 以毫秒(ms)为单位 */

struct etask_context;
typedef void (*etask_ctx_init_func) (struct etask_context *);
typedef void (*etask_ctx_exit_func) (struct etask_context *);

struct etask_context;
struct etask_message {
	struct list_node node;
	int fd;
	uint32_t events;
	void (*do_task)(struct etask_context *ctx, struct etask_message *msg, uint32_t events);
	void *data;
};

struct etask_context {
	char name[64];
	pthread_t pid;
	env_completion cmpl;
	env_atomic stop;
	int epfd;
	int evfd;
	struct etask_message emsg;
	struct list_head list;
	pthread_mutex_t lock;

	etask_ctx_init_func ctx_init_fn;
	etask_ctx_exit_func ctx_exit_fn;

	void *data;
};

static inline void __etask_msg_register(struct etask_context *ctx, struct etask_message *msg, uint32_t events)
{
        assert(events & EPOLLIN);
	assert(ctx->evfd == msg->fd);

        eventfd_t       val;
        int             ret;

        do {
                ret = eventfd_read(ctx->evfd, &val);
        } while ((ret < 0) && (errno == EINTR));

        if ((ret != 0) && (errno != EAGAIN)) {
		abort();
        }

	if (val) {
		struct etask_message *tmp;
		pthread_mutex_lock(&ctx->lock);
		list_for_each_entry_safe(msg, tmp, &ctx->list, node) {
			list_del(&msg->node);

			struct epoll_event evt = {};
			evt.events = msg->events;
			evt.data.ptr = msg;

			int ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, msg->fd, &evt);
			assert(!ret);
		}
		pthread_mutex_unlock(&ctx->lock);
	}
}

static inline void _etask_ctx_main(struct etask_context *ctx, struct epoll_event *evt)
{
	struct etask_message *msg = (struct etask_message *)evt->data.ptr;
	msg->do_task(ctx, msg, evt->events);
}

static inline void _etask_ctx_init(struct etask_context *ctx)
{
	ctx->epfd = epoll_create(MAX_EPOLL_SIZE);

	INIT_LIST_HEAD(&ctx->list);
	pthread_mutex_init(&ctx->lock, NULL);

	int evfd = eventfd(0, EFD_NONBLOCK);
	assert(evfd >= 0);

	struct etask_message *msg = &ctx->emsg;
	msg->do_task = __etask_msg_register;
	msg->fd = evfd;

	struct epoll_event evt = {};
	evt.events = EPOLLERR | EPOLLIN;
	evt.data.ptr = msg;

	int ret = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, evfd, &evt);
	assert(!ret);

	ctx->evfd = evfd;
}

static inline void _etask_ctx_exit(struct etask_context *ctx)
{
	struct epoll_event evt = {};
	evt.events = -1;
	evt.data.ptr = NULL;

        int ret = epoll_ctl(ctx->epfd, EPOLL_CTL_DEL, ctx->evfd, &evt);
	assert(!ret);

	close(ctx->evfd);
	close(ctx->epfd);

	pthread_mutex_destroy(&ctx->lock);
}

static inline void __etask_thread_exit_cleanup(void *usr)
{
	struct etask_context *ctx = usr;

	if (ctx->ctx_exit_fn)
		ctx->ctx_exit_fn(ctx);

	_etask_ctx_exit(ctx);
}

static inline void *_etask_thread_start(void *arg)
{
	struct etask_context *ctx = arg;

	prctl(PR_SET_NAME, ctx->name);

	_etask_ctx_init(ctx);

	if (ctx->ctx_init_fn)
		ctx->ctx_init_fn(ctx);
	pthread_cleanup_push(__etask_thread_exit_cleanup, ctx);

	env_completion_complete(&ctx->cmpl);

	struct epoll_event events[MAX_EPOLL_UNIT] = {};
	while (!env_atomic_read(&ctx->stop)) {
		int cnt = epoll_wait(ctx->epfd, events, MAX_EPOLL_UNIT, MAX_EPOLL_TIME);
		for (int i = 0; i < cnt; i++) {
			struct epoll_event *evt = &events[i];
			_etask_ctx_main(ctx, evt);
		}
	}

	env_completion_wait(&ctx->cmpl);
	env_completion_destroy(&ctx->cmpl);

	pthread_cleanup_pop(1); /* do exit cleanup */
	pthread_exit(NULL);
}

static inline int etask_thread_open(struct etask_context *ctx,
		etask_ctx_init_func ifn, etask_ctx_exit_func efn, void *data,
		const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(ctx->name, sizeof(ctx->name), fmt, args);
	va_end(args);

	ctx->ctx_init_fn = ifn;
	ctx->ctx_exit_fn = efn;
	ctx->data = data;
	env_completion_init(&ctx->cmpl);
	env_atomic_set(&ctx->stop, 0);

	int ret = pthread_create(&ctx->pid, NULL, _etask_thread_start, ctx);

	if (ret == 0) {
		env_completion_wait(&ctx->cmpl);
		env_completion_destroy(&ctx->cmpl);
	} else {
		fprintf(stderr, "failed to create a worker thread %s:%s\n", ctx->name, strerror(ret));
	}

	return ret;
}

static inline void etask_thread_close(struct etask_context *ctx)
{
	env_completion_init(&ctx->cmpl);

	env_atomic_set(&ctx->stop, 1);
	eventfd_t val = 1;
	int       ret;

	do {
		ret = eventfd_write(ctx->evfd, val);
	} while ((ret < 0) && (errno == EINTR || errno == EAGAIN));

	if (ret < 0) {
		abort();
	}

	env_completion_complete(&ctx->cmpl);
	//pthread_cancel(ctx->pid);
	pthread_join(ctx->pid, NULL);
}

static inline int etask_thread_submit(struct etask_context *ctx, struct etask_message *msg)
{
	INIT_LIST_NODE(&msg->node);
	pthread_mutex_lock(&ctx->lock);
	list_add_tail(&msg->node, &ctx->list);
	pthread_mutex_unlock(&ctx->lock);

	eventfd_t val = 1;
	int       ret;

	do {
		ret = eventfd_write(ctx->evfd, val);
	} while ((ret < 0) && (errno == EINTR || errno == EAGAIN));

	if (ret < 0) {
		abort();
	}
	return ret;
}
