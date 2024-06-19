#pragma once

#include <pthread.h>
#include <sys/prctl.h>

struct ctask_context;
typedef void (*ctask_ctx_init_func) (struct ctask_context *);
typedef void (*ctask_ctx_exit_func) (struct ctask_context *);

struct ctask_context {
	char name[64];
	pthread_t pid;
	env_completion cmpl;
	env_atomic stop;
	struct co_scheduler *scheduler;

	ctask_ctx_init_func ctx_init_fn;
	ctask_ctx_exit_func ctx_exit_fn;

	void *data;
};

static inline void __ctask_thread_exit_cleanup(void *usr)
{
	struct ctask_context *ctx = usr;
	if (ctx->ctx_exit_fn)
		ctx->ctx_exit_fn(ctx);
	cosched_destroy(ctx->scheduler);
}

static inline void *_ctask_thread_start(void *arg)
{
	struct ctask_context *ctx = arg;

	prctl(PR_SET_NAME, ctx->name);
	ctx->scheduler = cosched_default();

	if (ctx->ctx_init_fn)
		ctx->ctx_init_fn(ctx);
	pthread_cleanup_push(__ctask_thread_exit_cleanup, ctx);

	env_completion_complete(&ctx->cmpl);

	while (!env_atomic_read(&ctx->stop)) {
		cosched_loop(ctx->scheduler, EVRUN_ONCE);
	}

	env_completion_wait(&ctx->cmpl);
	env_completion_destroy(&ctx->cmpl);

	pthread_cleanup_pop(1); /* do exit cleanup */
	pthread_exit(NULL);
}

static inline int ctask_thread_open(struct ctask_context *ctx,
		ctask_ctx_init_func ifn, ctask_ctx_exit_func efn, void *data,
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

	int ret = pthread_create(&ctx->pid, NULL, _ctask_thread_start, ctx);

	if (ret == 0) {
		env_completion_wait(&ctx->cmpl);
		env_completion_destroy(&ctx->cmpl);
	} else {
		fprintf(stderr, "failed to create a worker thread %s:%s\n", ctx->name, strerror(ret));
	}

	return ret;
}

static inline void ctask_thread_close(struct ctask_context *ctx)
{
	env_completion_init(&ctx->cmpl);

	env_atomic_set(&ctx->stop, 1);
	cosched_notify(ctx->scheduler);

	env_completion_complete(&ctx->cmpl);
	//pthread_cancel(ctx->pid);
	pthread_join(ctx->pid, NULL);
}

static inline int ctask_thread_submit(struct ctask_context *ctx, void (*func)(void *), void *user, size_t ss)
{
	return cotask_exec(ctx->scheduler, func, user, ss);
}
