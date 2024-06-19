#pragma once

#include <stdint.h>
#include <stdbool.h>

#define EV_READ	0x01
#define EVRUN_ONCE	2

struct co_scheduler;
struct co_scheduler *cosched_default(void);
void cosched_destroy(struct co_scheduler *trq);
void cosched_notify(struct co_scheduler *trq);
int cosched_loop(struct co_scheduler *trq, int flags);
int cotask_exec_with_prio(struct co_scheduler *, void (*)(void *), void *, size_t, int32_t);
static inline int cotask_exec(struct co_scheduler *rq, void (*func)(void *), void *user, size_t ss)
{
    return cotask_exec_with_prio(rq, func, user, ss, 0);
}
int __cotask_event(int fd, int ev, int timeout, bool ignore);
static inline int cotask_event(int fd, int ev, int timeout)
{
    return __cotask_event(fd, ev, timeout, true);
}
