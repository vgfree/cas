#pragma once
#include <sys/uio.h>
#include <stdint.h>
#include <semaphore.h>

typedef struct cas_completion {
	sem_t sem;
} cas_completion_t;

static inline void cas_completion_init(cas_completion_t *completion)
{
	sem_init(&completion->sem, 0, 0);
}

static inline void cas_completion_wait(cas_completion_t *completion)
{
	sem_wait(&completion->sem);
}

static inline void cas_completion_complete(cas_completion_t *completion)
{
	sem_post(&completion->sem);
}

static inline void cas_completion_destroy(cas_completion_t *completion)
{
	sem_destroy(&completion->sem);
}

struct cas_aio {
	struct iovec vb_vec;
	uint64_t vb_offset;
	uint64_t vb_length;
	enum {
		CAS_AIO_TYPE_READ,
		CAS_AIO_TYPE_WRITE,
		CAS_AIO_TYPE_FLUSH,
		CAS_AIO_TYPE_DISCARD,
	} type;
	cas_completion_t cmpl;
	int result;
};

int cas_init_module(void);

void cas_exit_module(void);

void *cas_lookup_vb_obj(uint16_t cache_id, uint16_t core_id);

int cas_submit_vb_aio(void *obj, struct cas_aio *aio);

uint64_t cas_obtain_vb_len(void *obj);
