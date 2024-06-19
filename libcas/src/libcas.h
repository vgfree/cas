#pragma once
#include <errno.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <semaphore.h>

enum cas_cache_param_id {
	cas_cache_param_cleaner_policy_control,
	cas_cache_param_cleaning_policy_type,
	cas_cache_param_cleaning_alru_wake_up_time,
	cas_cache_param_cleaning_alru_flush_split_unit,
	cas_cache_param_cleaning_alru_flush_max_buffers,
	cas_cache_param_cleaning_alru_activity_threshold,
	cas_cache_param_cleaning_alru_dirty_overflow_threshold,
	cas_cache_param_cleaning_acp_wake_up_time,
	cas_cache_param_cleaning_acp_flush_split_unit,
	cas_cache_param_cleaning_acp_flush_max_buffers,
	cas_cache_param_cleaning_acp_activity_threshold,
	cas_cache_param_cleaning_acp_dirty_overflow_threshold,
	cas_cache_param_promotion_policy_type,
	cas_cache_param_promotion_nhit_insertion_threshold,
	cas_cache_param_promotion_nhit_trigger_threshold,
	cas_cache_param_id_max,
};

typedef struct cas_completion {
	sem_t sem;
} cas_completion_t;

static inline void cas_completion_init(cas_completion_t *completion)
{
	sem_init(&completion->sem, 0, 0);
}

static inline void cas_completion_wait(cas_completion_t *completion)
{
	int ret;
	do {
		ret = sem_wait(&completion->sem);
	} while ((ret < 0) && (errno == EAGAIN || errno == EINTR));
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
	void (*cmpl_func)(void *cmpl_args);
	void *cmpl_args;
	int result;
};

/*
 * total = occupancy + free
 * occupancy = clean + dirty
 */
struct cas_usage {
	uint64_t occupancy;
	uint64_t free;
	uint64_t clean;
	uint64_t dirty;
};

int cas_init_module(void);

void cas_exit_module(void);

bool cas_lookup_vb_obj(uint32_t cache_id, uint16_t core_id);

int cas_submit_vb_aio(uint32_t cache_id, uint16_t core_id, struct cas_aio *aio);

uint64_t cas_obtain_vb_len(uint32_t cache_id, uint16_t core_id);

int cas_format_cache(uint32_t cache_id, char *path, uint16_t line_shift, char *mode_name);

int cas_append_core_to_cache(uint32_t cache_id, uint16_t core_id, char *path);

int cas_cache_add_core(uint32_t cache_id, uint16_t *core_id, char *path);

int cas_cache_del_core(uint32_t cache_id, uint16_t core_id, uint8_t flush_data);

int cas_stop_cache(uint32_t cache_id, uint8_t flush_data);

int cas_load_cache(uint32_t cache_id, char *path);

int cas_resume_cache(uint32_t cache_id);

int cas_hook_cache_submit_set(uint32_t cache_id, int (*func)(void *args), void *args);

int cas_hook_cache_submit_get(uint32_t cache_id, int (**func)(void *args), void **args);

int cas_snapshot_cache(uint32_t volume_cache_id, uint32_t snapshot_cache_id, char snapshot_cache_path_name[PATH_MAX]);

int cas_usage_cache(uint32_t cache_id, struct cas_usage *usage);

int cas_set_cache_param(uint32_t cache_id, enum cas_cache_param_id param_id, uint32_t param_value);
