#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include "libcas.h"
#include "../3api/sd_api.h"

static uint32_t g_cache_id = 1;
static uint16_t g_core_id = 1;
enum log_dst_type       g_log_dst_type = LOG_DST_SYSLOG;
static int g_step = 128;

char g_map1[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
char g_map2[8] = {'1', '2', '3', '4', '5', '6', '7', '8'};
int g_w_shift = 12;
int g_r_shift = 14;
typedef void (*CAS_AIO_CMPL)(void *args);

static void *_run_test(void *usr)
{
	int idx = (uintptr_t)usr;

	struct cas_aio aio = {};
	cas_completion_t cmpl;
	aio.cmpl_func = (CAS_AIO_CMPL)cas_completion_complete;
	aio.cmpl_args = &cmpl;

	/*test io*/
	bool have = cas_lookup_vb_obj(g_cache_id, g_core_id);
	assert(have);

	uint64_t vb_len = cas_obtain_vb_len(g_cache_id, g_core_id);
	assert(vb_len);
	char *data = malloc(1 << g_w_shift);
	uint64_t i = 0;
	do {
		uint64_t line = idx + i * g_step;
		uint64_t offset = line * (1ULL << g_w_shift);
		if (offset >= vb_len)
			break;
		//printf("write offset %ld\n", offset);
		char cstr = (offset < (vb_len/2)) ? g_map1[line % sizeof(g_map1)] : g_map2[line % sizeof(g_map2)];
		memset(data, cstr, 1 << g_w_shift);

		aio.vb_vec.iov_base = data;
		aio.vb_vec.iov_len = 1 << g_w_shift;
		aio.vb_offset = offset;
		aio.vb_length = 1 << g_w_shift;
		aio.type = CAS_AIO_TYPE_WRITE;
		cas_completion_init(&cmpl);
		cas_submit_vb_aio(g_cache_id, g_core_id, &aio);
		cas_completion_wait(&cmpl);
		assert(aio.result == 0);
	} while (++i);
	free(data);

	printf("done write\n");
	return NULL;
}

static void *_run_check(void *usr)
{
	struct cas_aio aio = {};
	cas_completion_t cmpl;
	aio.cmpl_func = (CAS_AIO_CMPL)cas_completion_complete;
	aio.cmpl_args = &cmpl;

	/*test io*/
	bool have = cas_lookup_vb_obj(g_cache_id, g_core_id);
	assert(have);

	char *cmp_data = malloc(1 << g_r_shift);
	uint64_t vb_len = cas_obtain_vb_len(g_cache_id, g_core_id);
	assert(vb_len);
	char *data = malloc(1 << g_r_shift);
	uint64_t i = 0;
	int step = 1 << (g_r_shift - g_w_shift);
	do {
		for (int idx = 0; idx < step; idx ++) {
			uint64_t line = idx + i * step;
			uint64_t offset = line * (1ULL << g_w_shift);
			char cstr = (offset < (vb_len/2)) ? g_map1[line % sizeof(g_map1)] : g_map2[line % sizeof(g_map2)];
			memset(&cmp_data[idx * (1 << g_w_shift)], cstr, 1 << g_w_shift);
		}
		uint64_t line = i * step;
		uint64_t offset = line * (1ULL << g_w_shift);
		if (offset >= vb_len)
			break;
		//printf("read offset %ld\n", offset);

		aio.vb_vec.iov_base = data;
		aio.vb_vec.iov_len = 1 << g_r_shift;
		aio.vb_offset = offset;
		aio.vb_length = 1 << g_r_shift;
		aio.type = CAS_AIO_TYPE_READ;
		cas_completion_init(&cmpl);
		cas_submit_vb_aio(g_cache_id, g_core_id, &aio);
		cas_completion_wait(&cmpl);
		assert(aio.result == 0);

		if (memcmp(cmp_data, data, 1 << g_r_shift)) {
			printf("offset %lu is not ok\n", offset);
			assert(0);
		}
	} while (++i);
	free(data);
	free(cmp_data);

	printf("done read\n");
	return NULL;
}

int main(int argc, char **argv)
{
	int ret = cas_init_module();
	if (ret)
		return -1;

	/*add cache*/
	ret = cas_format_cache(g_cache_id, "/dev/loop0", 13, "wf");
	assert(!ret);

	/*add core*/
	ret = cas_append_core_to_cache(g_cache_id, g_core_id, "/dev/loop1");
	assert(!ret);

	pthread_t pids[g_step];
	for (int i = 0; i < g_step; i ++) {
		pthread_create(&pids[i], NULL, _run_test, (void *)(uintptr_t)i);
	}
	for (int i = 0; i < g_step; i ++) {
		pthread_join(pids[i], NULL);
	}

	_run_check(NULL);
	return 0;
}

