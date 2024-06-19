#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include "libcas.h"
#include "../3api/sd_api.h"

static uint32_t g_cache_id = 1;
static uint16_t g_core_id = 1;
enum log_dst_type       g_log_dst_type = LOG_DST_SYSLOG;

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage:\n"
			"\t./example [type]\n"
			"\t\t0----->run as one daemon\n"
			"\t\t1----->test new cache and core to write and read\n"
			"\t\t2----->test load cache to read\n");
		return -1;
	}

	int ret = cas_init_module();
	if (ret)
		return -1;

	bool have = false;
	char *data = malloc(1 << 22);
	memset(data, 'a', 1 << 22);
	struct cas_aio aio = {};
	cas_completion_t cmpl;
	typedef void (*CAS_AIO_CMPL)(void *args);
	aio.cmpl_func = (CAS_AIO_CMPL)cas_completion_complete;
	aio.cmpl_args = &cmpl;

	int type = atoi(argv[1]);
	switch (type) {
		case 0:
			while(1) {
				sleep(1);
			}
			break;
		case 1:
			/*add cache*/
			ret = cas_format_cache(g_cache_id, "/dev/loop0", 12, "wf");
			assert(!ret);
			/*flush wait 10ms each cycle*/
			ret = cas_set_cache_param(g_cache_id, cas_cache_param_cleaning_alru_wake_up_time, 10);
			assert(!ret);
			/*no merge*/
			ret = cas_set_cache_param(g_cache_id, cas_cache_param_cleaning_alru_flush_split_unit, 1);
			assert(!ret);
			/*flush 128 dirty cachelines each cycle*/
			ret = cas_set_cache_param(g_cache_id, cas_cache_param_cleaning_alru_flush_max_buffers, 128);
			assert(!ret);
			/*flush no wait when no IO activity detected for 1000(ms)*/
			ret = cas_set_cache_param(g_cache_id, cas_cache_param_cleaning_alru_activity_threshold, 1000);
			assert(!ret);
			/*flush no wait when dirty overflow 100% of total cachelines*/
			ret = cas_set_cache_param(g_cache_id, cas_cache_param_cleaning_alru_dirty_overflow_threshold, 100);
			assert(!ret);

			/*add core*/
			ret = cas_append_core_to_cache(g_cache_id, g_core_id, "/dev/loop1");
			assert(!ret);

			/*test io*/
			have = cas_lookup_vb_obj(g_cache_id, g_core_id);
			if (!have)
				return -1;

			aio.vb_vec.iov_base = data;
			aio.vb_vec.iov_len = 1 << 12;
			aio.vb_offset = 0;
			aio.vb_length = 1 << 12;
			aio.type = CAS_AIO_TYPE_WRITE;
			cas_completion_init(&cmpl);
			cas_submit_vb_aio(g_cache_id, g_core_id, &aio);
			cas_completion_wait(&cmpl);
			assert(aio.result == 0);

			int i;
			for (i = 0; i < 153000; i++) {
				aio.vb_offset = (1 << 12) * i;
				cas_completion_init(&cmpl);
				cas_submit_vb_aio(g_cache_id, g_core_id, &aio);
				cas_completion_wait(&cmpl);
				assert(aio.result == 0);
			}

			memset(data, 0, 1 << 12);

			aio.type = CAS_AIO_TYPE_READ;
			cas_completion_init(&cmpl);
			cas_submit_vb_aio(g_cache_id, g_core_id, &aio);
			cas_completion_wait(&cmpl);
			assert(aio.result == 0);

			struct cas_usage usage = {};
			ret = cas_usage_cache(g_cache_id, &usage);
			assert(!ret);

			ret = cas_stop_cache(g_cache_id, 0);
			assert(!ret);

			printf("%s\n", data);
			printf("==occupancy==%lu\n", usage.occupancy);
			printf("==free==%lu\n", usage.free);
			printf("==clean==%lu\n", usage.clean);
			printf("==dirty==%lu\n", usage.dirty);
			break;
		case 2:
			/*load cache*/
			ret = cas_load_cache(g_cache_id, "/dev/loop0");
			assert(!ret);

			/*test io*/
			have = cas_lookup_vb_obj(g_cache_id, g_core_id);
			if (!have)
				return -1;

			aio.vb_vec.iov_base = data;
			aio.vb_vec.iov_len = 1 << 21;
			aio.vb_offset = 0;
			aio.vb_length = 1 << 21;
			aio.type = CAS_AIO_TYPE_WRITE;
			cas_completion_init(&cmpl);
			cas_submit_vb_aio(g_cache_id, g_core_id, &aio);
			cas_completion_wait(&cmpl);
			assert(aio.result == 0);

			aio.vb_vec.iov_base = data + (1 << 21);
			aio.vb_vec.iov_len = 1 << 21;
			aio.vb_offset = 1 << 21;
			aio.vb_length = 1 << 21;
			aio.type = CAS_AIO_TYPE_WRITE;
			cas_completion_init(&cmpl);
			cas_submit_vb_aio(g_cache_id, g_core_id, &aio);
			cas_completion_wait(&cmpl);
			assert(aio.result == 0);
			printf("%s\n", data);
			break;
		case 3:
			/*load cache*/
			ret = cas_load_cache(g_cache_id, "/dev/loop0");
			assert(!ret);

			char snapshot_cache_path_name[PATH_MAX] = {};
			ret = cas_snapshot_cache(g_cache_id, g_cache_id + 1, snapshot_cache_path_name);
			assert(!ret);
			printf("snapshot cache: %s\n", snapshot_cache_path_name);

			ret = cas_snapshot_cache(g_cache_id, g_cache_id + 2, snapshot_cache_path_name);
			assert(!ret);
			printf("snapshot cache: %s\n", snapshot_cache_path_name);

			/*test io*/
			have = cas_lookup_vb_obj(g_cache_id, g_core_id);
			assert(have);
			break;
		default:
			break;
	}
	return 0;
}

