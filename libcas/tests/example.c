#include <stdint.h>
#include <stdlib.h>
#include "libcas.h"
#include "cas_ioctl_codes.h"
#include "cas_cache.h"

static uint16_t g_cache_id = 1;
static uint16_t g_core_id = 1;

static void *xvalloc(size_t size)
{
        void    *ret = NULL;
        int     err = posix_memalign((void **)&ret, getpagesize(), size);

        if (unlikely(err)) {
                assert(0);
        }   

        memset(ret, 0, size);
        return ret;
}

static void test_add_cache(void)
{
	struct kcas_start_cache cmd_info = {};
	struct ocf_mngt_cache_config cfg;
	struct ocf_mngt_cache_attach_config attach_cfg;

	snprintf(cmd_info.cache_path_name, sizeof(cmd_info.cache_path_name), "%s", "/dev/loop0");
	cmd_info.caching_mode = ocf_cache_mode_wb;
	cmd_info.init_cache = CACHE_INIT_NEW;
	cmd_info.cache_id = g_cache_id;
	cmd_info.force = 1;
	cmd_info.line_size = 4 * KiB;

	int retval = cache_mngt_create_cache_cfg(&cfg, &attach_cfg, &cmd_info);
	assert(!retval);
	retval = cache_mngt_init_instance(&cfg, &attach_cfg, &cmd_info);
	assert(retval == 0);
}

static void test_add_core(void)
{
	struct kcas_insert_core cmd_info = {};
	struct ocf_mngt_core_config cfg;
	char cache_name[OCF_CACHE_NAME_SIZE];

	snprintf(cmd_info.core_path_name, sizeof(cmd_info.core_path_name), "%s", "/dev/loop1");
	cmd_info.cache_id = g_cache_id;
	cmd_info.core_id = g_core_id;

	cache_name_from_id(cache_name, cmd_info.cache_id);

	int retval = cache_mngt_prepare_core_cfg(&cfg, &cmd_info);
	assert(!retval);

	retval = cache_mngt_add_core_to_cache(cache_name,
			OCF_CACHE_NAME_SIZE, &cfg, &cmd_info);
	assert(retval == 0);
}

static void test_load_cache(void)
{
	struct kcas_start_cache cmd_info = {};
	struct ocf_mngt_cache_config cfg;
	struct ocf_mngt_cache_attach_config attach_cfg;

	snprintf(cmd_info.cache_path_name, sizeof(cmd_info.cache_path_name), "%s", "/dev/loop0");
	cmd_info.caching_mode = ocf_cache_mode_none;
	cmd_info.init_cache = CACHE_INIT_LOAD;
	cmd_info.cache_id = OCF_CACHE_ID_INVALID;
	cmd_info.force = 0;
	cmd_info.line_size = ocf_cache_line_size_none;

	int retval = cache_mngt_create_cache_cfg(&cfg, &attach_cfg, &cmd_info);
	assert(!retval);
	retval = cache_mngt_init_instance(&cfg, &attach_cfg, &cmd_info);
	assert(retval == 0);
}


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

	void *vb_obj = NULL;
	char *data = xvalloc(1 << 12);
	memset(data, 'a', 1 << 12);
	struct cas_aio aio = {};

	int type = atoi(argv[1]);
	switch (type) {
		case 0:
			while(1) {
				sleep(1);
			}
			break;
		case 1:
			/*add cache*/
			test_add_cache();

			/*add core*/
			test_add_core();

			/*test io*/
			vb_obj = cas_lookup_vb_obj(g_cache_id, g_core_id);
			if (!vb_obj)
				return -1;

			aio.vb_vec.iov_base = data;
			aio.vb_vec.iov_len = 1 << 12;
			aio.vb_offset = 0;
			aio.vb_length = 1 << 12;
			aio.type = CAS_AIO_TYPE_WRITE;
			cas_completion_init(&aio.cmpl);
			cas_submit_vb_aio(vb_obj, &aio);
			cas_completion_wait(&aio.cmpl);
			assert(aio.result == 0);

			int i;
			for (i = 0; i < 153000; i++) {
				aio.vb_offset = (1 << 12) * i;
				cas_completion_init(&aio.cmpl);
				cas_submit_vb_aio(vb_obj, &aio);
				cas_completion_wait(&aio.cmpl);
				assert(aio.result == 0);
			}

			memset(data, 0, 1 << 12);

			aio.type = CAS_AIO_TYPE_READ;
			cas_completion_init(&aio.cmpl);
			cas_submit_vb_aio(vb_obj, &aio);
			cas_completion_wait(&aio.cmpl);
			assert(aio.result == 0);

			printf("%s\n", data);
			break;
		case 2:
			/*load cache*/
			test_load_cache();

			/*test io*/
			vb_obj = cas_lookup_vb_obj(g_cache_id, g_core_id);
			if (!vb_obj)
				return -1;

			aio.vb_vec.iov_base = data;
			aio.vb_vec.iov_len = 1 << 12;
			aio.vb_offset = 0;
			aio.vb_length = 1 << 12;
			aio.type = CAS_AIO_TYPE_READ;
			cas_completion_init(&aio.cmpl);
			cas_submit_vb_aio(vb_obj, &aio);
			cas_completion_wait(&aio.cmpl);
			assert(aio.result == 0);

			printf("%s\n", data);
			break;
		default:
			break;
	}
	return 0;
}

