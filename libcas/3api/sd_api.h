#pragma once

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DISK_MAX                                64
#define DISK_LEN                                128
#define STORAGE_LEN                             16
#define MAX_POOL_ADDRESS_LEN                    1024
#define SD_MAX_VOLUME_NAME_LEN                  256U
#define SD_MAX_SNAPSHOT_NAME_LEN                256U
#define SD_VOLUME_METADATA_BITMAP_SNAPSHOT_SIZE 8192 /* 8k */
#define SD_VOLUME_METADATA_SERIAL_SNAPSHOT_SIZE 524288 /* 512k */
#define SD_VOLUME_METADATA_BRANCH_SNAPSHOT_SIZE 524288 /* 512k */
#define SD_MAX_NR_VOLUMES               (UINT32_C(1) << 16)	/*0 is not use*/
#define SD_VID_SHIFT                    44
#define SD_SID_SHIFT                    28
#define MAX_NODE_ID_IDENT               128

#define DIV_ROUND_UP(n, d)      (((n) + (d) - 1) / (d))
#define BITS_PER_BYTE   8
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define DECLARE_BITMAP(name, bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

static inline uint64_t form_to_data_oid(uint32_t vid, uint32_t sid, uint64_t idx)
{
	return ((uint64_t)vid << SD_VID_SHIFT) | ((uint64_t)sid << SD_SID_SHIFT) | idx;
}

static inline const char *sd_strerror(int err)
{
	static __thread char msg[32];
	snprintf(msg, sizeof(msg), "Error code 0x%x", err);
	return msg;
}

enum log_dst_type
{
	LOG_DST_DEFAULT,
	LOG_DST_STDOUT,
	LOG_DST_SYSLOG,
};

enum volume_state {
	VOLUME_STATE_NOTHING = 0,
	VOLUME_STATE_PROCESS,
	VOLUME_STATE_SUCCESS,
	VOLUME_STATE_FAILURE,
} __attribute__ ((__packed__));

enum snapshot_state {
	SNAPSHOT_STATE_NOTHING = 0,
	SNAPSHOT_STATE_PROCESS,
	SNAPSHOT_STATE_SUCCESS,
	SNAPSHOT_STATE_FAILURE,
} __attribute__ ((__packed__));

enum snapshot_type {
	SD_SNAPSHOT_TYPE_ROW,
	SD_SNAPSHOT_TYPE_COW,
} __attribute__ ((__packed__));

struct snapshot_note
{
	uint32_t        volume_sid;
	uint32_t        object_sid;
};

/* 
 * BE CAREFUL: need align.
 */
struct volume_item
{
	uint8_t         bitmap_snapshot[SD_VOLUME_METADATA_BITMAP_SNAPSHOT_SIZE]; /* 8K-sized snapshot bitmap area, total 2^16 snaps */
	struct snapshot_note serial_snapshot[SD_VOLUME_METADATA_SERIAL_SNAPSHOT_SIZE >> 3];	/* 512K-sized snapshot serial area, total 2^16 snaps*/
	struct snapshot_note branch_snapshot[SD_VOLUME_METADATA_BRANCH_SNAPSHOT_SIZE >> 3];	/* 512K-sized snapshot branch area, total 2^16 snaps*/
	uint16_t        nr_serial_snapshot;
	uint16_t        nr_branch_snapshot;
	uint8_t         cas;		/* 是否是cas卷 */
	uint8_t		pad[3];

	char            name[SD_MAX_VOLUME_NAME_LEN];
	uint32_t        version;	/* need update from volume_storage's version */
	uint32_t        vid;
	uint64_t        volume_size;
	uint64_t        create_time;
	uint8_t         thick;		/* thick provisioning */
	uint8_t         chunk_size_shift;

	uint8_t         flags;
	enum snapshot_type snapshot_type;
	uint32_t        last_sid;
	uint32_t        origin_vid;
	uint32_t        origin_sid;

	char		basic_address[MAX_POOL_ADDRESS_LEN];
	char		cache_address[MAX_POOL_ADDRESS_LEN];
};

/* 
 * BE CAREFUL: need align.
 */
struct snapshot_item
{
	struct snapshot_note serial_snapshot[SD_VOLUME_METADATA_SERIAL_SNAPSHOT_SIZE >> 3];	/* 512K-sized snapshot serial area, total 2^16 snaps*/
	uint16_t        nr_serial_snapshot;
	uint8_t         cas;		/* 是否是cas卷 */
	uint8_t		pad[5];

	char            name[SD_MAX_SNAPSHOT_NAME_LEN];
	uint32_t        sid;
	uint32_t        vid;
	uint64_t        volume_size;
	uint64_t        create_time;
	uint8_t         thick;		/* thick provisioning */
	uint8_t         chunk_size_shift;
	uint8_t		pad1[6];

	char		cache_address[MAX_POOL_ADDRESS_LEN];
};

struct api_volume_info {
	struct volume_item item;
	uint32_t create_iters;
	uint32_t delete_iters;
	enum volume_state create_state;
	enum volume_state delete_state;
};

struct api_volume_list {
	union {
		DECLARE_BITMAP(volume_bitmaps, SD_MAX_NR_VOLUMES);
		struct {
			uint32_t    nr_items;
			struct volume_item items[0];
		};
	};
};

struct api_snapshot_info {
	struct snapshot_item item;
	uint32_t create_iters;
	uint32_t delete_iters;
	enum snapshot_state create_state;
	enum snapshot_state delete_state;
};

struct api_snapshot_list {
	struct volume_item vitem;
	struct snapshot_item sitems[0];
};

struct vs_id {
	uint32_t        vid;
	uint32_t        sid;
};

struct api_snapshot_create {
	char            name[SD_MAX_SNAPSHOT_NAME_LEN];
	uint32_t        vid;
	bool		global;
	char		*batch;
	bool		feign;
};

typedef void (*COMMGFD_POLL_CB)(int efd, void *usr);
struct api_session;
void sd_api_init(void);
struct api_session *sd_api_session_get(char *addr_list);
int sd_api_session_put(struct api_session *s);
void sd_api_set_pcb(struct api_session *s, COMMGFD_POLL_CB ctl_pcb, COMMGFD_POLL_CB rw_pcb);

int sd_api_volume_info(struct api_session *s, struct api_volume_info *info, uint32_t vid);
int sd_api_volume_list(struct api_session *s, struct api_volume_list **list, bool detail);

int sd_api_snapshot_info(struct api_session *s, struct api_snapshot_info *info, uint32_t vid, uint32_t sid);
int sd_api_snapshot_list(struct api_session *s, struct api_snapshot_list **list, uint32_t vid, bool detail);

int sd_api_snapshot_create(struct api_session *s, char ident[MAX_NODE_ID_IDENT],
		struct api_snapshot_create *params, uint32_t *nr_vs_id, struct vs_id vs_id[SD_MAX_NR_VOLUMES]);

int sd_api_volume_obj_read(struct api_session *s, struct volume_item *vitem,
		uint64_t oid, void *data, uint64_t length, uint64_t offset);
int sd_api_volume_obj_write(struct api_session *s, struct volume_item *vitem,
		uint64_t oid, void *data, uint64_t length, uint64_t offset);

int sd_api_volume_read(struct api_session *s, struct volume_item *vitem,
		uint32_t vid, void *data, uint64_t length, uint64_t offset);
int sd_api_volume_write(struct api_session *s, struct volume_item *vitem,
		uint32_t vid, void *data, uint64_t length, uint64_t offset);
#ifdef __cplusplus
}
#endif
