/*
* Copyright(c) 2012-2021 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
#include <linux/fs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include "cas_logger.h"
#include "service_ui_ioctl.h"
#include "control.h"
#include "cas_cache.h"

static int do_read(int fd, void *buf, size_t count)
{
	int rv;
	size_t off = 0;

	while (off < count) {
		rv = read(fd, (char *)buf + off, count - off);
		if (rv == 0)
			return -1;
		if (rv == -1 && errno == EINTR)
			continue;
		if (rv == -1)
			return -1;
		off += rv;
	}
	return 0;
}

static int do_write(int fd, void *buf, size_t count)
{
	int rv, off = 0;

 retry:
	rv = write(fd, (char *)buf + off, count);
	if (rv == -1 && errno == EINTR)
		goto retry;
	if (rv < 0) {
		cas_printf(LOG_ERR, "write errno %d", errno);
		return rv;
	}

	if (rv != count) {
		count -= rv;
		off += rv;
		goto retry;
	}
	return 0;
}


static int setup_listener(const char *sock_path)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	int rv, s;

	/* we listen for new client connections on socket s */

	s = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (s < 0) {
		cas_printf(LOG_ERR, "socket error %d %d", s, errno);
		return s;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strcpy(&addr.sun_path[1], sock_path);
	addrlen = sizeof(sa_family_t) + strlen(addr.sun_path+1) + 1;

	rv = bind(s, (struct sockaddr *) &addr, addrlen);
	if (rv < 0) {
		cas_printf(LOG_ERR, "bind error %d %d", rv, errno);
		close(s);
		return rv;
	}

	rv = listen(s, 5);
	if (rv < 0) {
		cas_printf(LOG_ERR, "listen error %d %d", rv, errno);
		close(s);
		return rv;
	}
	return s;
}


static void cas_query_handle(int fd, struct cas_query_header *h, char *extra)
{
	uint64_t length = h->length - sizeof(struct cas_query_header);

	cas_service_ioctl_ctrl(h->command, extra);//TODO: return error

	cas_query_init_header(h, h->command, length);
	int rv = do_write(fd, h, sizeof(*h));
	if (rv < 0)
		return;

	if (length) {
		rv = do_write(fd, extra, length);
		if (rv < 0)
			return;
	}
}

static void *cas_query_process(void *arg)
{
	struct cas_query_header h;
	int s, f, rv;
	char *extra = NULL;
	int extra_len = 0;
	char sock_path[PATH_MAX] = {};

	prctl(PR_SET_NAME, "control");
	pid_t pid = getpid();
	snprintf(sock_path, sizeof(sock_path), "%s@%d", CAS_QUERY_QUERY_SOCK_PATH, pid);
	rv = setup_listener(sock_path);
	if (rv < 0)
		return NULL;

	s = rv;

	pthread_mutex_t cas_query_mutex;
	pthread_mutex_init(&cas_query_mutex, NULL);
	for (;;) {
		f = accept(s, NULL, NULL);
		if (f < 0)
			return NULL;

		rv = do_read(f, &h, sizeof(h));
		if (rv < 0) {
			goto out;
		}

		if (h.magic != CAS_QUERY_MAGIC) {
			goto out;
		}

		if ((h.version & 0xFFFF0000) != (CAS_QUERY_VERSION & 0xFFFF0000)) {
			goto out;
		}

		if (h.length > sizeof(h)) {
			extra_len = h.length - sizeof(h);
			extra = malloc(extra_len);
			if (!extra) {
				cas_printf(LOG_ERR, "process_connection no mem %d", extra_len);
				goto out;
			}
			memset(extra, 0, extra_len);

			rv = do_read(f, extra, extra_len);
			if (rv < 0) {
				cas_printf(LOG_DEBUG, "connection %d extra read error %d", f, rv);
				goto out;
			}
		}

		pthread_mutex_lock(&cas_query_mutex);
		cas_query_handle(f, &h, extra);
		pthread_mutex_unlock(&cas_query_mutex);

 out:
		close(f);
		if (extra) {
			free(extra);
			extra = NULL;
		}
	}
}

static int cas_query_setup(void)
{
	int rv;
	pthread_t cas_query_thread;

	rv = pthread_create(&cas_query_thread, NULL, cas_query_process, NULL);
	if (rv < 0) {
		cas_printf(LOG_ERR, "can't create cas_query thread");
		return rv;
	}
	return 0;
}

int cas_ctrl_init(void)
{
	cas_query_setup();
	return 0;
}

void cas_ctrl_deinit(void)
{
}
