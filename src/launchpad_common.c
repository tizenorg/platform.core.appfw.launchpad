/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/xattr.h>
#include <errno.h>
#include <systemd/sd-daemon.h>

#include "launchpad_common.h"
#include "key.h"

#define BINSH_NAME  "/bin/sh"
#define BINSH_SIZE  7
#define VALGRIND_NAME   "/home/developer/sdk_tools/valgrind/usr/bin/valgrind"
#define VALGRIND_SIZE   51
#define BASH_NAME   "/bin/bash"
#define BASH_SIZE   9
#define OPROFILE_NAME   "/usr/bin/oprofile_command"
#define OPROFILE_SIZE   25
#define OPTION_VALGRIND_NAME    "valgrind"
#define OPTION_VALGRIND_SIZE    8
#define MAX_CMD_BUFSZ 1024

#define SOCKET_PATH "/run/user"
#define LAUNCHPAD_TYPE ".launchpad-type"
#define MAX_PENDING_CONNECTIONS 10
#define CONNECT_RETRY_TIME 100 * 1000
#define CONNECT_RETRY_COUNT 3
#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int))

#define APP_START  0
#define APP_OPEN  1
#define APP_RESUME 2
#define APP_START_RES 3

static int __read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

static void __set_sock_option(int fd, int cli)
{
	int size;
	struct timeval tv = { 5, 200 * 1000 };  /*  5.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int __parse_app_path(const char *arg, char *out, int out_size)
{
	register int i;
	int state = 1;
	char *start_out = out;

	if (arg == NULL || out == NULL) {
		/* Handles null buffer*/
		return 0;
	}

	for (i = 0; out_size > 1; i++) {
		switch (state) {
		case 1:
			switch (arg[i]) {
			case ' ':
			case '\t':
				state = 5;
				break;
			case '\0':
				state = 7;
				break;
			case '\"':
				state = 2;
				break;
			case '\\':
				state = 4;
				break;
			default:
				*out = arg[i];
				out++;
				out_size--;
				break;
			}
			break;
		case 2: /* escape start*/
			switch (arg[i]) {
			case '\0':
				state = 6;
				break;
			case '\"':
				state = 1;
				break;
			default:
				*out = arg[i];
				out++;
				out_size--;
				break;
			}
			break;
		case 4: /* character escape*/
			if (arg[i] == '\0') {
				state = 6;
			} else {
				*out = arg[i];
				out++;
				out_size--;
				state = 1;
			}
			break;
		case 5: /* token*/
			if (out != start_out) {
				*out = '\0';
				out_size--;
				return i;
			}
			i--;
			state = 1;
			break;
		case 6:
			return -1;  /* error*/
		case 7: /* terminate*/
			*out = '\0';
			out_size--;
			return 0;
		default:
			state = 6;
			break;  /* error*/
		}
	}

	if (out_size == 1)
		*out = '\0';

	/* Buffer overflow*/
	return -2;
}

int _create_server_sock(int pid)
{
	struct sockaddr_un saddr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/*  support above version 2.6.27*/
	if (fd < 0) {
		if (errno == EINVAL) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0) {
				_E("second chance - socket create error");
				return -1;
			}
		} else {
			_E("socket error");
			return -1;
		}
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "/run/user/%d/%d", getuid(), pid);
	unlink(saddr.sun_path);

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		_E("bind error");
		close(fd);
		return -1;
	}

	if (chmod(saddr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		/* Flawfinder: ignore*/
		_E("failed to change the socket permission");
		close(fd);
		return -1;
	}

	__set_sock_option(fd, 0);

	if (listen(fd, 128) == -1) {
		_E("listen error");
		close(fd);
		return -1;
	}

	return fd;
}

app_pkt_t *_recv_pkt_raw(int fd, int *clifd, struct ucred *cr)
{
	int len;
	int ret;
	struct sockaddr_un aul_addr = { 0, };
	int sun_size;
	app_pkt_t *pkt = NULL;
	int cl = sizeof(struct ucred);
	unsigned char buf[AUL_SOCK_MAXBUFF];
	int cmd;
	int datalen;

	sun_size = sizeof(struct sockaddr_un);

	if ((*clifd = accept(fd, (struct sockaddr *)&aul_addr,
			(socklen_t *) &sun_size)) == -1) {
		if (errno != EINTR)
			_E("accept error");
		return NULL;
	}

	if (getsockopt(*clifd, SOL_SOCKET, SO_PEERCRED, cr,
			(socklen_t *) &cl) < 0) {
		_E("peer information error");
		close(*clifd);
		return NULL;
	}

	__set_sock_option(*clifd, 1);

retry_recv:
	/* receive header(cmd, datalen) */
	len = recv(*clifd, buf, AUL_PKT_HEADER_SIZE, 0);
	if (len < 0)
		if (errno == EINTR)
			goto retry_recv;

	if (len < AUL_PKT_HEADER_SIZE) {
		_E("recv error");
		close(*clifd);
		return NULL;
	}
	memcpy(&cmd, buf, sizeof(int));
	memcpy(&datalen, buf + sizeof(int), sizeof(int));

	/* allocate for a null byte */
	pkt = (app_pkt_t *)calloc(1, AUL_PKT_HEADER_SIZE + datalen + 1);
	if (pkt == NULL) {
		close(*clifd);
		return NULL;
	}
	pkt->cmd = cmd;
	pkt->len = datalen;

	len = 0;
	while ( len != pkt->len ) {
		ret = recv(*clifd, pkt->data + len, pkt->len - len, 0);
		if (ret < 0) {
			_E("recv error %d %d", len, pkt->len);
			free(pkt);
			close(*clifd);
			return NULL;
		}
		len += ret;
		_D("recv len %d %d", len, pkt->len);
	}

	return pkt;
}

int _send_pkt_raw(int client_fd, app_pkt_t *pkt)
{
	int send_ret = 0;
	int pkt_size = 0;

	if (client_fd == -1 || pkt == NULL) {
		_E("arguments error!");
		goto error;
	}

	pkt_size = sizeof(pkt->cmd) + sizeof(pkt->len) + pkt->len;

	send_ret = send(client_fd, pkt, pkt_size, 0);
	_D("send(%d) : %d / %d", client_fd, send_ret, pkt_size);

	if (send_ret == -1) {
		_E("send error!");
		goto error;
	} else if (send_ret != pkt_size) {
		_E("send byte fail!");
		goto error;
	}

	return 0;

error:
	return -1;
}

char *_proc_get_cmdline_bypid(int pid)
{
	char buf[MAX_CMD_BUFSZ];
	int ret;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* support app launched by shell script*/
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0) {
		return strdup(&buf[BINSH_SIZE + 1]);
	} else if (strncmp(buf, VALGRIND_NAME, VALGRIND_SIZE) == 0) {
		char* ptr = buf;

		// buf comes with double null-terminated string
		while (1) {
			while (*ptr) {
				ptr++;
			}
			ptr++;

			if (!(*ptr))
				break;

			// ignore trailing "--"
			if (strncmp(ptr, "-", 1) != 0)
				break;
		}

		return strdup(ptr);
	} else if (strncmp(buf, BASH_NAME, BASH_SIZE) == 0) {
		if (strncmp(&buf[BASH_SIZE + 1], OPROFILE_NAME, OPROFILE_SIZE) == 0) {
			if (strncmp(&buf[BASH_SIZE + OPROFILE_SIZE + 2], OPTION_VALGRIND_NAME,
					OPTION_VALGRIND_SIZE) == 0) {
				return strdup(&buf[BASH_SIZE + OPROFILE_SIZE + OPTION_VALGRIND_SIZE + 3]);
			}
		}
	}

	return strdup(buf);
}

app_info_from_db *_get_app_info_from_bundle_by_pkgname(const char *pkgname, bundle *kb)
{
	app_info_from_db *menu_info;
	const char *ptr = NULL;

	menu_info = calloc(1, sizeof(app_info_from_db));
	if (menu_info == NULL)
		return NULL;

	menu_info->pkg_name = strdup(pkgname);
	ptr = bundle_get_val(kb, AUL_K_EXEC);
	if (ptr)
		menu_info->app_path = strdup(ptr);
	if (menu_info->app_path != NULL)
		menu_info->original_app_path = strdup(menu_info->app_path);
	ptr = bundle_get_val(kb, AUL_K_PACKAGETYPE);
	if (ptr)
		menu_info->pkg_type = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_HWACC);
	if (ptr)
		menu_info->hwacc = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_TASKMANAGE);
	if (ptr)
		menu_info->taskmanage = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_PKGID);
	if (ptr)
		menu_info->pkg_id = strdup(ptr);

	if (!_get_app_path(menu_info)) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	return menu_info;
}

void _modify_bundle(bundle * kb, int caller_pid, app_info_from_db * menu_info, int cmd)
{
	bundle_del(kb, AUL_K_APPID);
	bundle_del(kb, AUL_K_EXEC);
	bundle_del(kb, AUL_K_PACKAGETYPE);
	bundle_del(kb, AUL_K_HWACC);
	bundle_del(kb, AUL_K_TASKMANAGE);

	/* Parse app_path to retrieve default bundle*/
	if (cmd == APP_START || cmd == APP_START_RES || cmd == APP_OPEN
		|| cmd == APP_RESUME) {
		char *ptr;
		char exe[MAX_PATH_LEN];
		int flag;

		ptr = _get_original_app_path(menu_info);

		flag = __parse_app_path(ptr, exe, sizeof(exe));
		if (flag > 0) {
			char key[256];
			char value[256];

			ptr += flag;
			SECURE_LOGD("parsing app_path: EXEC - %s\n", exe);

			do {
				flag = __parse_app_path(ptr, key, sizeof(key));
				if (flag <= 0)
					break;
				ptr += flag;

				flag = __parse_app_path(ptr, value, sizeof(value));
				if (flag < 0)
					break;
				ptr += flag;

				/*bundle_del(kb, key);*/
				bundle_add(kb, key, value);
			} while (flag > 0);
		} else if (flag == 0)
			_D("parsing app_path: No arguments\n");
		else
			_D("parsing app_path: Invalid argument\n");
	}
}

int _listen_candidate_process(int type)
{
	struct sockaddr_un addr;
	int fd = -1;
	int listen_fds = 0;
	int i;

	_D("[launchpad] enter, type: %d", type);

	memset(&addr, 0x00, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%d/%s%d", SOCKET_PATH, getuid(),
		LAUNCHPAD_TYPE, type);

	listen_fds = sd_listen_fds(0);
	if (listen_fds < 0) {
		_E("Invalid systemd environment");
		return -1;
	} else if (listen_fds > 0) {
		for (i = 0; i < listen_fds; i++) {
			fd = SD_LISTEN_FDS_START + i;
			if (sd_is_socket_unix(fd, SOCK_STREAM, 1, addr.sun_path, 0))
				return fd;
		}
		_E("Socket not found: %s", addr.sun_path);
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		_E("Socket error");
		goto error;
	}

	unlink(addr.sun_path);

	_D("bind to %s", addr.sun_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		_E("bind error");
		goto error;
	}

	_D("chmod %s", addr.sun_path);
	if (chmod(addr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		_E("chmod error");
		goto error;
	}

	_D("listen to %s", addr.sun_path);
	if (listen(fd, MAX_PENDING_CONNECTIONS) == -1) {
		_E("listen error");
		goto error;
	}

	SECURE_LOGD("[launchpad] done, listen fd: %d", fd);
	return fd;

error:
	if (fd != -1)
		close(fd);

	return -1;
}

int _connect_to_launchpad(int type)
{
	struct sockaddr_un addr;
	int fd = -1;
	int retry = CONNECT_RETRY_COUNT;
	int send_ret = -1;
	int client_pid = getpid();

	_D("[launchpad] enter, type: %d", type);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		_E("socket error");
		goto error;
	}

	memset(&addr, 0x00, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%d/%s%d", SOCKET_PATH, getuid(),
		LAUNCHPAD_TYPE, type);

	_D("connect to %s", addr.sun_path);
	while (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		if (errno != ETIMEDOUT || retry <= 0) {
			_E("connect error : %d", errno);
			goto error;
		}

		usleep(CONNECT_RETRY_TIME);
		--retry;
		_D("re-connect to %s (%d)", addr.sun_path, retry);
	}

	send_ret = send(fd, &client_pid, sizeof(client_pid), 0);
	_D("send(%d) : %d", client_pid, send_ret);

	if (send_ret == -1) {
		_E("send error");
		goto error;
	}

	SECURE_LOGD("[launchpad] done, connect fd: %d", fd);
	return fd;

error:
	if (fd != -1)
		close(fd);

	return -1;
}

int _accept_candidate_process(int server_fd, int* out_client_fd,
                              int* out_client_pid)
{
	int client_fd = -1, client_pid = 0, recv_ret = 0;

	if (server_fd == -1 || out_client_fd == NULL || out_client_pid == NULL) {
		_E("arguments error!");
		goto error;
	}

	client_fd = accept(server_fd, NULL, NULL);

	if (client_fd == -1) {
		_E("accept error!");
		goto error;
	}

	recv_ret = recv(client_fd, &client_pid, sizeof(client_pid), MSG_WAITALL);

	if (recv_ret == -1) {
		_E("recv error!");
		goto error;
	}

	*out_client_fd = client_fd;
	*out_client_pid = client_pid;

	return *out_client_fd;

error:
	if (client_fd != -1)
		close(client_fd);

	return -1;
}

void _refuse_candidate_process(int server_fd)
{
	int client_fd = -1;

	if (server_fd == -1) {
		_E("arguments error!");
		goto error;
	}

	client_fd = accept(server_fd, NULL, NULL);
	if (client_fd == -1) {
		_E("accept error!");
		goto error;
	}

	close(client_fd);
	_D("refuse connection!");

error:
	return;
}

void _set_oom(void)
{
	char buf[MAX_LOCAL_BUFSZ];
	FILE *fp;

	/* we should reset oomadj value as default because child
	inherits from parent oom_adj*/
	snprintf(buf, MAX_LOCAL_BUFSZ, "/proc/%d/oom_adj", getpid());
	fp = fopen(buf, "w");
	if (fp == NULL)
		return;
	fprintf(fp, "%d", -16);
	fclose(fp);
}

void _set_env(app_info_from_db * menu_info, bundle * kb)
{
	const char *str;

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str != NULL)
		setenv("APP_START_TIME", str, 1);

	if (menu_info->hwacc != NULL)
		setenv("HWACC", menu_info->hwacc, 1);
	if (menu_info->taskmanage != NULL)
		setenv("TASKMANAGE", menu_info->taskmanage, 1);
}

char** _create_argc_argv(bundle * kb, int *margc)
{
	char **argv;
	int argc;

	argc = bundle_export_to_argv(kb, &argv);

	*margc = argc;
	return argv;
}

