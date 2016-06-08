/*
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#define _GNU_SOURCE

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/xattr.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/limits.h>

#include "launchpad_common.h"
#include "key.h"

#define MAX_PATH_LEN	1024
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

#define MAX_PENDING_CONNECTIONS 10
#define CONNECT_RETRY_TIME 100 * 1000
#define CONNECT_RETRY_COUNT 3
#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int) + sizeof(int))

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

void _set_sock_option(int fd, int cli)
{
	int size;
	int flag;
	struct timeval tv = { 5, 200 * 1000 };  /*  5.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli) {
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		flag = fcntl(fd, F_GETFD);
		flag |= FD_CLOEXEC;
		fcntl(fd, F_SETFD, flag);
	}
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

int _create_server_sock(const char *name)
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
	snprintf(saddr.sun_path, sizeof(saddr.sun_path), "/run/user/%d/%s",
			getuid(), name);
	unlink(saddr.sun_path);

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		_E("bind error");
		close(fd);
		return -1;
	}

	_set_sock_option(fd, 0);

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
	int opt;

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

	_set_sock_option(*clifd, 1);

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
	memcpy(&opt, buf + sizeof(int) + sizeof(int), sizeof(int));

	/* allocate for a null byte */
	pkt = (app_pkt_t *)calloc(1, AUL_PKT_HEADER_SIZE + datalen + 1);
	if (pkt == NULL) {
		close(*clifd);
		return NULL;
	}
	pkt->cmd = cmd;
	pkt->len = datalen;
	pkt->opt = opt;

	len = 0;
	while (len != pkt->len) {
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

	pkt_size = AUL_PKT_HEADER_SIZE + pkt->len;

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
	char *ptr;
	int len;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* support app launched by shell script*/
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0)
		return strdup(&buf[BINSH_SIZE + 1]);
	else if (strncmp(buf, VALGRIND_NAME, VALGRIND_SIZE) == 0) {
		ptr = buf;

		/* buf comes with double null-terminated string */
		while (1) {
			while (*ptr)
				ptr++;
			ptr++;

			if (!(*ptr))
				break;

			/* ignore trailing "--" */
			if (strncmp(ptr, "-", 1) != 0)
				break;
		}

		return strdup(ptr);
	} else if (strncmp(buf, BASH_NAME, BASH_SIZE) == 0) {
		if (strncmp(&buf[BASH_SIZE + 1], OPROFILE_NAME,
					OPROFILE_SIZE) == 0) {
			if (strncmp(&buf[BASH_SIZE + OPROFILE_SIZE + 2],
						OPTION_VALGRIND_NAME,
						OPTION_VALGRIND_SIZE) == 0) {
				len = BASH_SIZE + OPROFILE_SIZE +
					OPTION_VALGRIND_SIZE + 3;
				return strdup(&buf[len]);
			}
		}
	}

	return strdup(buf);
}

appinfo_t *_appinfo_create(bundle *kb)
{
	appinfo_t *menu_info;
	const char *ptr = NULL;

	menu_info = calloc(1, sizeof(appinfo_t));
	if (menu_info == NULL)
		return NULL;

	ptr = bundle_get_val(kb, AUL_K_APPID);
	if (ptr)
		menu_info->appid = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_EXEC);
	if (ptr)
		menu_info->app_path = strdup(ptr);
	if (menu_info->app_path != NULL)
		menu_info->original_app_path = strdup(menu_info->app_path);
	ptr = bundle_get_val(kb, AUL_K_PACKAGETYPE);
	if (ptr)
		menu_info->pkg_type = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_APP_TYPE);
	if (ptr)
		menu_info->app_type = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_HWACC);
	if (ptr)
		menu_info->hwacc = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_TASKMANAGE);
	if (ptr)
		menu_info->taskmanage = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_PKGID);
	if (ptr)
		menu_info->pkgid = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_COMP_TYPE);
	if (ptr)
		menu_info->comp_type = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_INTERNAL_POOL);
	if (ptr)
		menu_info->internal_pool = strdup(ptr);
	ptr = bundle_get_val(kb, AUL_K_ROOT_PATH);
	if (ptr)
		menu_info->root_path = strdup(ptr);

	if (!_appinfo_get_app_path(menu_info)) {
		_appinfo_free(menu_info);
		return NULL;
	}

	return menu_info;
}

char *_appinfo_get_app_path(appinfo_t *menu_info)
{
	int i = 0;
	int path_len = -1;
	char *tmp_app_path;

	if (!menu_info || menu_info->app_path == NULL)
		return NULL;

	while (menu_info->app_path[i] != 0) {
		if (menu_info->app_path[i] == ' '
		    || menu_info->app_path[i] == '\t') {
			path_len = i;
			break;
		}
		i++;
	}

	if (path_len == 0) {
		free(menu_info->app_path);
		menu_info->app_path = NULL;
	} else if (path_len > 0) {
		tmp_app_path = malloc(sizeof(char) * (path_len + 1));
		if (tmp_app_path == NULL)
			return NULL;
		snprintf(tmp_app_path, path_len + 1, "%s", menu_info->app_path);
		free(menu_info->app_path);
		menu_info->app_path = tmp_app_path;
	}

	return menu_info->app_path;
}

void _appinfo_free(appinfo_t *menu_info)
{
	if (menu_info == NULL)
		return;

	if (menu_info->appid != NULL)
		free(menu_info->appid);
	if (menu_info->app_path != NULL)
		free(menu_info->app_path);
	if (menu_info->original_app_path != NULL)
		free(menu_info->original_app_path);
	if (menu_info->pkg_type != NULL)
		free(menu_info->pkg_type);
	if (menu_info->app_type != NULL)
		free(menu_info->app_type);
	if (menu_info->hwacc != NULL)
		free(menu_info->hwacc);
	if (menu_info->taskmanage != NULL)
		free(menu_info->taskmanage);
	if (menu_info->pkgid != NULL)
		free(menu_info->pkgid);
	if (menu_info->comp_type != NULL)
		free(menu_info->comp_type);
	if (menu_info->internal_pool != NULL)
		free(menu_info->internal_pool);
	if (menu_info->root_path != NULL)
		free(menu_info->root_path);

	free(menu_info);
}

void _modify_bundle(bundle *kb, int caller_pid, appinfo_t *menu_info, int cmd)
{
	char *ptr;
	char exe[MAX_PATH_LEN];
	int flag;
	char key[256];
	char value[256];

	bundle_del(kb, AUL_K_APPID);
	bundle_del(kb, AUL_K_EXEC);
	bundle_del(kb, AUL_K_APP_TYPE);
	bundle_del(kb, AUL_K_PACKAGETYPE);
	bundle_del(kb, AUL_K_TASKMANAGE);
	bundle_del(kb, AUL_K_PKGID);
	bundle_del(kb, AUL_K_COMP_TYPE);

	/* Parse app_path to retrieve default bundle*/
	if (cmd == PAD_CMD_LAUNCH) {
		ptr = menu_info->original_app_path;
		flag = __parse_app_path(ptr, exe, sizeof(exe));
		if (flag > 0) {
			ptr += flag;
			SECURE_LOGD("parsing app_path: EXEC - %s\n", exe);

			do {
				flag = __parse_app_path(ptr, key, sizeof(key));
				if (flag <= 0)
					break;
				ptr += flag;

				flag = __parse_app_path(ptr, value,
						sizeof(value));
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

int _connect_to_launchpad(int type, int id)
{
	struct sockaddr_un addr;
	int fd = -1;
	int retry = CONNECT_RETRY_COUNT;
	int send_ret = -1;
	int client_pid = getpid();
	struct stat statbuf;
	int ret;

	_D("[launchpad] enter, type: %d", type);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		_E("socket error");
		goto error;
	}

	memset(&addr, 0x00, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%d/%s%d-%d",
			SOCKET_PATH, getuid(), LAUNCHPAD_LOADER_SOCKET_NAME,
			type, id);

	ret = stat(addr.sun_path, &statbuf);
	if (ret < 0) {
		_E("Failed to get file status - %s", addr.sun_path);
		close(fd);
		return -1;
	}

	if (S_ISSOCK(statbuf.st_mode) == 0 || S_ISLNK(statbuf.st_mode)) {
		_E("%s is not a socket", addr.sun_path);
		close(fd);
		return - 1;
	}

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

void _set_env(appinfo_t *menu_info, bundle *kb)
{
	const char *str;

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str != NULL)
		setenv("APP_START_TIME", str, 1);

	if (menu_info->hwacc != NULL)
		setenv("HWACC", menu_info->hwacc, 1);
	if (menu_info->taskmanage != NULL)
		setenv("TASKMANAGE", menu_info->taskmanage, 1);

	str = bundle_get_val(kb, AUL_K_WAYLAND_DISPLAY);
	if (str != NULL)
		setenv("WAYLAND_DISPLAY", str, 1);

	str = bundle_get_val(kb, AUL_K_WAYLAND_WORKING_DIR);
	if (str != NULL)
		setenv("XDG_RUNTIME_DIR", str, 1);

	str = bundle_get_val(kb, AUL_K_API_VERSION);
	if (str != NULL)
		setenv("TIZEN_API_VERSION", str, 1);
}

char **_create_argc_argv(bundle *kb, int *margc)
{
	char **argv;
	int argc;

	argc = bundle_export_to_argv(kb, &argv);

	*margc = argc;
	return argv;
}

char *_get_libdir(const char *path)
{
	char *path_dup;
	char buf[PATH_MAX];
	char *ptr;

	path_dup = strdup(path);
	ptr = strrchr(path_dup, '/');
	*ptr = '\0';

	snprintf(buf, sizeof(buf), "%s/../lib/", path_dup);
	free(path_dup);

	if (access(buf, F_OK) == -1)
		return NULL;

	return strdup(buf);
}

int _proc_get_attr_by_pid(int pid, char *buf, int size)
{
	char path[PATH_MAX] = { 0, };
	int ret;

	snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
	ret = __read_proc(path, buf, size);
	if (ret <= 0)
		return -1;

	return 0;
}

