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

#ifndef __LAUNCHPAD_COMMON__
#define __LAUNCHPAD_COMMON__

#define _GNU_SOURCE

#include <unistd.h>
#include <ctype.h>
#include <dlog.h>
#include <bundle_internal.h>
#include <sys/socket.h>

#ifdef LAUNCHPAD_LOG
#undef LOG_TAG
#define LOG_TAG "LAUNCHPAD"
#endif

#define SOCKET_PATH "/run/user"
#define LAUNCHPAD_LOADER_SOCKET_NAME ".launchpad-type"
#define MAX_PENDING_CONNECTIONS 10
#define MAX_LOCAL_BUFSZ 128
#define AUL_SOCK_MAXBUFF 131071

#define PAD_CMD_LAUNCH		0
#define PAD_CMD_VISIBILITY	10
#define PAD_CMD_ADD_LOADER	11
#define PAD_CMD_REMOVE_LOADER	12

#define PAD_LOADER_ID_STATIC	0
#define PAD_LOADER_ID_DIRECT	1
#define PAD_LOADER_ID_DYNAMIC_BASE	10

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_E(fmt, ##arg); \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if (expr) { \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

typedef struct _app_pkt_t {
	int cmd;
	int len;
	unsigned char data[1];
} app_pkt_t;

typedef struct {
	char *appid;
	char *app_path;
	char *original_app_path;
	char *pkg_type;
	char *hwacc;
	char *taskmanage;
	char *pkgid;
	char *comp_type;
	char *internal_pool;
} appinfo_t;

char *_proc_get_cmdline_bypid(int pid);
void _modify_bundle(bundle * kb, int caller_pid, appinfo_t *menu_info, int cmd);

int _create_server_sock(const char *name);
app_pkt_t *_recv_pkt_raw(int fd, int *clifd, struct ucred *cr);
int _send_pkt_raw(int client_fd, app_pkt_t *pkt);
int  _connect_to_launchpad(int type, int id);
void _set_env(appinfo_t *menu_info, bundle * kb);
char** _create_argc_argv(bundle * kb, int *margc);

appinfo_t* _appinfo_create(bundle *kb);
void _appinfo_free(appinfo_t *menu_info);
char *_appinfo_get_app_path(appinfo_t *menu_info);

#endif
