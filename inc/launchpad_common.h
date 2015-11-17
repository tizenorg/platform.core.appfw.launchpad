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

#include <unistd.h>
#include <ctype.h>
#include <dlog.h>
#include <bundle_internal.h>
#ifndef __USE_GNU
	#define __USE_GNU
#endif
#include <sys/socket.h>
#include <linux/un.h>

#include "menu_db_util.h"

#ifdef LAUNCHPAD_LOG
#undef LOG_TAG
#define LOG_TAG "LAUNCHPAD"
#endif

#define SOCKET_PATH "/run/user"
#define LAUNCHPAD_LOADER_SOCKET_NAME ".launchpad-type"
#define MAX_PENDING_CONNECTIONS 10
#define MAX_LOCAL_BUFSZ 128
#define AUL_SOCK_MAXBUFF 65535

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

char *_proc_get_cmdline_bypid(int pid);
app_info_from_db *_get_app_info_from_bundle_by_pkgname(const char *pkgname, bundle *kb);
void _modify_bundle(bundle * kb, int caller_pid, app_info_from_db * menu_info, int cmd);

int _create_server_sock(int pid);
app_pkt_t *_recv_pkt_raw(int fd, int *clifd, struct ucred *cr);
int _send_pkt_raw(int client_fd, app_pkt_t *pkt);
int  _connect_to_launchpad(int type);
void _set_env(app_info_from_db * menu_info, bundle * kb);
char** _create_argc_argv(bundle * kb, int *margc);

#endif
