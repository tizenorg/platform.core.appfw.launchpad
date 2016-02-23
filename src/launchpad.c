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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <malloc.h>
#include <bundle_internal.h>
#include <security-manager.h>
#include <time.h>
#include <vconf.h>
#include <systemd/sd-daemon.h>
#include <glib.h>
#include <linux/limits.h>
#include <ttrace.h>

#include "perf.h"
#include "launchpad_common.h"
#include "sigchild.h"
#include "key.h"
#include "launchpad.h"

#define AUL_PR_NAME         16
#define EXEC_CANDIDATE_EXPIRED 5
#define EXEC_CANDIDATE_WAIT 1
#define DIFF(a, b) (((a) > (b)) ? (a) - (b) : (b) - (a))
#define CANDIDATE_NONE 0
#define PROCESS_POOL_LAUNCHPAD_SOCK ".launchpad-process-pool-sock"
#define LOADER_PATH_DEFAULT "/usr/bin/launchpad-loader"
#define LOADER_PATH_WRT		"/usr/bin/wrt-loader"
#define LOADER_PATH_JS_NATIVE	"/usr/bin/jsnative-loader"

typedef struct {
	int type;
	bool prepared;
	int pid;
	int loader_id;
	int caller_pid;
	int send_fd;
	int last_exec_time;
	guint source;
	guint timer;
	char *loader_path;
	char *loader_extra;
} candidate_process_context_t;

typedef struct {
	GPollFD *gpollfd;
	int type;
	int loader_id;
} loader_context_t;

static GList *candidate_slot_list;
static int sys_hwacc = -1;
static candidate_process_context_t* __add_slot(int type, int loader_id, int caller_pid, const char *loader_path, const char *extra);
static int __remove_slot(int type, int loader_id);
static int __add_default_slots();

static int __make_loader_id()
{
	static int id = PAD_LOADER_ID_DYNAMIC_BASE;

	return ++id;
}

static candidate_process_context_t* __find_slot_from_static_type(int type)
{
	GList *iter = candidate_slot_list;

	if (type == LAUNCHPAD_TYPE_DYNAMIC || type == LAUNCHPAD_TYPE_UNSUPPORTED)
		return NULL;

	while (iter) {
		candidate_process_context_t *cpc = (candidate_process_context_t*)iter->data;
		if (type == cpc->type)
			return cpc;

		iter = g_list_next(iter);
	}

	return NULL;
}

static candidate_process_context_t* __find_slot_from_pid(int pid)
{
	GList *iter = candidate_slot_list;

	while (iter) {
		candidate_process_context_t *cpc = (candidate_process_context_t*)iter->data;
		if (pid == cpc->pid)
			return cpc;

		iter = g_list_next(iter);
	}

	return NULL;
}

static candidate_process_context_t* __find_slot_from_caller_pid(int caller_pid)
{
	GList *iter = candidate_slot_list;

	while (iter) {
		candidate_process_context_t *cpc = (candidate_process_context_t*)iter->data;
		if (caller_pid == cpc->caller_pid)
			return cpc;

		iter = g_list_next(iter);
	}

	return NULL;
}

static candidate_process_context_t* __find_slot_from_loader_id(int id)
{
	GList *iter = candidate_slot_list;

	while (iter) {
		candidate_process_context_t *cpc = (candidate_process_context_t*)iter->data;
		if (id == cpc->loader_id)
			return cpc;

		iter = g_list_next(iter);
	}

	return NULL;
}

static candidate_process_context_t* __find_slot(int type, int loader_id)
{
	if (type == LAUNCHPAD_TYPE_DYNAMIC)
		return __find_slot_from_loader_id(loader_id);

	return __find_slot_from_static_type(type);
}

static void __kill_process(int pid)
{
	char err_str[MAX_LOCAL_BUFSZ] = { 0, };

	if (kill(pid, SIGKILL) == -1)
		_E("send SIGKILL: %s", strerror_r(errno, err_str, sizeof(err_str)));
}

static void __refuse_candidate_process(int server_fd)
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

static int __accept_candidate_process(int server_fd, int *out_client_fd,
		int *out_client_pid)
{
	int client_fd = -1;
	int client_pid = 0;
	int recv_ret = 0;

	if (server_fd == -1 || out_client_fd == NULL || out_client_pid == NULL) {
		_E("arguments error!");
		goto error;
	}

	client_fd = accept(server_fd, NULL, NULL);

	if (client_fd == -1) {
		_E("accept error!");
		goto error;
	}

	_set_sock_option(client_fd, 1);

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

static int __listen_candidate_process(int type, int loader_id)
{
	struct sockaddr_un addr;
	int fd = -1;

	_D("[launchpad] enter, type: %d", type);

	memset(&addr, 0x00, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%d/%s%d-%d", SOCKET_PATH, getuid(),
		LAUNCHPAD_LOADER_SOCKET_NAME, type, loader_id);

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

static int __set_access(const char* appId)
{
	return security_manager_prepare_app(appId) == SECURITY_MANAGER_SUCCESS ? 0 : -1;
}

static int __get_launchpad_type(const char* internal_pool, const char* hwacc, const char *app_type)
{
	if (app_type && strcmp(app_type, "webapp") == 0) {
		_D("[launchpad] launchpad type: wrt");
		return LAUNCHPAD_TYPE_WRT;
	} else if (app_type && strcmp(app_type, "jsapp") == 0) {
		_D("[launchpad] launchpad type: js_native");
		return LAUNCHPAD_TYPE_JS_NATIVE;
	}

	if (internal_pool && strcmp(internal_pool, "true") == 0 && hwacc) {
		if (strcmp(hwacc, "NOT_USE") == 0) {
			_D("[launchpad] launchpad type: S/W(%d)", LAUNCHPAD_TYPE_SW);
			return LAUNCHPAD_TYPE_SW;
		}
		if (strcmp(hwacc, "USE") == 0) {
			_D("[launchpad] launchpad type: H/W(%d)", LAUNCHPAD_TYPE_HW);
			return LAUNCHPAD_TYPE_HW;
		}
		if (strcmp(hwacc, "SYS") == 0) {
			if (sys_hwacc == SETTING_HW_ACCELERATION_ON) {
				_D("[launchpad] launchpad type: H/W(%d)", LAUNCHPAD_TYPE_HW);
				return LAUNCHPAD_TYPE_HW;
			} else if (sys_hwacc == SETTING_HW_ACCELERATION_OFF) {
				_D("[launchpad] launchpad type: S/W(%d)", LAUNCHPAD_TYPE_SW);
				return LAUNCHPAD_TYPE_SW;
			}
		}
	}

	_D("[launchpad] launchpad type: COMMON(%d)", LAUNCHPAD_TYPE_COMMON);
	return LAUNCHPAD_TYPE_COMMON;
}

static int __get_loader_id(bundle *kb)
{
	const char *val;

	val = bundle_get_val(kb, AUL_K_LOADER_ID);
	if (val == NULL) {
		_E("failed to get loader_id");
		return -1;
	}

	return atoi(val);
}

static int __candidate_process_real_launch(int candidate_fd, app_pkt_t *pkt)
{
	return _send_pkt_raw(candidate_fd, pkt);
}

static int __real_send(int clifd, int ret)
{
	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
			close(clifd);
			return -1;
		}
		_E("send fail to client");
	}

	close(clifd);
	return 0;
}

static void __send_result_to_caller(int clifd, int ret, const char* app_path)
{
	char *cmdline;

	_W("Check app launching");

	if (clifd == -1)
		return;

	if (ret <= 1) {
		_E("launching failed");
		__real_send(clifd, ret);
		return;
	}

	cmdline = _proc_get_cmdline_bypid(ret);
	if (cmdline == NULL) {
		_E("The app process might be terminated while we are wating %d", ret);
		__real_send(clifd, -1); /* abnormally launched*/
		return;
	}

	if (__real_send(clifd, ret) < 0)
		__kill_process(ret);

	return;
}

static int __prepare_candidate_process(int type, int loader_id)
{
	int pid;
	char type_str[2] = {0, };
	char loader_id_str[10] = {0, };
	char *argv[] = {NULL, NULL, NULL, NULL, NULL};
	candidate_process_context_t* cpt = __find_slot(type, loader_id);

	if (cpt == NULL)
		return -1;

	cpt->last_exec_time = time(NULL);
	pid = fork();
	if (pid == 0) { /* child */
		__signal_unblock_sigchld();
		__signal_fini();

		type_str[0] = '0' + type;
		snprintf(loader_id_str, sizeof(loader_id_str), "%d", loader_id);
		argv[0] = cpt->loader_path;
		argv[1] = type_str;
		argv[2] = loader_id_str;
		argv[3] = cpt->loader_extra;
		if (execv(argv[0], argv) < 0)
			_E("Failed to prepare candidate_process");
		else
			_D("Succeeded to prepare candidate_process");

		exit(-1);
	} else {
		cpt->pid = pid;
	}

	return 0;
}

static gboolean __handle_preparing_candidate_process(gpointer user_data)
{
	candidate_process_context_t *cpc = (candidate_process_context_t*)user_data;

	__prepare_candidate_process(cpc->type, cpc->loader_id);
	_D("Prepare another candidate process");
	cpc->timer = 0;
	return G_SOURCE_REMOVE;
}

static int __send_launchpad_loader(candidate_process_context_t *cpc, app_pkt_t *pkt,
				const char *app_path, int clifd, const char *comp_type)
{
	char sock_path[PATH_MAX];
	int pid = -1;

	snprintf(sock_path, sizeof(sock_path), "/run/user/%d/%d", getuid(),
		cpc->pid);
	unlink(sock_path);

	__candidate_process_real_launch(cpc->send_fd, pkt);
	SECURE_LOGD("Request to candidate process, pid: %d, bin path: %s",
		cpc->pid, app_path);

	pid = cpc->pid;
	close(cpc->send_fd);

	cpc->prepared = false;
	cpc->pid = CANDIDATE_NONE;
	cpc->send_fd = -1;
	if (cpc->source > 0) {
		g_source_remove(cpc->source);
		cpc->source = 0;
	}

	if (cpc->timer > 0) {
		g_source_remove(cpc->timer);
		cpc->timer = 0;
	}

	if (strcmp("uiapp", comp_type) == 0)
		cpc->timer = g_timeout_add(5000, __handle_preparing_candidate_process, cpc);
	else
		cpc->timer = g_timeout_add(2000, __handle_preparing_candidate_process, cpc);

	return pid;
}

static int __normal_fork_exec(int argc, char **argv)
{
	char *libdir = NULL;

	_D("start real fork and exec");

	libdir = _get_libdir(argv[0]);
	if (libdir)
		setenv("LD_LIBRARY_PATH", libdir, 1);
	free(libdir);

	if (execv(argv[0], argv) < 0) { /* Flawfinder: ignore */
		if (errno == EACCES)
			_E("such a file is no executable - %s", argv[0]);
		else
			_E("unknown executable error - %s", argv[0]);
		return -1;
	}
	/* never reach*/
	return 0;
}

static void __real_launch(const char *app_path, bundle * kb)
{
	int app_argc;
	char **app_argv;
	int i;

	if (bundle_get_val(kb, AUL_K_DEBUG) != NULL)
		putenv("TIZEN_DEBUGGING_PORT=1");

	app_argv = _create_argc_argv(kb, &app_argc);
	app_argv[0] = strdup(app_path);

	for (i = 0; i < app_argc; i++) {
		if ((i % 2) == 1)
			continue;
		SECURE_LOGD("input argument %d : %s##", i, app_argv[i]);
	}

	PERF("setup argument done");
	__normal_fork_exec(app_argc, app_argv);
}

static int __prepare_exec(const char *appId, const char *app_path,
			appinfo_t *menu_info, bundle * kb)
{
	char *file_name;
	char process_name[AUL_PR_NAME];
	int ret;

	/* Set new session ID & new process group ID*/
	/* In linux, child can set new session ID without check permission */
	/* TODO : should be add to check permission in the kernel*/
	setsid();

	/* SET PRIVILEGES*/
	if (bundle_get_val(kb, AUL_K_PRIVACY_APPID) == NULL) {
		_D("appId: %s / app_path : %s ", appId, app_path);
		if ((ret = __set_access(appId)) != 0) {
			_D("fail to set privileges - check your package's credential : %d\n", ret);
			return -1;
		}
	}
	/* SET DUMPABLE - for coredump*/
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME*/
	if (app_path == NULL) {
		_D("app_path should not be NULL - check menu db");
		return -1;
	}
	file_name = strrchr(app_path, '/') + 1;
	if (file_name == NULL) {
		_D("can't locate file name to execute");
		return -1;
	}
	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	/* SET ENVIROMENT*/
	_set_env(menu_info, kb);

	return 0;
}

static int __launch_directly(const char *appid, const char *app_path, int clifd,
				bundle* kb, appinfo_t *menu_info)
{
	char sock_path[PATH_MAX];
	int pid = fork();
	int max_fd;
	int iter_fd;

	if (pid == 0) {
		PERF("fork done");
		_D("lock up test log(no error) : fork done");

		__signal_unblock_sigchld();
		__signal_fini();

		max_fd = sysconf(_SC_OPEN_MAX);
		for (iter_fd = 3; iter_fd <= max_fd; iter_fd++)
			close(iter_fd);

		snprintf(sock_path, sizeof(sock_path), "/run/user/%d/%d", getuid(), getpid());
		unlink(sock_path);

		PERF("prepare exec - first done");
		_D("lock up test log(no error) : prepare exec - first done");

		if (__prepare_exec(appid, app_path,
				menu_info, kb) < 0) {
			SECURE_LOGE("preparing work fail to launch - "
				"can not launch %s\n", appid);
			exit(-1);
		}

		PERF("prepare exec - second done");
		_D("lock up test log(no error) : prepare exec - second done");
		__real_launch(app_path, kb);

		exit(-1);
	}
	SECURE_LOGD("==> real launch pid : %d %s\n", pid, app_path);

	return pid;
}

static int __create_sock_activation(void)
{
	int fds;

	fds = sd_listen_fds(0);
	if (fds == 1)
		return SD_LISTEN_FDS_START;
	else if (fds > 1)
		_E("Too many file descriptors received.\n");
	else
		_D("There is no socket stream");

	return -1;
}

static int __launchpad_pre_init(int argc, char **argv)
{
	int fd;

	/* signal init*/
	__signal_init();

	/* create launchpad sock */
	fd = __create_sock_activation();
	if (fd < 0) {
		fd = _create_server_sock(PROCESS_POOL_LAUNCHPAD_SOCK);
		if (fd < 0) {
			_E("server sock error %d", fd);
			return -1;
		}
	}

	return fd;
}

static void __destroy_poll_data(gpointer data)
{
	free(data);
}

static gboolean __glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		if ((tmp->revents & (G_IO_IN | G_IO_PRI | G_IO_HUP | G_IO_NVAL)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __glib_dispatch(GSource *src, GSourceFunc callback,
		gpointer data)
{
	return callback(data);
}

static gboolean __glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	.prepare = __glib_prepare,
	.check = __glib_check,
	.dispatch = __glib_dispatch,
	.finalize = NULL
};

static int __poll_fd(int fd, gushort events, GSourceFunc func, int type, int loader_id)
{
	int r;
	GPollFD *gpollfd;
	GSource *src;

	src = g_source_new(&funcs, sizeof(GSource));
	if (!src) {
		_E("out of memory");
		return -1;
	}

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	if (!gpollfd) {
		_E("out of memory");
		g_source_destroy(src);
		return -1;
	}

	gpollfd->events = events;
	gpollfd->fd = fd;

	loader_context_t *lc = malloc(sizeof(loader_context_t));
	if (lc == NULL) {
		g_free(gpollfd);
		g_source_destroy(src);
		return -1;
	}

	lc->gpollfd = gpollfd;
	lc->type = type;
	lc->loader_id = loader_id;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, func,
			(gpointer) lc, __destroy_poll_data);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);

	r = g_source_attach(src, NULL);
	if (r  == 0) {
		g_free(gpollfd);
		g_source_destroy(src);
		return -1;
	}

	return r;
}

static gboolean __handle_loader_client_event(gpointer data)
{
	loader_context_t *lc = (loader_context_t*) data;
	int type = lc->type;
	int loader_id = lc->loader_id;
	gushort revents = lc->gpollfd->revents;

	candidate_process_context_t *cpc = __find_slot(type, loader_id);

	if (cpc == NULL)
		return G_SOURCE_REMOVE;

	if (revents & (G_IO_HUP | G_IO_NVAL)) {
		SECURE_LOGE("Type %d candidate process was (POLLHUP|POLLNVAL), pid: %d", cpc->type,
				cpc->pid);
		close(cpc->send_fd);

		cpc->prepared = false;
		cpc->pid = CANDIDATE_NONE;
		cpc->send_fd = -1;
		cpc->source = 0;
		if (cpc->timer > 0)
			g_source_remove(cpc->timer);
		cpc->timer = 0;
		__prepare_candidate_process(cpc->type, cpc->loader_id);

		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static gboolean __handle_loader_event(gpointer data)
{
	loader_context_t *lc = (loader_context_t*) data;
	int fd = lc->gpollfd->fd;
	int type = lc->type;
	int loader_id = lc->loader_id;
	int client_fd;
	int client_pid;

	candidate_process_context_t *cpc = __find_slot(type, loader_id);

	if (cpc == NULL)
		return G_SOURCE_REMOVE;

	if (!cpc->prepared) {
		if (__accept_candidate_process(fd, &client_fd, &client_pid) >= 0) {
			cpc->prepared = true;
			cpc->send_fd = client_fd;

			SECURE_LOGD("Type %d candidate process was connected, pid: %d", type,
					cpc->pid);

			cpc->source = __poll_fd(client_fd, G_IO_IN | G_IO_HUP,
							(GSourceFunc)__handle_loader_client_event, type, loader_id);
			if (cpc->source < 0)
				close(client_fd);
		}
	} else {
		__refuse_candidate_process(fd);
		_E("Refused candidate process connection");
	}

	return G_SOURCE_CONTINUE;
}

static gboolean __handle_sigchild(gpointer data)
{
	loader_context_t *lc = (loader_context_t*) data;
	int fd = lc->gpollfd->fd;
	struct signalfd_siginfo siginfo;
	ssize_t s;

	do {
		s = read(fd, &siginfo, sizeof(struct signalfd_siginfo));
		if (s == 0)
			break;

		if (s != sizeof(struct signalfd_siginfo)) {
			_E("error reading sigchld info");
			break;
		}
		__launchpad_process_sigchld(&siginfo);
		candidate_process_context_t *cpc = __find_slot_from_pid(siginfo.ssi_pid);

		if (cpc != NULL) {
			cpc->prepared = false;
			__prepare_candidate_process(cpc->type, cpc->loader_id);
		}

		cpc = __find_slot_from_caller_pid(siginfo.ssi_pid);
		while (cpc) {
			__remove_slot(LAUNCHPAD_TYPE_DYNAMIC, cpc->loader_id);
			cpc = __find_slot_from_caller_pid(siginfo.ssi_pid);
		}

	} while (s > 0);

	return G_SOURCE_CONTINUE;
}

static int __dispatch_cmd_visibility(bundle *kb)
{
	GList *iter = candidate_slot_list;

	_W("cmd visibility");
	while (iter) {
		candidate_process_context_t *cpc = (candidate_process_context_t*)iter->data;

		if (cpc->pid == CANDIDATE_NONE) {
			if (cpc->timer > 0) {
				g_source_remove(cpc->timer);
				cpc->timer = 0;
			}
			__prepare_candidate_process(cpc->type, cpc->loader_id);
		}

		iter = g_list_next(iter);
	}

	return 0;
}

static int __dispatch_cmd_add_loader(bundle *kb)
{
	const char *add_slot_str = NULL;
	const char *caller_pid = NULL;
	const char *extra;
	int lid;

	_W("cmd add loader");
	add_slot_str = bundle_get_val(kb, AUL_K_LOADER_PATH);
	caller_pid = bundle_get_val(kb, AUL_K_CALLER_PID);
	extra = bundle_get_val(kb, AUL_K_LOADER_EXTRA);

	if (add_slot_str && caller_pid) {
		lid = __make_loader_id();
		candidate_process_context_t *cpc = __add_slot(LAUNCHPAD_TYPE_DYNAMIC, lid, atoi(caller_pid), add_slot_str, extra);
		if (cpc)
			cpc->timer = g_timeout_add(2000, __handle_preparing_candidate_process, cpc);

		return lid;
	}

	return -1;
}

static int __dispatch_cmd_remove_loader(bundle *kb)
{
	const char *id = bundle_get_val(kb, AUL_K_LOADER_ID);
	int lid;

	_W("cmd remove loader");
	if (id) {
		lid = atoi(id);
		if (__remove_slot(LAUNCHPAD_TYPE_DYNAMIC, lid) == 0)
			return 0;
	}

	return -1;
}

static gboolean __handle_launch_event(gpointer data)
{
	loader_context_t *lc = (loader_context_t*) data;
	int fd = lc->gpollfd->fd;
	bundle *kb = NULL;
	app_pkt_t *pkt = NULL;
	appinfo_t *menu_info = NULL;
	candidate_process_context_t *cpc;

	const char *app_path = NULL;
	int pid = -1;
	int clifd = -1;
	struct ucred cr;
	int type = -1;
	int loader_id;
	int ret;

	traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "LAUNCHPAD:LAUNCH");
	pkt = _recv_pkt_raw(fd, &clifd, &cr);
	if (!pkt) {
		_E("packet is NULL");
		goto end;
	}

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_E("bundle decode error");
		goto end;
	}

	switch (pkt->cmd) {
	case PAD_CMD_VISIBILITY:
		ret = __dispatch_cmd_visibility(kb);
		__real_send(clifd, ret);
		clifd = -1;
		goto end;
	case PAD_CMD_ADD_LOADER:
		ret = __dispatch_cmd_add_loader(kb);
		__real_send(clifd, ret);
		clifd = -1;
		goto end;
	case PAD_CMD_REMOVE_LOADER:
		ret = __dispatch_cmd_remove_loader(kb);
		__real_send(clifd, ret);
		clifd = -1;
		goto end;
	case PAD_CMD_MAKE_DEFAULT_SLOTS:
		ret = __add_default_slots();
		if (ret != 0)
			_E("Failed to make default slots");
		__real_send(clifd, ret);
		clifd = -1;
		goto end;
	}

	INIT_PERF(kb);
	PERF("packet processing start");

	menu_info = _appinfo_create(kb);
	if (menu_info == NULL) {
		_E("such pkg no found");
		goto end;
	}

	app_path = _appinfo_get_app_path(menu_info);
	if (app_path == NULL) {
		_E("app_path is NULL");
		goto end;
	}
	if (app_path[0] != '/') {
		_E("app_path is not absolute path");
		goto end;
	}

	if (menu_info->hwacc == NULL) {
		_E("[launchpad] Failed to find H/W acceleration type");
		goto end;
	}

	SECURE_LOGD("exec : %s\n", menu_info->app_path);
	SECURE_LOGD("comp_type : %s\n", menu_info->comp_type);
	SECURE_LOGD("internal pool : %s\n", menu_info->internal_pool);
	SECURE_LOGD("hwacc : %s\n", menu_info->hwacc);
	SECURE_LOGD("app_type : %s\n", menu_info->app_type);
	SECURE_LOGD("pkg_type : %s\n", menu_info->pkg_type);

	if ((loader_id = __get_loader_id(kb)) <= PAD_LOADER_ID_STATIC) {
		type = __get_launchpad_type(menu_info->internal_pool, menu_info->hwacc,
					menu_info->app_type);
		if (type < 0) {
			_E("failed to get launchpad type");
			goto end;
		}

		if (menu_info->comp_type && strcmp(menu_info->comp_type, "svcapp") == 0)
			loader_id = PAD_LOADER_ID_DIRECT;
		else
			loader_id = PAD_LOADER_ID_STATIC;
	} else {
		type = LAUNCHPAD_TYPE_DYNAMIC;
	}

	_modify_bundle(kb, cr.pid, menu_info, pkt->cmd);
	if (menu_info->appid == NULL) {
		_E("unable to get appid from menu_info");
		goto end;
	}

	PERF("get package information & modify bundle done");

	if (loader_id == PAD_LOADER_ID_DIRECT ||
		(cpc = __find_slot(type, loader_id)) == NULL) {
		_W("Launch directly");
		pid = __launch_directly(menu_info->appid, app_path, clifd, kb, menu_info);
	} else {
		if (cpc->prepared) {
			_W("Launch %d type process", type);
			pid = __send_launchpad_loader(cpc, pkt, app_path, clifd, menu_info->comp_type);
		} else if (cpc->type == LAUNCHPAD_TYPE_SW || cpc->type == LAUNCHPAD_TYPE_HW) {
				cpc = __find_slot(LAUNCHPAD_TYPE_COMMON, loader_id);
				if (cpc != NULL && cpc->prepared) {
					_W("Launch common type process");
					pid = __send_launchpad_loader(cpc, pkt, app_path, clifd, menu_info->comp_type);
				} else {
					_W("Launch directly");
					pid = __launch_directly(menu_info->appid, app_path, clifd, kb, menu_info);
				}
		} else {
			_W("Launch directly");
			pid = __launch_directly(menu_info->appid, app_path, clifd, kb, menu_info);
		}
	}

	__send_result_to_caller(clifd, pid, app_path);
	clifd = -1;
end:
	if (clifd != -1)
		close(clifd);

	if (pid > 0)
		__send_app_launch_signal_dbus(pid, menu_info->appid);

	if (menu_info != NULL)
		_appinfo_free(menu_info);

	if (kb != NULL)
		bundle_free(kb);
	if (pkt != NULL)
		free(pkt);

	traceEnd(TTRACE_TAG_APPLICATION_MANAGER);

	return G_SOURCE_CONTINUE;
}

static candidate_process_context_t* __add_slot(int type, int loader_id, int caller_pid, const char *loader_path, const char *loader_extra)
{
	candidate_process_context_t *cpc;
	int fd = -1;

	if (__find_slot(type, loader_id) != NULL)
		return NULL;

	cpc = (candidate_process_context_t*)malloc(sizeof(candidate_process_context_t));
	if (cpc == NULL)
		return NULL;

	cpc->type = type;
	cpc->prepared = false;
	cpc->pid = CANDIDATE_NONE;
	cpc->caller_pid = caller_pid;
	cpc->loader_id = loader_id;
	cpc->send_fd = -1;
	cpc->last_exec_time = 0;
	cpc->source = 0;
	cpc->timer = 0;
	cpc->loader_path = strdup(loader_path);
	cpc->loader_extra = loader_extra ? strdup(loader_extra) : NULL;

	fd = __listen_candidate_process(cpc->type, cpc->loader_id);
	if (fd == -1) {
		_E("[launchpad] Listening the socket to the type %d candidate process failed.",
		   cpc->type);
		free(cpc);
		return NULL;
	}

	if (__poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_loader_event, cpc->type, cpc->loader_id) < 0) {
		close(fd);
		free(cpc);
		return NULL;
	}

	candidate_slot_list = g_list_append(candidate_slot_list, cpc);

	return cpc;
}

static int __remove_slot(int type, int loader_id)
{
	GList *iter;
	iter = candidate_slot_list;

	while (iter) {
		candidate_process_context_t *cpc = (candidate_process_context_t*)iter->data;

		if (type == cpc->type && loader_id == cpc->loader_id) {
			if (cpc->pid > 0)
				__kill_process(cpc->pid);
			if (cpc->timer > 0)
				g_source_remove(cpc->timer);
			if (cpc->source > 0)
				g_source_remove(cpc->source);

			candidate_slot_list = g_list_delete_link(candidate_slot_list, iter);
			free(cpc->loader_path);
			if (cpc->loader_extra)
				free(cpc->loader_extra);

			free(cpc);
			return 0;
		}

		iter = g_list_next(iter);
	}

	return -1;
}

static int __init_launchpad_fd(int argc, char **argv)
{
	int fd = -1;

	fd = __launchpad_pre_init(argc, argv);
	if (fd < 0) {
		_E("launchpad pre init failed");
		return -1;
	}

	if (__poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_launch_event, 0, 0) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static int __init_sigchild_fd(void)
{
	int fd = -1;

	fd = __signal_get_sigchld_fd();
	if (fd < 0) {
		_E("failed to get sigchld fd");
		return -1;
	}

	if (__poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_sigchild, 0, 0) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static int __add_default_slots()
{
	if (__add_slot(LAUNCHPAD_TYPE_COMMON, PAD_LOADER_ID_STATIC, 0, LOADER_PATH_DEFAULT, NULL) == NULL)
		return -1;
	if (__prepare_candidate_process(LAUNCHPAD_TYPE_COMMON, PAD_LOADER_ID_STATIC) != 0)
		return -1;

	if (__add_slot(LAUNCHPAD_TYPE_SW, PAD_LOADER_ID_STATIC, 0, LOADER_PATH_DEFAULT, NULL) == NULL)
		return -1;
	if (__prepare_candidate_process(LAUNCHPAD_TYPE_SW, PAD_LOADER_ID_STATIC) != 0)
		return -1;

	if (__add_slot(LAUNCHPAD_TYPE_HW, PAD_LOADER_ID_STATIC, 0, LOADER_PATH_DEFAULT, NULL) == NULL)
		return -1;
	if (__prepare_candidate_process(LAUNCHPAD_TYPE_HW, PAD_LOADER_ID_STATIC) != 0)
		return -1;

	if (access(LOADER_PATH_WRT, F_OK | X_OK) == 0) {
		if (__add_slot(LAUNCHPAD_TYPE_WRT, PAD_LOADER_ID_STATIC, 0, LOADER_PATH_WRT, NULL) == NULL)
			return -1;
		if (__prepare_candidate_process(LAUNCHPAD_TYPE_WRT, PAD_LOADER_ID_STATIC) != 0)
			return -1;
	}

	if (access(LOADER_PATH_JS_NATIVE, F_OK | X_OK) == 0) {
		if (__add_slot(LAUNCHPAD_TYPE_JS_NATIVE, PAD_LOADER_ID_STATIC, 0, LOADER_PATH_JS_NATIVE, NULL) == NULL)
			return -1;
		if (__prepare_candidate_process(LAUNCHPAD_TYPE_JS_NATIVE, PAD_LOADER_ID_STATIC) != 0)
			return -1;
	}

	return 0;
}

static void __vconf_cb(keynode_t *key, void *data)
{
	const char *name;

	name = vconf_keynode_get_name(key);
	if (name && strcmp(name, VCONFKEY_SETAPPL_APP_HW_ACCELERATION) == 0) {
		sys_hwacc = vconf_keynode_get_int(key);
		SECURE_LOGD("sys hwacc: %d", sys_hwacc);
	}
}

static int __before_loop(int argc, char **argv)
{
	if (__init_sigchild_fd() != 0) {
		_E("__init_sigchild_fd() failed");
		return -1;
	}

	if (__init_launchpad_fd(argc, argv) != 0) {
		_E("__init_launchpad_fd() failed");
		return -1;
	}

	if (vconf_get_int(VCONFKEY_SETAPPL_APP_HW_ACCELERATION, &sys_hwacc) != VCONF_OK)
		_E("Failed to get vconf int: %s", VCONFKEY_SETAPPL_APP_HW_ACCELERATION);

	SECURE_LOGD("sys hwacc: %d", sys_hwacc);

	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_APP_HW_ACCELERATION, __vconf_cb, NULL) != 0)
		_E("Failed to register callback for %s", VCONFKEY_SETAPPL_APP_HW_ACCELERATION);

	return 0;
}

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
static void __set_priority(void)
{
	char err_str[MAX_LOCAL_BUFSZ] = { 0, };
	int res = setpriority(PRIO_PROCESS, 0, -12);

	if (res == -1)
		SECURE_LOGE("Setting process (%d) priority to -12 failed, errno: %d (%s)",
			getpid(), errno, strerror_r(errno, err_str, sizeof(err_str)));
}
#endif

int main(int argc, char **argv)
{
	GMainLoop *mainloop = NULL;

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		_E("failed to create glib main loop");
		return -1;
	}

	if (__before_loop(argc, argv) != 0) {
		_E("process-pool Initialization failed!\n");
		return -1;
	}

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	__set_priority();
#endif
	g_main_loop_run(mainloop);

	return -1;
}
