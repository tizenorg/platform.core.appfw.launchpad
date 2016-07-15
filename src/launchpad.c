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
#include <systemd/sd-daemon.h>
#include <glib.h>
#include <linux/limits.h>
#include <ttrace.h>
#include <vconf.h>

#include "perf.h"
#include "launchpad_common.h"
#include "sigchild.h"
#include "key.h"
#include "launchpad.h"
#include "loader_info.h"

#define AUL_PR_NAME         16
#define EXEC_CANDIDATE_EXPIRED 5
#define EXEC_CANDIDATE_WAIT 1
#define DIFF(a, b) (((a) > (b)) ? (a) - (b) : (b) - (a))
#define CANDIDATE_NONE 0
#define PROCESS_POOL_LAUNCHPAD_SOCK ".launchpad-process-pool-sock"
#define LOADER_PATH_DEFAULT "/usr/bin/launchpad-loader"
#define LOADER_INFO_PATH	"/usr/share/aul"
#define REGULAR_UID_MIN 5000
#define PAD_ERR_FAILED			-1
#define PAD_ERR_REJECTED		-2
#define PAD_ERR_INVALID_ARGUMENT	-3
#define PAD_ERR_INVALID_PATH		-4


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
	int detection_method;
	int timeout_val;
} candidate_process_context_t;

typedef struct {
	GPollFD *gpollfd;
	int type;
	int loader_id;
} loader_context_t;

static int __sys_hwacc;
static GList *loader_info_list;
static int user_slot_offset;
static GList *candidate_slot_list;
static app_labels_monitor *label_monitor;

static candidate_process_context_t *__add_slot(int type, int loader_id,
		int caller_pid, const char *loader_path, const char *extra,
		int detection_method, int timeout_val);
static int __remove_slot(int type, int loader_id);
static int __add_default_slots(void);

static int __make_loader_id(void)
{
	static int id = PAD_LOADER_ID_DYNAMIC_BASE;

	return ++id;
}

static candidate_process_context_t *__find_slot_from_static_type(int type)
{
	candidate_process_context_t *cpc;
	GList *iter = candidate_slot_list;

	if (type == LAUNCHPAD_TYPE_DYNAMIC ||
			type == LAUNCHPAD_TYPE_UNSUPPORTED)
		return NULL;

	while (iter) {
		cpc = (candidate_process_context_t *)iter->data;
		if (type == cpc->type)
			return cpc;

		iter = g_list_next(iter);
	}

	return NULL;
}

static candidate_process_context_t *__find_slot_from_pid(int pid)
{
	candidate_process_context_t *cpc;
	GList *iter = candidate_slot_list;

	while (iter) {
		cpc = (candidate_process_context_t *)iter->data;
		if (pid == cpc->pid)
			return cpc;

		iter = g_list_next(iter);
	}

	return NULL;
}

static candidate_process_context_t *__find_slot_from_caller_pid(int caller_pid)
{
	candidate_process_context_t *cpc;
	GList *iter = candidate_slot_list;

	while (iter) {
		cpc = (candidate_process_context_t *)iter->data;
		if (caller_pid == cpc->caller_pid)
			return cpc;

		iter = g_list_next(iter);
	}

	return NULL;
}

static candidate_process_context_t *__find_slot_from_loader_id(int id)
{
	candidate_process_context_t *cpc;
	GList *iter = candidate_slot_list;

	while (iter) {
		cpc = (candidate_process_context_t *)iter->data;
		if (id == cpc->loader_id)
			return cpc;

		iter = g_list_next(iter);
	}

	return NULL;
}

static candidate_process_context_t *__find_slot(int type, int loader_id)
{
	if (type == LAUNCHPAD_TYPE_DYNAMIC)
		return __find_slot_from_loader_id(loader_id);

	return __find_slot_from_static_type(type);
}

static void __kill_process(int pid)
{
	char err_str[MAX_LOCAL_BUFSZ] = { 0, };

	if (kill(pid, SIGKILL) == -1) {
		_E("send SIGKILL: %s",
				strerror_r(errno, err_str, sizeof(err_str)));
	}
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

	if (server_fd == -1 || out_client_fd == NULL ||
			out_client_pid == NULL) {
		_E("arguments error!");
		goto error;
	}

	client_fd = accept(server_fd, NULL, NULL);
	if (client_fd == -1) {
		_E("accept error!");
		goto error;
	}

	_set_sock_option(client_fd, 1);

	recv_ret = recv(client_fd, &client_pid, sizeof(client_pid),
			MSG_WAITALL);
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
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/daemons/%d/%s%d-%d",
			SOCKET_PATH, getuid(), LAUNCHPAD_LOADER_SOCKET_NAME,
			type, loader_id);

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

static void __send_result_to_caller(int clifd, int ret, const char *app_path)
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
		_E("The app process might be terminated while we are wating %d",
				ret);
		__real_send(clifd, -1); /* abnormally launched*/
		return;
	}

	if (__real_send(clifd, ret) < 0)
		__kill_process(ret);
}

static int __prepare_candidate_process(int type, int loader_id)
{
	int pid;
	char type_str[2] = {0, };
	char loader_id_str[10] = {0, };
	char argbuf[LOADER_ARG_LEN];
	char *argv[] = {NULL, NULL, NULL, NULL, NULL};
	candidate_process_context_t *cpt = __find_slot(type, loader_id);

	if (cpt == NULL)
		return -1;

	memset(argbuf, ' ', LOADER_ARG_LEN);
	argbuf[LOADER_ARG_LEN - 1] = '\0';
	argv[LOADER_ARG_DUMMY] = argbuf;

	cpt->last_exec_time = time(NULL);
	pid = fork();
	if (pid == 0) { /* child */
		__signal_unblock_sigchld();
		__signal_fini();

		type_str[0] = '0' + type;
		snprintf(loader_id_str, sizeof(loader_id_str), "%d", loader_id);
		argv[LOADER_ARG_PATH] = cpt->loader_path;
		argv[LOADER_ARG_TYPE] = type_str;
		argv[LOADER_ARG_ID] = loader_id_str;

		_set_extra_data(cpt->loader_extra);
		if (execv(argv[LOADER_ARG_PATH], argv) < 0)
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
	candidate_process_context_t *cpc;

	cpc = (candidate_process_context_t *)user_data;
	__prepare_candidate_process(cpc->type, cpc->loader_id);
	_D("Prepare another candidate process");
	cpc->timer = 0;
	return G_SOURCE_REMOVE;
}

static void __set_timer(candidate_process_context_t *cpc)
{
	if (cpc == NULL)
		return;

	if (cpc->detection_method & METHOD_TIMEOUT) {
		cpc->timer = g_timeout_add(cpc->timeout_val,
				__handle_preparing_candidate_process, cpc);
	}
}

static int __send_launchpad_loader(candidate_process_context_t *cpc,
		app_pkt_t *pkt, const char *app_path, int clifd)
{
	int pid = -1;
	int ret;

	ret = _delete_sock_path(cpc->pid, getuid());
	if (ret != 0)
		return -1;

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

	__set_timer(cpc);
	return pid;
}

static int __normal_fork_exec(int argc, char **argv)
{
	char *libdir = NULL;

	_D("start real fork and exec");

	libdir = _get_libdir(argv[LOADER_ARG_PATH]);
	if (libdir)
		setenv("LD_LIBRARY_PATH", libdir, 1);
	free(libdir);

	if (execv(argv[LOADER_ARG_PATH], argv) < 0) { /* Flawfinder: ignore */
		if (errno == EACCES) {
			_E("such a file is no executable - %s",
					argv[LOADER_ARG_PATH]);
		} else {
			_E("unknown executable error - %s",
					argv[LOADER_ARG_PATH]);
		}
		return -1;
	}
	/* never reach*/
	return 0;
}

static void __real_launch(const char *app_path, bundle *kb)
{
	int app_argc;
	char *app_argv[] = {NULL, NULL};
	char *extra_data = NULL;
	int len;
	int r;

	if (bundle_get_val(kb, AUL_K_DEBUG) != NULL)
		putenv("TIZEN_DEBUGGING_PORT=1");

	r = bundle_encode(kb, (bundle_raw **)&extra_data, &len);
	if (r != BUNDLE_ERROR_NONE)
		exit(-1);

	_set_extra_data(extra_data);
	free(extra_data);
	bundle_free(kb);

	app_argv[LOADER_ARG_PATH] = strdup(app_path);

	PERF("setup argument done");
	__normal_fork_exec(app_argc, app_argv);
}

static int __prepare_exec(const char *appid, const char *app_path,
			appinfo_t *menu_info, bundle *kb)
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
		ret = security_manager_prepare_app(appid);
		if (ret != SECURITY_MANAGER_SUCCESS)
			return PAD_ERR_REJECTED;
	}

	/* SET DUMPABLE - for coredump*/
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME*/
	if (app_path == NULL)
		return PAD_ERR_INVALID_ARGUMENT;

	file_name = strrchr(app_path, '/');
	if (file_name == NULL)
		return PAD_ERR_INVALID_PATH;

	file_name++;
	if (*file_name == '\0')
		return PAD_ERR_INVALID_PATH;

	_prepare_listen_sock();

	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	/* SET ENVIROMENT*/
	_set_env(menu_info, kb);

	return 0;
}

static int __launch_directly(const char *appid, const char *app_path, int clifd,
		bundle *kb, appinfo_t *menu_info,
		candidate_process_context_t *cpc)
{
	int pid = fork();
	int ret;
	int fds[1] = { 0 };

	if (pid == 0) {
		PERF("fork done");
		_D("lock up test log(no error) : fork done");

		__signal_unblock_sigchld();
		__signal_fini();

		_close_all_fds(fds, ARRAY_SIZE(fds));
		_delete_sock_path(getpid(), getuid());

		PERF("prepare exec - first done");
		ret = __prepare_exec(appid, app_path, menu_info, kb);
		if (ret < 0)
			exit(ret);

		PERF("prepare exec - second done");
		__real_launch(app_path, kb);

		exit(PAD_ERR_FAILED);
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
		if ((tmp->revents & (G_IO_IN | G_IO_PRI | G_IO_HUP |
						G_IO_NVAL)))
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

static void __glib_finalize(GSource *src)
{
	GSList *fd_list;
	GPollFD *gpollfd;

	fd_list = src->poll_fds;
	do {
		gpollfd = (GPollFD *)fd_list->data;
		close(gpollfd->fd);
		g_free(gpollfd);

		fd_list = fd_list->next;
	} while (fd_list);
}

static GSourceFuncs funcs = {
	.prepare = __glib_prepare,
	.check = __glib_check,
	.dispatch = __glib_dispatch,
	.finalize = __glib_finalize
};

static guint __poll_fd(int fd, gushort events, GSourceFunc func, int type,
		int loader_id)
{
	int r;
	GPollFD *gpollfd;
	GSource *src;
	loader_context_t *lc;

	src = g_source_new(&funcs, sizeof(GSource));
	if (!src) {
		_E("out of memory");
		return 0;
	}

	gpollfd = (GPollFD *)g_malloc(sizeof(GPollFD));
	if (!gpollfd) {
		_E("out of memory");
		g_source_destroy(src);
		return 0;
	}

	gpollfd->events = events;
	gpollfd->fd = fd;

	lc = malloc(sizeof(loader_context_t));
	if (lc == NULL) {
		g_free(gpollfd);
		g_source_destroy(src);
		return 0;
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
		return 0;
	}

	return r;
}

static gboolean __handle_loader_client_event(gpointer data)
{
	loader_context_t *lc = (loader_context_t *) data;
	int type = lc->type;
	int loader_id = lc->loader_id;
	gushort revents = lc->gpollfd->revents;
	candidate_process_context_t *cpc = __find_slot(type, loader_id);

	if (cpc == NULL)
		return G_SOURCE_REMOVE;

	if (revents & (G_IO_HUP | G_IO_NVAL)) {
		SECURE_LOGE("Type %d candidate process was " \
				"(POLLHUP|POLLNVAL), pid: %d",
				cpc->type, cpc->pid);
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
	loader_context_t *lc = (loader_context_t *) data;
	int fd = lc->gpollfd->fd;
	int type = lc->type;
	int loader_id = lc->loader_id;
	int client_fd;
	int client_pid;
	int ret;

	candidate_process_context_t *cpc = __find_slot(type, loader_id);

	if (cpc == NULL)
		return G_SOURCE_REMOVE;

	if (!cpc->prepared) {
		ret = __accept_candidate_process(fd, &client_fd, &client_pid);
		if (ret >= 0) {
			cpc->prepared = true;
			cpc->send_fd = client_fd;

			SECURE_LOGD("Type %d candidate process was connected," \
					" pid: %d", type, cpc->pid);
			cpc->source = __poll_fd(client_fd, G_IO_IN | G_IO_HUP,
					__handle_loader_client_event, type,
					loader_id);
			if (cpc->source == 0)
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
	candidate_process_context_t *cpc;
	loader_context_t *lc = (loader_context_t *) data;
	int fd = lc->gpollfd->fd;
	struct signalfd_siginfo siginfo;
	ssize_t s;

	do {
		s = read(fd, &siginfo, sizeof(struct signalfd_siginfo));
		if (s == 0)
			break;

		if (s != sizeof(struct signalfd_siginfo))
			break;

		__launchpad_process_sigchld(&siginfo);
		cpc = __find_slot_from_pid(siginfo.ssi_pid);
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

static gboolean __handle_label_monitor(gpointer data)
{
	candidate_process_context_t *cpc;
	GList *iter = candidate_slot_list;

	_D("__handle_label_monitor()");
	security_manager_app_labels_monitor_process(label_monitor);

	while (iter) {
		cpc = (candidate_process_context_t *)iter->data;
		if (cpc->pid > 0) {
			if (cpc->source > 0) {
				g_source_remove(cpc->source);
				cpc->source = 0;
			}

			if (cpc->timer > 0) {
				g_source_remove(cpc->timer);
				cpc->timer = 0;
			}

			_D("Dispose candidate process %d", cpc->pid);
			__kill_process(cpc->pid);
			close(cpc->send_fd);
			cpc->prepared = false;
			cpc->pid = CANDIDATE_NONE;
			cpc->send_fd = -1;
			__prepare_candidate_process(cpc->type, cpc->loader_id);
		}

		iter = g_list_next(iter);
	}

	return G_SOURCE_CONTINUE;
}

static int __dispatch_cmd_hint(bundle *kb, int detection_method)
{
	candidate_process_context_t *cpc;
	GList *iter = candidate_slot_list;

	_W("cmd hint %d", detection_method);
	while (iter) {
		cpc = (candidate_process_context_t *)iter->data;
		if (cpc->pid == CANDIDATE_NONE &&
				(cpc->detection_method & detection_method)) {
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
	candidate_process_context_t *cpc;

	_W("cmd add loader");
	add_slot_str = bundle_get_val(kb, AUL_K_LOADER_PATH);
	caller_pid = bundle_get_val(kb, AUL_K_CALLER_PID);
	extra = bundle_get_val(kb, AUL_K_LOADER_EXTRA);

	if (add_slot_str && caller_pid) {
		lid = __make_loader_id();
		cpc = __add_slot(LAUNCHPAD_TYPE_DYNAMIC, lid, atoi(caller_pid),
				add_slot_str, extra,
				METHOD_TIMEOUT | METHOD_VISIBILITY, 2000);
		__set_timer(cpc);
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

static int __check_caller_by_pid(int pid)
{
	int ret;
	char buf[PATH_MAX] = { 0, };

	ret = _proc_get_attr_by_pid(pid, buf, sizeof(buf));
	if (ret < 0)
		return -1;

	if (strcmp(buf, "User") == 0)
		return 0;

	return -1;
}

static bool __is_hw_acc(const char *hwacc)
{
	if (strcmp(hwacc, "USE") == 0 ||
		(strcmp(hwacc, "SYS") == 0 &&
			__sys_hwacc == SETTING_HW_ACCELERATION_ON))
		return true;

	return false;
}

static candidate_process_context_t *__find_available_slot(const char *hwacc,
		const char *app_type, const char *loader_name)
{
	int type;
	candidate_process_context_t *cpc;
	int *a_types;
	int len = 0;
	int i;

	if (loader_name) {
		type = _loader_info_find_type_by_loader_name(loader_info_list,
				loader_name);
	} else {
		type = _loader_info_find_type(loader_info_list,
				app_type, __is_hw_acc(hwacc));
	}
	cpc = __find_slot(type, PAD_LOADER_ID_STATIC);
	if (!cpc)
		return NULL;

	if (cpc->prepared)
		return cpc;

	a_types = _loader_get_alternative_types(loader_info_list, type, &len);
	if (!a_types)
		return NULL;

	for (i = 0; i < len; i++) {
		cpc = __find_slot(a_types[i], PAD_LOADER_ID_STATIC);
		if (!cpc)
			continue;
		if (cpc->prepared) {
			free(a_types);
			return cpc;
		}
	}

	free(a_types);
	return NULL;
}

static gboolean __handle_launch_event(gpointer data)
{
	loader_context_t *lc = (loader_context_t *) data;
	int fd = lc->gpollfd->fd;
	bundle *kb = NULL;
	app_pkt_t *pkt = NULL;
	appinfo_t *menu_info = NULL;
	candidate_process_context_t *cpc = NULL;
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

	if (cr.uid >= REGULAR_UID_MIN) {
		if (__check_caller_by_pid(cr.pid) < 0) {
			_E("Invalid caller pid");
			goto end;
		}
	}

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_E("bundle decode error");
		goto end;
	}

	switch (pkt->cmd) {
	case PAD_CMD_VISIBILITY:
		ret = __dispatch_cmd_hint(kb, METHOD_VISIBILITY);
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
	case PAD_CMD_DEMAND:
		ret = __dispatch_cmd_hint(kb, METHOD_DEMAND);
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

	if (menu_info->comp_type &&
			strcmp(menu_info->comp_type, "svcapp") == 0) {
		loader_id = PAD_LOADER_ID_DIRECT;
	} else {
		loader_id = __get_loader_id(kb);
		if (loader_id <= PAD_LOADER_ID_STATIC) {
			cpc = __find_available_slot(menu_info->hwacc,
					menu_info->app_type,
					menu_info->loader_name);
		} else {
			type = LAUNCHPAD_TYPE_DYNAMIC;
			cpc = __find_slot(type, loader_id);
		}
	}

	_modify_bundle(kb, cr.pid, menu_info, pkt->cmd);
	if (menu_info->appid == NULL) {
		_E("unable to get appid from menu_info");
		goto end;
	}

	PERF("get package information & modify bundle done");

	if (loader_id == PAD_LOADER_ID_DIRECT || cpc == NULL) {
		_W("Launch directly %d %d", loader_id, cpc);
		pid = __launch_directly(menu_info->appid, app_path, clifd, kb,
				menu_info, NULL);
	} else {
		_W("Launch %d type process", cpc->type);
		pid = __send_launchpad_loader(cpc, pkt, app_path, clifd);
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

static candidate_process_context_t *__add_slot(int type, int loader_id,
		int caller_pid, const char *loader_path,
		const char *loader_extra, int detection_method,
		int timeout_val)
{
	candidate_process_context_t *cpc;
	int fd = -1;
	guint pollfd;

	if (__find_slot(type, loader_id) != NULL)
		return NULL;

	cpc = (candidate_process_context_t *)malloc(
			sizeof(candidate_process_context_t));
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
	cpc->loader_extra = loader_extra ? strdup(loader_extra) : strdup("");
	cpc->detection_method = detection_method;
	cpc->timeout_val = timeout_val;

	fd = __listen_candidate_process(cpc->type, cpc->loader_id);
	if (fd == -1) {
		_E("[launchpad] Listening the socket to " \
				"the type %d candidate process failed.",
				cpc->type);
		free(cpc);
		return NULL;
	}

	pollfd = __poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_loader_event,
			cpc->type, cpc->loader_id);
	if (pollfd == 0) {
		close(fd);
		free(cpc);
		return NULL;
	}

	candidate_slot_list = g_list_append(candidate_slot_list, cpc);

	return cpc;
}

static int __remove_slot(int type, int loader_id)
{
	candidate_process_context_t *cpc;
	GList *iter;

	iter = candidate_slot_list;
	while (iter) {
		cpc = (candidate_process_context_t *)iter->data;
		if (type == cpc->type && loader_id == cpc->loader_id) {
			if (cpc->pid > 0)
				__kill_process(cpc->pid);
			if (cpc->timer > 0)
				g_source_remove(cpc->timer);
			if (cpc->source > 0)
				g_source_remove(cpc->source);

			candidate_slot_list = g_list_delete_link(
					candidate_slot_list, iter);
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
	guint pollfd;

	fd = __launchpad_pre_init(argc, argv);
	if (fd < 0) {
		_E("launchpad pre init failed");
		return -1;
	}

	pollfd = __poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_launch_event, 0,
			0);
	if (pollfd == 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static int __init_sigchild_fd(void)
{
	int fd = -1;
	guint pollfd;

	fd = __signal_get_sigchld_fd();
	if (fd < 0) {
		_E("failed to get sigchld fd");
		return -1;
	}

	pollfd = __poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_sigchild, 0, 0);
	if (pollfd == 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static int __init_label_monitor_fd(void)
{
	int fd = -1;
	guint pollfd;

	if (security_manager_app_labels_monitor_init(&label_monitor)
			!= SECURITY_MANAGER_SUCCESS)
		return -1;
	if (security_manager_app_labels_monitor_process(label_monitor)
			!= SECURITY_MANAGER_SUCCESS)
		return -1;
	security_manager_app_labels_monitor_get_fd(label_monitor, &fd);

	if (fd < 0) {
		_E("failed to get fd");
		return -1;
	}

	pollfd = __poll_fd(fd, G_IO_IN,
			(GSourceFunc)__handle_label_monitor, 0, 0);
	if (pollfd == 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static void __add_slot_from_info(gpointer data, gpointer user_data)
{
	loader_info_t *info = (loader_info_t *)data;
	candidate_process_context_t *cpc;
	bundle_raw *extra = NULL;
	int len;
	int ret;

	if (!strcmp(info->exe, "null")) {
		cpc = __add_slot(LAUNCHPAD_TYPE_USER + user_slot_offset,
				PAD_LOADER_ID_DIRECT,
				0, info->exe, NULL, 0, 0);
		if (cpc == NULL)
			return;

		info->type = LAUNCHPAD_TYPE_USER + user_slot_offset;
		user_slot_offset++;
		return;
	}

	if (access(info->exe, F_OK | X_OK) == 0) {
		if (info->extra)
			bundle_encode(info->extra, &extra, &len);

		cpc = __add_slot(LAUNCHPAD_TYPE_USER + user_slot_offset,
				PAD_LOADER_ID_STATIC,
				0, info->exe, (char *)extra,
				info->detection_method, info->timeout_val);
		if (cpc == NULL)
			return;

		ret = __prepare_candidate_process(
				LAUNCHPAD_TYPE_USER + user_slot_offset,
				PAD_LOADER_ID_STATIC);
		if (ret != 0)
			return;

		info->type = LAUNCHPAD_TYPE_USER + user_slot_offset;
		user_slot_offset++;
	}
}

static int __add_default_slots(void)
{
	if (loader_info_list)
		_loader_info_dispose(loader_info_list);

	loader_info_list = _loader_info_load(LOADER_INFO_PATH);

	if (loader_info_list == NULL)
		return -1;

	user_slot_offset = 0;
	g_list_foreach(loader_info_list, __add_slot_from_info, NULL);

	return 0;
}

static void __vconf_cb(keynode_t *key, void *data)
{
	const char *name;

	name = vconf_keynode_get_name(key);
	if (name && strcmp(name, VCONFKEY_SETAPPL_APP_HW_ACCELERATION) == 0) {
		__sys_hwacc = vconf_keynode_get_int(key);
		_D("sys hwacc: %d", __sys_hwacc);
	}
}

static int __before_loop(int argc, char **argv)
{
	int ret;

	ret = __init_sigchild_fd();
	if (ret != 0) {
		_E("__init_sigchild_fd() failed");
		return -1;
	}

	ret = __init_launchpad_fd(argc, argv);
	if (ret != 0) {
		_E("__init_launchpad_fd() failed");
		return -1;
	}

	ret = __init_label_monitor_fd();
	if (ret != 0) {
		_E("__init_launchpad_fd() failed");
		return -1;
	}

	ret = vconf_get_int(VCONFKEY_SETAPPL_APP_HW_ACCELERATION, &__sys_hwacc);
	if (ret != VCONF_OK) {
		_E("Failed to get vconf int: %s",
				VCONFKEY_SETAPPL_APP_HW_ACCELERATION);
	}

	ret = vconf_notify_key_changed(VCONFKEY_SETAPPL_APP_HW_ACCELERATION,
			__vconf_cb, NULL);
	if (ret != 0) {
		_E("Failed to register callback for %s",
				VCONFKEY_SETAPPL_APP_HW_ACCELERATION);
	}

	return 0;
}

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
static void __set_priority(void)
{
	char err_str[MAX_LOCAL_BUFSZ] = { 0, };
	int res;

	res = setpriority(PRIO_PROCESS, 0, -12);
	if (res == -1) {
		SECURE_LOGE("Setting process (%d) priority to -12 failed, " \
				"errno: %d (%s)", getpid(), errno,
				strerror_r(errno, err_str, sizeof(err_str)));
	}
}
#endif

int main(int argc, char **argv)
{
	GMainLoop *mainloop = NULL;

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		_E("Failed to create glib main loop");
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

	if (label_monitor)
		security_manager_app_labels_monitor_finish(label_monitor);

	return -1;
}

