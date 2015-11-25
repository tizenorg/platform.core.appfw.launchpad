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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <malloc.h>
#include <bundle_internal.h>
#include <security-manager.h>
#include <time.h>
#include <vconf.h>
#include <systemd/sd-daemon.h>
#include <glib.h>

#include "perf.h"
#include "launchpad_common.h"
#include "sigchild.h"
#include "key.h"
#include "launchpad.h"

#define AUL_PR_NAME         16
#define AUL_POLL_CNT        15
#define EXEC_CANDIDATE_EXPIRED 5
#define EXEC_CANDIDATE_WAIT 1
#define DIFF(a,b) (((a)>(b))?(a)-(b):(b)-(a))
#define CANDIDATE_NONE 0
#define PROCESS_POOL_LAUNCHPAD_SOCK ".launchpad-process-pool-sock"

typedef struct {
	int pid;
	int effective_pid;
	int send_fd;
	int last_exec_time;
	guint source;
} candidate;

typedef struct {
	GPollFD *gpollfd;
	int type;
} loader_context_t;

static candidate __candidate[LAUNCHPAD_TYPE_MAX] = {
	{ CANDIDATE_NONE, CANDIDATE_NONE, -1, 0, 0 },
	{ CANDIDATE_NONE, CANDIDATE_NONE, -1, 0, 0 },
	{ CANDIDATE_NONE, CANDIDATE_NONE, -1, 0, 0 }
};

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

static int __accept_candidate_process(int server_fd, int* out_client_fd,
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

static int __listen_candidate_process(int type)
{
	struct sockaddr_un addr;
	int fd = -1;

	_D("[launchpad] enter, type: %d", type);

	memset(&addr, 0x00, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, "%s/%d/%s%d", SOCKET_PATH, getuid(),
		LAUNCHPAD_LOADER_SOCKET_NAME, type);

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

static int __set_access(const char* appId, const char* pkg_type,
			const char* app_path)
{
	return security_manager_prepare_app(appId) == SECURITY_MANAGER_SUCCESS ? 0 : -1;
}

static int __get_launchpad_type(const char* internal_pool, const char* hwacc)
{
	if (internal_pool && strncmp(internal_pool, "true", 4) == 0 && hwacc) {
		if (strncmp(hwacc, "NOT_USE", 7) == 0) {
			_D("[launchpad] launchpad type: S/W(%d)", LAUNCHPAD_TYPE_SW);
			return LAUNCHPAD_TYPE_SW;
		}
		if (strncmp(hwacc, "USE", 3) == 0) {
			_D("[launchpad] launchpad type: H/W(%d)", LAUNCHPAD_TYPE_HW);
			return LAUNCHPAD_TYPE_HW;
		}
		if (strncmp(hwacc, "SYS", 3) == 0) {
		    int r;
		    int sys_hwacc = -1;

		    r = vconf_get_int(VCONFKEY_SETAPPL_APP_HW_ACCELERATION, &sys_hwacc);
		    if (r != VCONF_OK)
		        _E("failed to get vconf int: %s", VCONFKEY_SETAPPL_APP_HW_ACCELERATION);

		    SECURE_LOGD("sys hwacc: %d", sys_hwacc);

		    if (sys_hwacc == SETTING_HW_ACCELERATION_ON) {
		        _D("[launchpad] launchpad type: H/W(%d)", LAUNCHPAD_TYPE_HW);
		        return LAUNCHPAD_TYPE_HW;
		    }
		    if (sys_hwacc == SETTING_HW_ACCELERATION_OFF) {
		        _D("[launchpad] launchpad type: S/W(%d)", LAUNCHPAD_TYPE_SW);
		        return LAUNCHPAD_TYPE_SW;
		    }
		}
	}

	_D("[launchpad] launchpad type: COMMON(%d)", LAUNCHPAD_TYPE_COMMON);
	return LAUNCHPAD_TYPE_COMMON;
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
	int wait_count;
	int cmdline_changed = 0;
	int cmdline_exist = 0;
	int r;

	_W("Check app launching");

	if (clifd == -1)
		return;

	if (ret <= 1) {
		_E("launching failed");
		__real_send(clifd, ret);
		return;
	}
	/* check normally was launched?*/
	wait_count = 1;
	do {
		cmdline = _proc_get_cmdline_bypid(ret);
		if (cmdline == NULL) {
			_E("error founded when being launched with %d", ret);
			if (cmdline_exist || cmdline_changed) {
				_E("The app process might be terminated while we are wating %d", ret);
				break;
			}
		} else if (strcmp(cmdline, app_path) == 0) {
			/* Check app main loop is prepared or not */
			_D("-- now wait app mainloop creation --");
			free(cmdline);
			cmdline_changed = 1;

			char sock_path[UNIX_PATH_MAX] = { 0, };
			snprintf(sock_path, UNIX_PATH_MAX, "/run/user/%d/%d", getuid(), ret);
			if (access(sock_path, F_OK) == 0)
				break;

		} else {
			_D("-- now wait cmdline changing --");
			cmdline_exist = 1;
			free(cmdline);
		}
		usleep(100 * 1000); /* 100ms sleep*/
		wait_count++;

	} while (wait_count <= 50); /* max 100*50ms will be sleep*/

	if ((!cmdline_exist) && (!cmdline_changed)) {
		__real_send(clifd, -1); /* abnormally launched*/
		return;
	}

	if (!cmdline_changed)
		_E("process launched, but cmdline not changed");

	if (__real_send(clifd, ret) < 0) {
		r = kill(ret, SIGKILL);
		if (r == -1) {
			char err_str[MAX_LOCAL_BUFSZ] = { 0, };

			_E("send SIGKILL: %s", strerror_r(errno, err_str, sizeof(err_str)));
		}
	}

	return;
}

static void __prepare_candidate_process(int type)
{
	int pid;

	__candidate[type].last_exec_time = time(NULL);
	pid = fork();

	if (pid == 0) { /* child */
		char type_str[2] = {0,};

		/* execute with very long (1024 bytes) argument in order to prevent argv overflow caused by dlopen */
		char *argv[] = {"/usr/bin/launchpad-loader", NULL,
		                "                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ", NULL
		               };
		__signal_unblock_sigchld();

		type_str[0] = '0' + type;
		argv[1] = type_str;
		if (execv(argv[0], argv) < 0)
			_E("Failed to prepare candidate_process");
		else
			_D("Succeeded to prepare candidate_process");

		exit(-1);
	} else {
		__candidate[type].effective_pid = pid;
	}
}

static gboolean __handle_preparing_candidate_process(gpointer user_data)
{
	int type = GPOINTER_TO_INT(user_data);

	__prepare_candidate_process(type);
	_D("Prepare another candidate process");
	return G_SOURCE_REMOVE;
}

static int __send_launchpad_loader(int type, app_pkt_t *pkt,
				const char *app_path, int clifd)
{
	char sock_path[UNIX_PATH_MAX] = { 0, };
	int pid = -1;

	snprintf(sock_path, UNIX_PATH_MAX, "/run/user/%d/%d", getuid(),
		__candidate[type].pid);
	unlink(sock_path);

	__candidate_process_real_launch(__candidate[type].send_fd, pkt);
	SECURE_LOGD("Request to candidate process, pid: %d, bin path: %s",
		__candidate[type].pid, app_path);

	pid = __candidate[type].pid;
	close(__candidate[type].send_fd);

	__candidate[type].pid = CANDIDATE_NONE;
	__candidate[type].effective_pid = CANDIDATE_NONE;
	__candidate[type].send_fd = -1;
	if (__candidate[type].source > 0) {
		g_source_remove(__candidate[type].source);
		__candidate[type].source = 0;
	}

	/* Temporary log: launch time checking */
	//SECURE_LOG(LOG_DEBUG, "LAUNCH", "[%s:Platform:launchpad:done]", app_path);

	__send_result_to_caller(clifd, pid, app_path); //to AMD

	g_timeout_add(1000, __handle_preparing_candidate_process, GINT_TO_POINTER(type));

	return pid;
}

static int __normal_fork_exec(int argc, char **argv)
{
	_D("start real fork and exec\n");

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
			app_info_from_db * menu_info, bundle * kb)
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
		_D("appId: %s / pkg_type : %s / app_path : %s ", appId, menu_info->pkg_type,
			app_path);
		if ((ret = __set_access(appId, menu_info->pkg_type, app_path)) != 0) {
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
				bundle* kb, app_info_from_db *menu_info)
{
	char sock_path[UNIX_PATH_MAX] = {0,};
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

		snprintf(sock_path, UNIX_PATH_MAX, "/run/user/%d/%d", getuid(), getpid());
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

static void __preload_candidate_process()
{
	int i;

	for (i = 0; i < LAUNCHPAD_TYPE_MAX; ++i)
		__prepare_candidate_process(i);
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

static int __poll_fd(int fd, gushort events, GSourceFunc func, int type)
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
	int fd = lc->gpollfd->fd;
	int type = lc->type;
	gushort revents = lc->gpollfd->revents;

	if (revents & (G_IO_HUP | G_IO_NVAL)) {
		SECURE_LOGE("Type %d candidate process was (POLLHUP|POLLNVAL), pid: %d", type,
				__candidate[type].effective_pid);
		close(fd);

		__candidate[type].pid = CANDIDATE_NONE;
		__candidate[type].effective_pid = CANDIDATE_NONE;
		__candidate[type].send_fd = -1;
		__candidate[type].source = 0;
		__prepare_candidate_process(type);

		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

static gboolean __handle_loader_event(gpointer data)
{
	loader_context_t *lc = (loader_context_t*) data;
	int fd = lc->gpollfd->fd;
	int type = lc->type;
	int client_fd;
	int client_pid;

	if (__candidate[type].pid == CANDIDATE_NONE) {
		if (__accept_candidate_process(fd, &client_fd, &client_pid) >= 0) {
			__candidate[type].pid = client_pid;
			__candidate[type].send_fd = client_fd;

			SECURE_LOGD("Type %d candidate process was connected, pid: %d", type,
					__candidate[type].pid);

			__candidate[type].source = __poll_fd(client_fd, G_IO_IN | G_IO_HUP,
							(GSourceFunc)__handle_loader_client_event, type);
			if (__candidate[type].source < 0) {
				close(client_fd);
			}
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
	int i;

	do {
		s = read(fd, &siginfo, sizeof(struct signalfd_siginfo));
		if (s == 0)
			break;

		if (s != sizeof(struct signalfd_siginfo)) {
			_E("error reading sigchld info");
			break;
		}
		__launchpad_process_sigchld(&siginfo);

		for (i = 0; i < LAUNCHPAD_TYPE_MAX; ++i) {
			if (__candidate[i].effective_pid == siginfo.ssi_pid) {
				__prepare_candidate_process(i);
				break;
			}
		}
	} while (s > 0);

	return G_SOURCE_CONTINUE;
}
static gboolean __handle_launch_event(gpointer data)
{
	loader_context_t *lc = (loader_context_t*) data;
	int fd = lc->gpollfd->fd;
	bundle *kb = NULL;
	app_pkt_t *pkt = NULL;
	app_info_from_db *menu_info = NULL;

	const char *pkg_name = NULL;
	const char *internal_pool = NULL;
	const char *app_path = NULL;
	int pid = -1;
	int clifd = -1;
	struct ucred cr;
	int type = -1;

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

	INIT_PERF(kb);
	PERF("packet processing start");

	pkg_name = bundle_get_val(kb, AUL_K_APPID);
	SECURE_LOGD("pkg name : %s\n", pkg_name);

	menu_info = _get_app_info_from_bundle_by_pkgname(pkg_name, kb);
	if (menu_info == NULL) {
		_E("such pkg no found");
		goto end;
	}

	app_path = _get_app_path(menu_info);
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

	internal_pool = bundle_get_val(kb, AUL_K_EXEC);
	SECURE_LOGD("exec : %s\n", internal_pool);
	internal_pool = bundle_get_val(kb, AUL_K_INTERNAL_POOL);

	SECURE_LOGD("internal pool : %s\n", internal_pool);
	SECURE_LOGD("hwacc : %s\n", menu_info->hwacc);
	type = __get_launchpad_type(internal_pool, menu_info->hwacc);
	if (type < 0) {
		_E("failed to get launchpad type");
		goto end;
	}

	_modify_bundle(kb, cr.pid, menu_info, pkt->cmd);
	pkg_name = _get_pkgname(menu_info);
	if (pkg_name == NULL) {
		_E("unable to get pkg_name from menu_info");
		goto end;
	}

	PERF("get package information & modify bundle done");

	if ((type >= 0) && (type < LAUNCHPAD_TYPE_MAX)
		&& (__candidate[type].pid != CANDIDATE_NONE)
		&& (DIFF(__candidate[type].last_exec_time, time(NULL)) > EXEC_CANDIDATE_WAIT)) {
		_W("Launch on type-based process-pool");
		pid = __send_launchpad_loader(type, pkt, app_path, clifd);
	} else if ((__candidate[LAUNCHPAD_TYPE_COMMON].pid != CANDIDATE_NONE)
		&& (DIFF(__candidate[LAUNCHPAD_TYPE_COMMON].last_exec_time,
		time(NULL)) > EXEC_CANDIDATE_WAIT)) {
		_W("Launch on common type process-pool");
		pid = __send_launchpad_loader(LAUNCHPAD_TYPE_COMMON, pkt, app_path, clifd);
	} else {
		_W("Candidate is not prepared");
		pid = __launch_directly(pkg_name, app_path, clifd, kb, menu_info);
		__send_result_to_caller(clifd, pid, app_path);
	}
	clifd = -1;

end:
	if (clifd != -1)
		close(clifd);

	if (pid > 0) {
		__send_app_launch_signal_dbus(pid);
	}

	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);

	if (kb != NULL)
		bundle_free(kb);
	if (pkt != NULL)
		free(pkt);

	return G_SOURCE_CONTINUE;
}

static int __init_launchpad_fd(int argc, char **argv)
{
	int fd = -1;

	fd = __launchpad_pre_init(argc, argv);
	if (fd < 0) {
		_E("launchpad pre init failed");
		return -1;
	}

	if (__poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_launch_event, 0) < 0) {
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

	if (__poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_sigchild, 0) < 0) {
		close(fd);
		return -1;
	}

	return 0;
}

static int __init_loader_fds(void)
{
	int i;

	for (i = 0; i < LAUNCHPAD_TYPE_MAX; ++i) {
		int fd = -1;

		fd = __listen_candidate_process(i);
		if (fd == -1) {
			_E("[launchpad] Listening the socket to the type %d candidate process failed.",
			   i);
			return -1;
		}

		if (__poll_fd(fd, G_IO_IN, (GSourceFunc)__handle_loader_event, i) < 0) {
			close(fd);
			return -1;
		}
	}

	return 0;
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

	if (__init_loader_fds() != 0) {
		_E("__init_loader_fds() failed");
		return -1;
	}

	__preload_candidate_process();

	return 0;
}

static void __set_priority(void)
{
#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	int res = setpriority(PRIO_PROCESS, 0, -12);
	if (res == -1) {
		char err_str[MAX_LOCAL_BUFSZ] = { 0, };

		SECURE_LOGE("Setting process (%d) priority to -12 failed, errno: %d (%s)",
			getpid(), errno, strerror_r(errno, err_str, sizeof(err_str)));
	}
#endif
}

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

	__set_priority();
	g_main_loop_run(mainloop);

	return -1;
}
