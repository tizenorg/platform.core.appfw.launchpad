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
#include <dlfcn.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <sqlite3.h>
#include <Elementary.h>
#include <Ecore.h>
#include <bundle_internal.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <security-manager.h>

#include "menu_db_util.h"
#include "launchpad_common.h"
#include "preload.h"
#include "process_pool_preload.h"
#include "preexec.h"
#include "key.h"

#define AUL_PR_NAME 16
#define LOWEST_PRIO 20

static char *__appid;
static char *__pkgid;
static bundle *_s_bundle;

const char* const HOME = "HOME";
const char* const APP_HOME_PATH = "/opt/home/app";

static int __set_access(const char* appId, const char* pkg_type,
			const char* app_path)
{
	return security_manager_prepare_app(appId) == SECURITY_MANAGER_SUCCESS ? 0 : -1;
}

static int __candidate_process_prepare_exec(const char *pkg_name,
		const char *app_path, app_info_from_db *menu_info,
		bundle *kb, int type)
{
	const char *file_name = NULL;
	char process_name[AUL_PR_NAME] = { 0, };
	int ret = 0;

	__preexec_run(menu_info->pkg_type, pkg_name, app_path);

	/* SET PRIVILEGES*/
	SECURE_LOGD("[candidata] pkg_name : %s / pkg_type : %s / app_path : %s",
			pkg_name, menu_info->pkg_type, app_path);
	if ((ret = __set_access(pkg_name, menu_info->pkg_type, app_path)) < 0) {
		_D("fail to set privileges - check your package's credential : %d\n", ret);
		return -1;
	}

	/*
	 * SET DUMPABLE - for coredump
	 * This dumpable flag should be set after calling perm_app_set_privilege()
	 */
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

static void __at_exit_to_release_bundle()
{
	if (_s_bundle) {
		bundle_free(_s_bundle);
		_s_bundle = NULL;
	}
}

static void __release_appid_at_exit(void)
{
	if (__appid != NULL) {
		free(__appid);
	}
	if (__pkgid != NULL) {
		free(__pkgid);
	}
}

static void __candidate_process_launchpad_main_loop(app_pkt_t* pkt,
	char* out_app_path, int* out_argc, char ***out_argv,
	int type)
{
	bundle *kb = NULL;
	app_info_from_db *menu_info = NULL;

	const char *app_id = NULL;
	const char *app_path = NULL;
	//const char *pkg_id = NULL;

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_E("bundle decode error");
		exit(-1);
	}

	if (_s_bundle != NULL)
		bundle_free(_s_bundle);

	_s_bundle = kb;
	atexit(__at_exit_to_release_bundle);

	app_id = bundle_get_val(kb, AUL_K_APPID);
	if (app_id == NULL) {
		_E("Unable to get app_id");
		exit(-1);
	}

	menu_info = _get_app_info_from_bundle_by_pkgname(app_id, kb);
	if (menu_info == NULL) {
		_D("such pkg no found");
		exit(-1);
	}

	if (type < 0) {
		_E("Invalid launchpad type: %d", type);
		exit(-1);
	}

	SECURE_LOGD("app id: %s, launchpad type: %d", app_id, type);

	app_path = _get_app_path(menu_info);
	if (app_path == NULL) {
		_E("app_path is NULL");
		exit(-1);
	}

	if (app_path[0] != '/') {
		_E("app_path is not absolute path");
		exit(-1);
	}

	_modify_bundle(kb, /*cr.pid - unused parameter*/ 0, menu_info, pkt->cmd);

	// caching appid
	app_id = _get_pkgname(menu_info);
	if (app_id == NULL) {
		_E("unable to get app_id from menu_info");
		exit(-1);
	}
	SECURE_LOGD("app id: %s", app_id);
#if 0
	//TODO : FIXME
	__appid = strdup(app_id);
	if (__appid == NULL) {
		_E("Out of memory");
		exit(-1);
	}
	//aul_set_preinit_appid(__appid); //TODO

	// caching pkgid
	pkg_id = _get_pkgid(menu_info);
	if (pkg_id == NULL) {
		_E("unable to get pkg_id from menu_info");
		exit(-1);
	}
	SECURE_LOGD("pkg id: %s", pkg_id);

	__pkgid = strdup(pkg_id);
	if (__pkgid == NULL) {
		_E("Out of memory");
		exit(-1);
	}
	//aul_set_preinit_pkgid(__pkgid); //TODO
#endif

	atexit(__release_appid_at_exit);

#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	const char *high_priority = bundle_get_val(kb, AUL_K_HIGHPRIORITY);
	_D("high_priority: %s", high_priority);

	if (strncmp(high_priority, "true", 4) == 0) {
		int res = setpriority(PRIO_PROCESS, 0, -10);
		if (res == -1) {
			SECURE_LOGE("Setting process (%d) priority to -10 failed, errno: %d (%s)",
				getpid(), errno, strerror(errno));
		}
	}
	bundle_del(kb, AUL_K_HIGHPRIORITY);
#endif

	if (__candidate_process_prepare_exec(app_id, app_path, menu_info, kb,
	                                     type) < 0) {
		_E("__candidate_process_prepare_exec() failed");
		if (access(app_path, F_OK | R_OK)) {
			SECURE_LOGE("access() failed for file: \"%s\", error: %d (%s)",
				app_path, errno, strerror(errno));
		}
		exit(-1);
	}

	if (out_app_path != NULL && out_argc != NULL && out_argv != NULL) {
		int i = 0;

		memset(out_app_path, '\0', strlen(out_app_path));
		sprintf(out_app_path, "%s", app_path);

		*out_argv = _create_argc_argv(kb, out_argc);
		(*out_argv)[0] = out_app_path;

		for (i = 0; i < *out_argc; i++)
			SECURE_LOGD("input argument %d : %s##", i, (*out_argv)[i]);
	} else
		exit(-1);

	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);
}

static Eina_Bool __candidate_proces_fd_handler(void* data,
	Ecore_Fd_Handler *handler)
{
	int type = data ? *((int *)data) : LAUNCHPAD_TYPE_UNSUPPORTED;
	int fd = ecore_main_fd_handler_fd_get(handler);

	if (fd == -1) {
		_D("[candidate] ECORE_FD_GET");
		exit(-1);
	}

	if (ecore_main_fd_handler_active_get(handler, ECORE_FD_ERROR)) {
		_D("[candidate] ECORE_FD_ERROR");
		close(fd);
		exit(-1);
	}

	if (ecore_main_fd_handler_active_get(handler, ECORE_FD_READ)) {
		_D("[candidate] ECORE_FD_READ");
		app_pkt_t* pkt = (app_pkt_t*) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
		if (!pkt) {
			_D("[candidate] out of memory1");
			exit(-1);
		}
		memset(pkt, 0, AUL_SOCK_MAXBUFF);

		int recv_ret = recv(fd, pkt, AUL_SOCK_MAXBUFF, 0);
		close(fd);
		if (recv_ret == -1) {
			_D("[condidate] recv error!");
			free(pkt);
			exit(-1);
		}
		_D("[candidate] recv_ret: %d, pkt->len: %d", recv_ret, pkt->len);

		ecore_main_fd_handler_del(handler);

		__candidate_process_launchpad_main_loop(pkt, g_argv[0], &g_argc, &g_argv, type);
		SECURE_LOGD("[candidate] real app argv[0]: %s, real app argc: %d", g_argv[0],
		            g_argc);
		free(pkt);

		ecore_main_loop_quit();
		_D("[candidate] ecore main loop quit");
	}

	return ECORE_CALLBACK_CANCEL;
}

static void __init_window(void)
{
#if 0 //TODO : FIXME
	Evas_Object *win = elm_win_add(NULL, "package_name", ELM_WIN_BASIC);
	if (win) {
		aul_set_preinit_window(win);

		Evas_Object *bg = elm_bg_add(win);
		if (bg) {
			evas_object_size_hint_weight_set(bg, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
			elm_win_resize_object_add(win, bg);
			aul_set_preinit_background(bg);
		} else {
			_E("[candidate] elm_bg_add() failed");
		}

		Evas_Object *conform = elm_conformant_add(win);
		if (conform) {
			evas_object_size_hint_weight_set(conform, EVAS_HINT_EXPAND, EVAS_HINT_EXPAND);
			elm_win_resize_object_add(win, conform);
			aul_set_preinit_conformant(conform);
		} else {
			_E("elm_conformant_add() failed");
		}
	} else {
		_E("[candidate] elm_win_add() failed");
	}
#endif
}

static void __init_theme(void)
{
	char *theme = elm_theme_list_item_path_get(eina_list_data_get(
			elm_theme_list_get(NULL)), NULL);
	Eina_Bool is_exist = edje_file_group_exists(theme, "*");
	if (!is_exist)
		_D("theme path: %s", theme);

	if (theme)
		free(theme);
}

static int __before_loop(int type, int argc, char **argv)
{
	int elm_init_cnt = 0;
	Ecore_Fd_Handler *fd_handler = NULL;
	int client_fd;

	__preload_init(argc, argv);
	__preload_init_for_process_pool();
	__preexec_init(argc, argv);

#ifdef _APPFW_FEATURE_BOOST_PRIORITY
	res = setpriority(PRIO_PROCESS, 0, LOWEST_PRIO);
	if (res == -1) {
		SECURE_LOGE("Setting process (%d) priority to %d failed, errno: %d (%s)",
			getpid(), LOWEST_PRIO, errno, strerror(errno));
	}
#endif
	_D("[candidate] Another candidate process was forked.");

	/* Set new session ID & new process group ID*/
	/* In linux, child can set new session ID without check permission */
	/* TODO : should be add to check permission in the kernel*/
	setsid();

	/* SET OOM*/
	_set_oom();

	client_fd = _connect_to_launchpad(type);
	if (client_fd == -1) {
		_D("Connecting to candidate process was failed.");
		return -1;
	}

	/* Temporarily change HOME path to app
	   This change is needed for getting elementary profile
	   /opt/home/app/.elementary/config/mobile/base.cfg */
	setenv(HOME, APP_HOME_PATH, 1);

	elm_init_cnt = elm_init(g_argc, g_argv);
	_D("[candidate] elm init, returned: %d", elm_init_cnt);

	switch (type) {
		case LAUNCHPAD_TYPE_SW:
			elm_config_accel_preference_set("none");
			__init_window();
			break;

		case LAUNCHPAD_TYPE_HW:
			elm_config_accel_preference_set("hw");
			__init_window();
			break;

		case LAUNCHPAD_TYPE_COMMON:
			__init_theme();
			break;
	}

	fd_handler = ecore_main_fd_handler_add(client_fd,
				(Ecore_Fd_Handler_Flags)(ECORE_FD_READ | ECORE_FD_ERROR),
				__candidate_proces_fd_handler, &type, NULL, NULL);
	if (fd_handler == NULL) {
		_D("fd_handler is NULL");
		return -1;
	}

	_D("[candidate] ecore handler add");
#ifdef _APPFW_FEATURE_BOOST_PRIORITY
	res = setpriority(PRIO_PGRP, 0, 0);
	if (res == -1) {
		SECURE_LOGE("Setting process (%d) priority to 0 failed, errno: %d (%s)",
			getpid(), errno, strerror(errno));
	}
#endif
	return 0;
}

static int __after_loop(void)
{
	void *handle = NULL;
	int res;
	int (*dl_main)(int, char **);

	SECURE_LOGD("[candidate] Launch real application (%s)", g_argv[0]);
	handle = dlopen(g_argv[0], RTLD_LAZY | RTLD_GLOBAL);
	if (handle == NULL) {
		_E("dlopen failed(%s). Please complile with -fPIE and link with -pie flag",
			dlerror());
		goto do_exec;
	}

	dlerror();

	dl_main = dlsym(handle, "main");
	if (dl_main != NULL)
		res = dl_main(g_argc, g_argv);
	else {
		_E("dlsym not founded(%s). Please export 'main' function", dlerror());
		dlclose(handle);
		goto do_exec;
	}

	dlclose(handle);
	return res;

do_exec:
	if (access(g_argv[0], F_OK | R_OK)) {
		SECURE_LOGE("access() failed for file: \"%s\", error: %d (%s)",
			g_argv[0], errno, strerror(errno));
	} else {
		SECURE_LOGD("[candidate] Exec application (%s)", g_argv[0]);
		if (execv(g_argv[0], g_argv) < 0) {
			SECURE_LOGE("execv() failed for file: \"%s\", error: %d (%s)",
				g_argv[0], errno, strerror(errno));
		}
	}

	return -1;
}

int main(int argc, char **argv)
{
	static int type = LAUNCHPAD_TYPE_UNSUPPORTED;

	if (argc < 2) {
		_E("too few argument.");
		return -1;
	}

	type = argv[1][0] - '0';
	if (type < 0 || type >= LAUNCHPAD_TYPE_MAX) {
		_E("invalid argument. (type: %d)", type);
		return -1;
	}

	//temp - this requires some optimization.
	sleep(1);
	_D("sleeping 1 sec...");

	if (__before_loop(type, argc, argv) != 0)
		return -1;

	_D("[candidate] ecore main loop begin");
	ecore_main_loop_begin();

	return __after_loop();
}
