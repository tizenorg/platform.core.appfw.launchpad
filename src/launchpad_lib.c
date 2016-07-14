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
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <malloc.h>
#ifdef _APPFW_FEATURE_LOADER_PRIORITY
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <bundle_internal.h>
#include <aul.h>
#include <security-manager.h>

#include "launchpad_common.h"
#include "launchpad.h"
#include "preexec.h"

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

#define AUL_PR_NAME 16
#define LOWEST_PRIO 20

static loader_lifecycle_callback_s *__loader_callbacks;
static loader_adapter_s *__loader_adapter;
static void *__loader_user_data;
static int __argc;
static char **__argv;
static bundle *__bundle;
static int __loader_type = LAUNCHPAD_TYPE_UNSUPPORTED;
static int __loader_id;

static void __at_exit_to_release_bundle()
{
	if (__bundle)
		bundle_free(__bundle);
}

static int __prepare_exec(const char *appid, const char *app_path,
			const char *pkg_type, int type)
{
	const char *file_name = NULL;
	char process_name[AUL_PR_NAME] = { 0, };
	int ret;

	__preexec_run(pkg_type, appid, app_path);

	/* SET PRIVILEGES*/
	SECURE_LOGD("[candidata] appid : %s / pkg_type : %s / app_path : %s",
		appid, pkg_type, app_path);
	ret = security_manager_prepare_app(appid);
	if (ret != SECURITY_MANAGER_SUCCESS) {
		_D("fail to set privileges - check your package's credential: "
				"%d\n", ret);
		return -1;
	}

	/*
	 * SET DUMPABLE - for coredump
	 * This dumpable flag should be set after
	 * calling perm_app_set_privilege().
	 */
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME*/
	if (app_path == NULL) {
		_D("app_path should not be NULL - check menu db");
		return -1;
	}

	file_name = strrchr(app_path, '/');
	if (file_name == NULL) {
		_D("file_name is NULL");
		return -1;
	}

	file_name++;
	if (file_name == '\0') {
		_D("can't locate file name to execute");
		return -1;
	}

	_prepare_listen_sock();

	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	return 0;
}

static int __default_launch_cb(bundle *kb, const char *appid,
		const char *app_path, const char *pkg_type, int loader_type)
{
	char err_str[MAX_LOCAL_BUFSZ] = { 0, };
#ifdef _APPFW_FEATURE_PRIORITY_CHANGE
	int res;
	const char *high_priority = bundle_get_val(kb, AUL_K_HIGHPRIORITY);

	_D("high_priority: %s", high_priority);
	if (strncmp(high_priority, "true", 4) == 0) {
		res = setpriority(PRIO_PROCESS, 0, -10);
		if (res == -1) {
			SECURE_LOGE("Setting process (%d) priority "
				"to -10 failed, errno: %d (%s)",
				getpid(), errno,
				strerror_r(errno, err_str, sizeof(err_str)));
		}
	}
	bundle_del(kb, AUL_K_HIGHPRIORITY);
#endif

	if (__prepare_exec(appid, app_path, pkg_type, loader_type) < 0) {
		_E("__candidate_process_prepare_exec() failed");
		if (access(app_path, F_OK | R_OK)) {
			SECURE_LOGE("access() failed for file: \"%s\", "
				"error: %d (%s)", app_path, errno,
				strerror_r(errno, err_str, sizeof(err_str)));
		}
		exit(-1);
	}

	return 0;
}

static int __candidate_process_launchpad_main_loop(app_pkt_t *pkt,
		char *out_app_path, int *out_argc, char ***out_argv, int type)
{
	bundle *kb;
	appinfo_t *menu_info = NULL;
	const char *app_path = NULL;
	int tmp_argc = 0;
	char **tmp_argv = NULL;
	int ret = -1;
	int i;

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_E("bundle decode error");
		exit(-1);
	}

	if (__bundle != NULL)
		bundle_free(__bundle);

	__bundle = kb;
	atexit(__at_exit_to_release_bundle);

	menu_info = _appinfo_create(kb);
	if (menu_info == NULL) {
		_D("such pkg no found");
		exit(-1);
	}

	if (menu_info->appid == NULL) {
		_E("Unable to get app_id");
		exit(-1);
	}

	if (type < 0) {
		_E("Invalid launchpad type: %d", type);
		exit(-1);
	}

	SECURE_LOGD("app id: %s, launchpad type: %d", menu_info->appid, type);

	app_path = _appinfo_get_app_path(menu_info);
	if (app_path == NULL) {
		_E("app_path is NULL");
		exit(-1);
	}

	if (app_path[0] != '/') {
		_E("app_path is not absolute path");
		exit(-1);
	}

	_modify_bundle(kb, /*cr.pid - unused parameter*/ 0, menu_info,
			pkt->cmd);

	if (menu_info->pkgid == NULL) {
		_E("unable to get pkg_id from menu_info");
		exit(-1);
	}

	SECURE_LOGD("pkg id: %s", menu_info->pkgid);

	tmp_argv = _create_argc_argv(kb, &tmp_argc);

	__default_launch_cb(kb, menu_info->appid, app_path,
			menu_info->pkg_type, type);

	if (__loader_callbacks->launch) {
		ret = __loader_callbacks->launch(tmp_argc, tmp_argv, app_path,
				menu_info->appid, menu_info->pkgid,
				menu_info->pkg_type, __loader_user_data);
	}

	/* SET ENVIROMENT*/
	_set_env(menu_info, kb);

	if (out_app_path != NULL && out_argc != NULL && out_argv != NULL) {
		memset(out_app_path, '\0', strlen(out_app_path));
		snprintf(out_app_path, LOADER_ARG_LEN, "%s", app_path);

		*out_argv = tmp_argv;
		*out_argc = tmp_argc;
		(*out_argv)[LOADER_ARG_PATH] = out_app_path;

		for (i = 0; i < *out_argc; i++) {
			SECURE_LOGD("input argument %d : %s##", i,
					(*out_argv)[i]);
		}
	} else {
		exit(-1);
	}

	if (menu_info != NULL)
		_appinfo_free(menu_info);

	if (__bundle) {
		bundle_free(__bundle);
		__bundle = NULL;
	}

	return ret;
}

static void __receiver_cb(int fd)
{
	int ret = -1;
	int recv_ret;
	app_pkt_t *pkt;

	_D("[candidate] ECORE_FD_READ");
	pkt = (app_pkt_t *)malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (!pkt) {
		_D("[candidate] out of memory1");
		exit(-1);
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	recv_ret = recv(fd, pkt, AUL_SOCK_MAXBUFF, 0);
	if (recv_ret == -1) {
		_D("[condidate] recv error!");
		close(fd);
		free(pkt);
		exit(-1);
	}
	_D("[candidate] recv_ret: %d, pkt->len: %d", recv_ret, pkt->len);

	__loader_adapter->remove_fd(__loader_user_data, fd);
	close(fd);
	ret = __candidate_process_launchpad_main_loop(pkt,
			__argv[LOADER_ARG_PATH], &__argc, &__argv,
			__loader_type);
	SECURE_LOGD("[candidate] real app argv[0]: %s, real app argc: %d",
			__argv[LOADER_ARG_PATH], __argc);
	free(pkt);

	if (ret >= 0) {
		__loader_adapter->loop_quit(__loader_user_data);
		_D("[candidate] ecore main loop quit");
	}
}

static int __before_loop(int argc, char **argv)
{
	int client_fd;
	int ret = -1;
	bundle *extra = NULL;
#ifdef _APPFW_FEATURE_LOADER_PRIORITY
	char err_str[MAX_LOCAL_BUFSZ] = { 0, };
	int res = setpriority(PRIO_PROCESS, 0, LOWEST_PRIO);

	if (res == -1) {
		SECURE_LOGE("Setting process (%d) priority to %d failed, "
				"errno: %d (%s)", getpid(), LOWEST_PRIO, errno,
				strerror_r(errno, err_str, sizeof(err_str)));
	}
#endif
	__preexec_init(argc, argv);

	/* Set new session ID & new process group ID*/
	/* In linux, child can set new session ID without check permission */
	/* TODO : should be add to check permission in the kernel*/
	setsid();

	if (argc > 3) {
		extra = bundle_decode((bundle_raw *)argv[LOADER_ARG_EXTRA],
				strlen(argv[LOADER_ARG_EXTRA]));
	}

	if (__loader_callbacks->create) {
		__loader_callbacks->create(extra, __loader_type,
				__loader_user_data);
		ret = 0;
	}

	if (extra)
		bundle_free(extra);

	malloc_trim(0);
#ifdef _APPFW_FEATURE_LOADER_PRIORITY
	res = setpriority(PRIO_PGRP, 0, 0);
	if (res == -1) {
		SECURE_LOGE("Setting process (%d) priority to 0 failed, "
				"errno: %d (%s)", getpid(), errno,
				strerror_r(errno, err_str, sizeof(err_str)));
	}
#endif
	client_fd = _connect_to_launchpad(__loader_type, __loader_id);
	if (client_fd == -1) {
		_D("Connecting to candidate process was failed.");
		return -1;
	}

	__loader_adapter->add_fd(__loader_user_data, client_fd, __receiver_cb);

	return ret;
}

static int __after_loop(void)
{
	if (__loader_callbacks->terminate) {
		return __loader_callbacks->terminate(__argc, __argv,
				__loader_user_data);
	}

	return -1;
}

bundle *launchpad_loader_get_bundle()
{
	return __bundle;
}

API int launchpad_loader_main(int argc, char **argv,
		loader_lifecycle_callback_s *callbacks,
		loader_adapter_s *adapter, void *user_data)
{
	if (argc < 3) {
		_E("too few argument.");
		return -1;
	}

	__loader_type = argv[LOADER_ARG_TYPE][0] - '0';
	if (__loader_type < 0 || __loader_type >= LAUNCHPAD_TYPE_MAX) {
		_E("invalid argument. (type: %d)", __loader_type);
		return -1;
	}

	__loader_id = atoi(argv[LOADER_ARG_ID]);

	if (callbacks == NULL) {
		_E("invalid argument. callback is null");
		return -1;
	}

	if (adapter == NULL) {
		_E("invalid argument. adapter is null");
		return -1;
	}

	if (adapter->loop_begin == NULL || adapter->loop_quit == NULL
		|| adapter->add_fd == NULL || adapter->remove_fd == NULL) {
		_E("invalid argument. adapter callback is null");
		return -1;
	}

	__loader_callbacks = callbacks;
	__loader_adapter = adapter;
	__loader_user_data = user_data;
	__argc = argc;
	__argv = argv;

	if (__before_loop(argc, argv) != 0)
		return -1;

	_D("[candidate] ecore main loop begin");
	__loader_adapter->loop_begin(__loader_user_data);

	return __after_loop();
}

