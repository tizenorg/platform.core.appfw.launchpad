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
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <Elementary.h>
#include <bundle_internal.h>
#include <aul.h>

#include "launchpad_common.h"
#include "preload.h"
#include "process_pool_preload.h"
#include "launchpad.h"

static Ecore_Fd_Handler *__fd_handler;
static loader_receiver_cb __receiver;

static void __init_window(void)
{
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

static void __loader_create_cb(int argc, char **argv, int type, void *user_data)
{
	int elm_init_cnt = 0;

	__preload_init(argc, argv);
	__preload_init_for_process_pool();

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
}

static int __loader_launch_cb(int argc, char **argv, const char *app_path,
			const char *appid, const char *pkgid, const char *pkg_type, void *user_data)
{
	return 0;
}

static int __loader_terminate_cb(int argc, char **argv, void *user_data)
{
	void *handle = NULL;
	int res;
	int (*dl_main)(int, char **);

	SECURE_LOGD("[candidate] Launch real application (%s)", argv[0]);
	handle = dlopen(argv[0], RTLD_LAZY | RTLD_GLOBAL);
	if (handle == NULL) {
		_E("dlopen failed(%s). Please complile with -fPIE and link with -pie flag",
			dlerror());
		goto do_exec;
	}

	dlerror();

	dl_main = dlsym(handle, "main");
	if (dl_main != NULL)
		res = dl_main(argc, argv);
	else {
		_E("dlsym not founded(%s). Please export 'main' function", dlerror());
		dlclose(handle);
		goto do_exec;
	}

	dlclose(handle);
	return res;

do_exec:
	if (access(argv[0], F_OK | R_OK)) {
		char err_str[MAX_LOCAL_BUFSZ] = { 0, };

		SECURE_LOGE("access() failed for file: \"%s\", error: %d (%s)",
			argv[0], errno, strerror_r(errno, err_str, sizeof(err_str)));
	} else {
		SECURE_LOGD("[candidate] Exec application (%s)", g_argv[0]);
		if (execv(argv[0], argv) < 0) {
			char err_str[MAX_LOCAL_BUFSZ] = { 0, };

			SECURE_LOGE("execv() failed for file: \"%s\", error: %d (%s)",
				argv[0], errno, strerror_r(errno, err_str, sizeof(err_str)));
		}
	}

	return -1;

}

static Eina_Bool __process_fd_handler(void* data, Ecore_Fd_Handler *handler)
{
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
		if (__receiver)
			__receiver(fd);
	}

	return ECORE_CALLBACK_CANCEL;
}

static void __adapter_loop_begin(void *user_data)
{
	ecore_main_loop_begin();
}

static void __adapter_loop_quit(void *user_data)
{
	ecore_main_loop_quit();
}

static void __adapter_add_fd(void *user_data, int fd,
                             loader_receiver_cb receiver)
{
	__fd_handler = ecore_main_fd_handler_add(fd,
			(Ecore_Fd_Handler_Flags)(ECORE_FD_READ | ECORE_FD_ERROR),
			__process_fd_handler, NULL, NULL, NULL);
	if (__fd_handler == NULL) {
		_D("fd_handler is NULL");
		close(fd);
		exit(-1);
	}

	__receiver = receiver;
}

static void __adapter_remove_fd(void *user_data, int fd)
{
	if (__fd_handler) {
		ecore_main_fd_handler_del(__fd_handler);
		__fd_handler = NULL;
		__receiver = NULL;
	}
}

int main(int argc, char **argv)
{
	loader_lifecycle_callback_s callbacks = {
		.create = __loader_create_cb,
		.launch = __loader_launch_cb,
		.terminate = __loader_terminate_cb
	};

	loader_adapter_s adapter = {
		.loop_begin = __adapter_loop_begin,
		.loop_quit = __adapter_loop_quit,
		.add_fd = __adapter_add_fd,
		.remove_fd = __adapter_remove_fd
	};

	return launchpad_loader_main(argc, argv, &callbacks, &adapter, NULL);
}
