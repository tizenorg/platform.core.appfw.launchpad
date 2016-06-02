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
#include <stdbool.h>
#include <dlfcn.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <malloc.h>
#include <linux/limits.h>
#include <Elementary.h>
#include <bundle_internal.h>
#include <aul.h>
#include <vconf.h>

#include "launchpad_common.h"
#include "preload.h"
#include "process_pool_preload.h"
#include "launchpad.h"

extern bundle *launchpad_loader_get_bundle();

static Ecore_Fd_Handler *__fd_handler;
static loader_receiver_cb __receiver;

static int __argc;
static char **__argv;
static int __sys_hwacc;
static Evas_Object *__win;
static Evas_Object *__bg;
static Evas_Object *__conform;

static void __vconf_cb(keynode_t *key, void *data)
{
	const char *name;

	name = vconf_keynode_get_name(key);
	if (name && strcmp(name, VCONFKEY_SETAPPL_APP_HW_ACCELERATION) == 0) {
		__sys_hwacc = vconf_keynode_get_int(key);
		_D("sys hwacc: %d", __sys_hwacc);
	}
}

static void __init_window(void)
{
	__win = elm_win_add(NULL, "package_name", ELM_WIN_BASIC);
	if (__win == NULL) {
		_E("[candidate] elm_win_add() failed");
		return;
	}

	elm_win_precreated_object_set(__win);

	__bg = elm_bg_add(__win);
	if (__bg) {
		evas_object_size_hint_weight_set(__bg, EVAS_HINT_EXPAND,
				EVAS_HINT_EXPAND);
		elm_win_resize_object_add(__win, __bg);
		elm_bg_precreated_object_set(__bg);
	} else {
		_E("[candidate] elm_bg_add() failed");
	}

	__conform = elm_conformant_add(__win);
	if (__conform) {
		evas_object_size_hint_weight_set(__conform, EVAS_HINT_EXPAND,
				EVAS_HINT_EXPAND);
		elm_win_resize_object_add(__win, __conform);
		elm_conformant_precreated_object_set(__conform);
	} else {
		_E("elm_conformant_add() failed");
	}
}

static void __fini_window(void)
{
	if (__conform) {
		evas_object_del(__conform);
		elm_conformant_precreated_object_set(NULL);
		__conform = NULL;
	}

	if (__bg) {
		evas_object_del(__bg);
		elm_bg_precreated_object_set(NULL);
		__bg = NULL;
	}

	if (__win) {
		evas_object_del(__win);
		elm_win_precreated_object_set(NULL);
		__win = NULL;
	}
}

static void __loader_create_cb(bundle *extra, int type, void *user_data)
{
	int elm_init_cnt = 0;
	int ret;

	__preload_init(__argc, __argv);
	__preload_init_for_process_pool();

	elm_init_cnt = elm_init(__argc, __argv);
	_D("[candidate] elm init, returned: %d", elm_init_cnt);

	elm_config_accel_preference_set("hw");
	__init_window();

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
	malloc_trim(0);
}

static int __loader_launch_cb(int argc, char **argv, const char *app_path,
		const char *appid, const char *pkgid, const char *pkg_type,
		void *user_data)
{
	const char *hwacc;
	bundle *kb = launchpad_loader_get_bundle();

	vconf_ignore_key_changed(VCONFKEY_SETAPPL_APP_HW_ACCELERATION, __vconf_cb);
	if (kb == NULL)
		return 0;

	hwacc = bundle_get_val(kb, AUL_K_HWACC);

	if (!hwacc)
		return 0;

	if (strcmp(hwacc, "USE") == 0) {
		_D("Use preinitialized window");
		return 0;
	} else if (strcmp(hwacc, "SYS") == 0 &&
			__sys_hwacc == SETTING_HW_ACCELERATION_ON) {
		_D("Use preinitialized window");
		return 0;
	}

	_D("Dispose window");
	__fini_window();
	elm_config_accel_preference_set("none");

	return 0;
}

static void __close_fds(void)
{
	int iter_fd;
	int max_fd = sysconf(_SC_OPEN_MAX);

	for (iter_fd = 3; iter_fd <= max_fd; iter_fd++)
		close(iter_fd);
}

static int __loader_terminate_cb(int argc, char **argv, void *user_data)
{
	void *handle;
	int res;
	int (*dl_main)(int, char **);
	char err_str[MAX_LOCAL_BUFSZ];
	char old_cwd[PATH_MAX];
	bool restore = false;
	char *libdir = NULL;

	SECURE_LOGD("[candidate] Launch real application (%s)",
			argv[LOADER_ARG_PATH]);

	if (getcwd(old_cwd, sizeof(old_cwd)) == NULL)
		goto do_dlopen;

	libdir = _get_libdir(argv[LOADER_ARG_PATH]);
	if (libdir == NULL)
		goto do_dlopen;

	/* To support 2.x applications which use their own shared libraries.
	 * We set '-rpath' to make the dynamic linker looks in the CWD forcely,
	 * so here we change working directory to find shared libraries well.
	 */
	if (chdir(libdir))
		_E("failed to chdir: %d", errno);
	else
		restore = true;

do_dlopen:
	handle = dlopen(argv[LOADER_ARG_PATH],
			RTLD_LAZY | RTLD_GLOBAL | RTLD_DEEPBIND);
	if (handle == NULL) {
		_E("dlopen failed(%s). Please complile with -fPIE and "
				"link with -pie flag", dlerror());
		goto do_exec;
	}

	dlerror();

	if (restore && chdir(old_cwd))
		_E("failed to chdir: %d", errno);

	dl_main = dlsym(handle, "main");
	if (dl_main == NULL) {
		_E("dlsym not founded(%s). Please export 'main' function",
				dlerror());
		dlclose(handle);
		goto do_exec;
	}

	free(libdir);
	res = dl_main(argc, argv);
	dlclose(handle);

	return res;

do_exec:
	if (access(argv[LOADER_ARG_PATH], F_OK | R_OK)) {
		SECURE_LOGE("access() failed for file: \"%s\", error: %d (%s)",
				argv[LOADER_ARG_PATH], errno,
				strerror_r(errno, err_str, sizeof(err_str)));
	} else {
		SECURE_LOGD("[candidate] Exec application (%s)",
				__argv[LOADER_ARG_PATH]);
		__close_fds();
		if (libdir)
			setenv("LD_LIBRARY_PATH", libdir, 1);
		free(libdir);
		if (execv(argv[LOADER_ARG_PATH], argv) < 0) {
			SECURE_LOGE("execv() failed for file: \"%s\", "
				"error: %d (%s)", argv[LOADER_ARG_PATH], errno,
				strerror_r(errno, err_str, sizeof(err_str)));
		}
	}

	return -1;
}

static Eina_Bool __process_fd_handler(void *data, Ecore_Fd_Handler *handler)
{
	int fd;

	fd = ecore_main_fd_handler_fd_get(handler);
	if (fd == -1) {
		_D("[candidate] ECORE_FD_GET");
		exit(-1);
	}

	if (ecore_main_fd_handler_active_get(handler, ECORE_FD_READ)) {
		if (__receiver)
			__receiver(fd);
	} else if (ecore_main_fd_handler_active_get(handler, ECORE_FD_ERROR)) {
		_D("[candidate] ECORE_FD_ERROR");
		close(fd);
		exit(-1);
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
			ECORE_FD_READ | ECORE_FD_ERROR, __process_fd_handler,
			NULL, NULL, NULL);
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

	__argc = argc;
	__argv = argv;

	return launchpad_loader_main(argc, argv, &callbacks, &adapter, NULL);
}

