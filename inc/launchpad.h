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

#ifndef __LAUNCHPAD_H__
#define __LAUNCHPAD_H__

#include <bundle.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*loader_create_cb)(bundle *extra, int type, void *user_data);
typedef int (*loader_launch_cb)(int argc, char **argv, const char *app_path,
		const char *appid, const char *pkgid, const char *pkg_type, void *user_data);
typedef int (*loader_terminate_cb)(int argc, char **argv, void *user_data);

typedef void (*loader_receiver_cb)(int fd);
typedef void (*loader_loop_begin_cb)(void *user_data);
typedef void (*loader_loop_quit_cb)(void *user_data);
typedef void (*loader_add_fd_cb)(void *user_data, int fd, loader_receiver_cb receiver);
typedef void (*loader_remove_fd_cb)(void *user_data, int fd);

typedef struct {
	loader_create_cb create;
	loader_launch_cb launch;
	loader_terminate_cb terminate;
} loader_lifecycle_callback_s;

typedef struct {
	loader_loop_begin_cb loop_begin;
	loader_loop_quit_cb loop_quit;
	loader_add_fd_cb add_fd;
	loader_remove_fd_cb remove_fd;
} loader_adapter_s;

enum LAUNCHPAD_TYPE {
	LAUNCHPAD_TYPE_UNSUPPORTED = -1,
	LAUNCHPAD_TYPE_COMMON,
	LAUNCHPAD_TYPE_SW,
	LAUNCHPAD_TYPE_HW,
	LAUNCHPAD_TYPE_WRT,
	LAUNCHPAD_TYPE_DYNAMIC,
	LAUNCHPAD_TYPE_MAX
};

int launchpad_loader_main(int argc, char **argv, loader_lifecycle_callback_s *callbacks, loader_adapter_s *adapter, void *user_data);

#ifdef __cplusplus
}
#endif

#endif  /* __LAUNCHPAD_H__ */

