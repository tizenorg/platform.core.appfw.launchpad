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

#ifndef __MENU_DB_UTIL_H_
#define __MENU_DB_UTIL_H_

#include <string.h>
#include <stdio.h>
#include <malloc.h>

#define MAX_PATH_LEN	1024

typedef struct {
	char *pkg_name;		/* appid */
	char *app_path;		/* exec */
	char *original_app_path;	/* exec */
	char *pkg_type;		/* x_slp_packagetype */
	char *hwacc;		/* hwacceleration */
	char *taskmanage;	/* taskmanage */
	char *pkg_id;
} app_info_from_db;

static inline char *_get_pkgname(app_info_from_db *menu_info)
{
	return menu_info ? menu_info->pkg_name : NULL;
}

static inline char *_get_pkgid(app_info_from_db *menu_info)
{
	return menu_info ? menu_info->pkg_id : NULL;
}

static inline char *_get_app_path(app_info_from_db *menu_info)
{
	int i = 0;
	int path_len = -1;

	if (!menu_info || menu_info->app_path == NULL)
		return NULL;

	while (menu_info->app_path[i] != 0) {
		if (menu_info->app_path[i] == ' '
		    || menu_info->app_path[i] == '\t') {
			path_len = i;
			break;
		}
		i++;
	}

	if (path_len == 0) {
		free(menu_info->app_path);
		menu_info->app_path = NULL;
	} else if (path_len > 0) {
		char *tmp_app_path = malloc(sizeof(char) * (path_len + 1));
		if(tmp_app_path == NULL)
			return NULL;
		snprintf(tmp_app_path, path_len + 1, "%s", menu_info->app_path);
		free(menu_info->app_path);
		menu_info->app_path = tmp_app_path;
	}

	return menu_info->app_path;
}

static inline char *_get_original_app_path(app_info_from_db *menu_info)
{
	return menu_info ? menu_info->original_app_path : NULL;
}

static inline void _free_app_info_from_db(app_info_from_db *menu_info)
{
	if (menu_info != NULL) {
		if (menu_info->pkg_name != NULL)
			free(menu_info->pkg_name);
		if (menu_info->app_path != NULL)
			free(menu_info->app_path);
		if (menu_info->original_app_path != NULL)
			free(menu_info->original_app_path);
		if (menu_info->pkg_type != NULL)
			free(menu_info->pkg_type);
		if (menu_info->hwacc != NULL)
			free(menu_info->hwacc);
		if (menu_info->taskmanage != NULL)
			free(menu_info->taskmanage);
		if (menu_info->pkg_id != NULL)
			free(menu_info->pkg_id);
		free(menu_info);
	}
}

#endif
