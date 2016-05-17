/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <malloc.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

#include "loader_info.h"
#include "launchpad_common.h"

#define TAG_LOADER	"[LOADER]"
#define TAG_NAME	"NAME"
#define TAG_EXE		"EXE"
#define TAG_APP_TYPE	"APP_TYPE"
#define TAG_DETECTION_METHOD	"DETECTION_METHOD"
#define TAG_TIMEOUT	"TIMEOUT"
#define VAL_METHOD_TIMEOUT	"TIMEOUT"
#define VAL_METHOD_DEMAND	"DEMAND"
#define VAL_METHOD_VISIBILITY	"VISIBILITY"

static loader_info_t *__create_loader_info()
{
	loader_info_t *info = malloc(sizeof(loader_info_t));

	info->type = 0;
	info->name = NULL;
	info->exe = NULL;
	info->app_type = NULL;
	info->detection_method = METHOD_TIMEOUT | METHOD_VISIBILITY;
	info->timeout_val = 5000;

	return info;
}

static void __parse_detection_method(loader_info_t *info, char *line)
{
	char *token;
	char *savedptr;
	char refined_tok[MAX_LOCAL_BUFSZ];

	token = strtok_r(line, "|", &savedptr);
	info->detection_method = 0;
	while (token) {
		sscanf(token, "%s", refined_tok);
		if (!strcmp(refined_tok, VAL_METHOD_TIMEOUT))
			info->detection_method |= METHOD_TIMEOUT;
		if (!strcmp(refined_tok, VAL_METHOD_VISIBILITY))
			info->detection_method |= METHOD_VISIBILITY;
		if (!strcmp(refined_tok, VAL_METHOD_DEMAND))
			info->detection_method |= METHOD_DEMAND;

		token = strtok_r(NULL, "|", &savedptr);
	}

	_D("detection_method:%d", info->detection_method);
}

static GList *__parse_file(GList *list, const char *path)
{
	FILE *fp;
	char buf[MAX_LOCAL_BUFSZ];
	char tok1[MAX_LOCAL_BUFSZ];
	char tok2[MAX_LOCAL_BUFSZ];
	loader_info_t *cur_info = NULL;

	fp = fopen(path, "rt");

	if (fp == NULL)
		return list;

	while (fgets(buf, MAX_LOCAL_BUFSZ, fp) != NULL) {
		tok1[0] = '\0';
		tok2[0] = '\0';
		sscanf(buf, "%s %s", tok1, tok2);

		if (strcasecmp(TAG_LOADER,  tok1) == 0) {
			if (cur_info != NULL)
				list = g_list_append(list, cur_info);
			cur_info = __create_loader_info();
			continue;
		}

		if (tok1[0] == '\0' || tok2[0] == '\0' || tok1[0] == '#')
			continue;

		if (strcasecmp(TAG_NAME,  tok1) == 0)
			cur_info->name = strdup(tok2);
		else if (strcasecmp(TAG_EXE, tok1) == 0)
			cur_info->exe = strdup(tok2);
		else if (strcasecmp(TAG_APP_TYPE, tok1) == 0)
			cur_info->app_type = strdup(tok2);
		else if (strcasecmp(TAG_DETECTION_METHOD, tok1) == 0)
			__parse_detection_method(cur_info, &buf[strlen(tok1)]);
		else if (strcasecmp(TAG_TIMEOUT,  tok1) == 0)
			cur_info->timeout_val = atoi(tok2);
	}

	if (cur_info != NULL)
		list = g_list_append(list, cur_info);

	fclose(fp);

	return list;
}

GList *_loader_info_load(const char *path)
{
	DIR *dir_info;
	struct dirent entry;
	struct dirent *result = NULL;
	GList *list = NULL;
	char buf[MAX_LOCAL_BUFSZ];
	char *ext;

	dir_info = opendir(path);
	if (dir_info == NULL)
		return  NULL;

	while (readdir_r(dir_info, &entry, &result) == 0 && result != NULL) {
		if (entry.d_name[0] == '.')
			continue;
		ext = strrchr(entry.d_name, '.');
		if (ext && !strcmp(ext, ".loader")) {
			snprintf(buf, sizeof(buf), "%s/%s", path, entry.d_name);
			list = __parse_file(list, buf);
		}
	}
	closedir(dir_info);

	return list;
}

static void __free_info(gpointer data)
{
	loader_info_t *info;

	if (data == NULL)
		return;

	info = (loader_info_t *)data;

	free(info->name);
	free(info->exe);
	free(info->app_type);

	free(info);
}

void _loader_info_dispose(GList *info)
{
	g_list_free_full(info, __free_info);
}

static int __comp_app_type(gconstpointer a, gconstpointer b)
{
	loader_info_t *info = (loader_info_t *)a;

	if (info == NULL || info->app_type == NULL || b == NULL)
		return -1;

	return strcmp(info->app_type, b);
}

int _loader_info_find_type_by_app_type(GList *info,  const char *app_type)
{
	GList *cur = g_list_find_custom(info, app_type, __comp_app_type);

	if (cur == NULL)
		return -1;

	loader_info_t *cur_info = (loader_info_t *)cur->data;

	return cur_info->type;
}




