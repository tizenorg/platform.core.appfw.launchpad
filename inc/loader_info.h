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

#pragma once

#include <stdbool.h>
#include <glib.h>
#include <bundle.h>

#define METHOD_TIMEOUT		0x1
#define METHOD_VISIBILITY	0x2
#define METHOD_DEMAND		0x4

typedef struct _loader_info {
	int type;
	char *name;
	char *exe;
	char *app_type;
	int detection_method;
	int timeout_val;
	char *hw_acc;
	GList *alternative_loaders;
	bundle *extra;
} loader_info_t;

GList *_loader_info_load(const char *path);
void _loader_info_dispose(GList *info);
int _loader_info_find_type_by_app_type(GList *info,  const char *app_type);




