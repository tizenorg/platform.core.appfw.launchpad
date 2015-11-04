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

#ifdef PREEXEC_ACTIVATE

#include <dlfcn.h>
#include <glib.h>
#define PREEXEC_FILE SHARE_PREFIX"/preexec_list.txt"

static int preexec_initialized = 0;

GSList *preexec_list = NULL;

typedef struct _preexec_list_t {
	char *pkg_type;
	char *so_path;
	int (*dl_do_pre_exe) (char *, char *);
} preexec_list_t;

static void __preexec_list_free()
{
	GSList *iter = NULL;
	preexec_list_t *type_t;

	for (iter = preexec_list; iter != NULL; iter = g_slist_next(iter)) {
		type_t = iter->data;
		if (type_t) {
			if (type_t->pkg_type)
				free(type_t->pkg_type);
			if (type_t->so_path)
				free(type_t->so_path);
			free(type_t);
		}
	}
	g_slist_free(preexec_list);
	preexec_initialized = 0;
	return;
}

static inline void __preexec_init(int argc, char **argv)
{
	void *handle = NULL;
	FILE *preexec_file;
	char *saveptr = NULL;
	char line[MAX_LOCAL_BUFSZ];
	char *type = NULL;
	char *sopath = NULL;
	char *symbol = NULL;
	int (*func) (char *, char *) = NULL;
	preexec_list_t *type_t = NULL;

	preexec_file = fopen(PREEXEC_FILE, "rt");
	if (preexec_file == NULL) {
		_E("no preexec\n");
		return;
	}

	_D("preexec start\n");

	while (fgets(line, MAX_LOCAL_BUFSZ, preexec_file) > 0) {
		/* Parse each line */
		if (line[0] == '#' || line[0] == '\0')
			continue;

		type = strtok_r(line, ":\f\n\r\t\v ", &saveptr);
		if (type == NULL)
			continue;
		sopath = strtok_r(NULL, ",\f\n\r\t\v ", &saveptr);
		if (sopath == NULL)
			continue;
		symbol = strtok_r(NULL, ",\f\n\r\t\v ", &saveptr);
		if (symbol == NULL)
			continue;

		type_t = (preexec_list_t *) calloc(1, sizeof(preexec_list_t));
		if (type_t == NULL) {
			_E("no available memory\n");
			__preexec_list_free();
			fclose(preexec_file);
			return;
		}

		handle = dlopen(sopath, RTLD_GLOBAL | RTLD_LAZY);
		if (handle == NULL) {
			free(type_t);
			continue;
		}
		_D("preexec %s %s# - handle : %x\n", type, sopath, handle);

		func = dlsym(handle, symbol);
		if (func == NULL) {
			_E("failed to get symbol type:%s path:%s\n",
			   type, sopath);
			free(type_t);
			dlclose(handle);
			handle = NULL;
			continue;
		}

		type_t->pkg_type = strdup(type);
		if (type_t->pkg_type == NULL) {
			_E("no available memory\n");
			free(type_t);
			__preexec_list_free();
			fclose(preexec_file);
			return;
		}
		type_t->so_path = strdup(sopath);
		if (type_t->so_path == NULL) {
			_E("no available memory\n");
			free(type_t->pkg_type);
			free(type_t);
			__preexec_list_free();
			fclose(preexec_file);
			return;
		}
		type_t->dl_do_pre_exe = func;

		preexec_list = g_slist_append(preexec_list, (void *)type_t);
	}

	fclose(preexec_file);
	preexec_initialized = 1;
}

static inline void __preexec_run(const char *pkg_type, const char *pkg_name,
				 const char *app_path)
{
	GSList *iter = NULL;
	preexec_list_t *type_t;

	if (!preexec_initialized || !pkg_type)
		return;

	for (iter = preexec_list; iter != NULL; iter = g_slist_next(iter)) {
		type_t = iter->data;
		if (type_t) {
			if (!strcmp(pkg_type, type_t->pkg_type)) {
				if (type_t->dl_do_pre_exe != NULL) {
					type_t->dl_do_pre_exe((char *)pkg_name,
							      (char *)app_path);
					_D("called dl_do_pre_exe() type: %s",
					   pkg_type);
				} else {
					_E("no symbol for this type: %s",
					   pkg_type);
				}
			}
		}
	}

}

#else

static void __preexec_list_free()
{
}

static inline void __preexec_init(int argc, char **argv)
{
}

static inline void __preexec_run(const char *pkg_type, const char *pkg_name,
				 const char *app_path)
{
}

#endif
