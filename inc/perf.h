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

#ifndef __PERF_H__
#define __PERF_H__

#ifdef PERF_ACTIVATE

#include <sys/time.h>
static struct timeval __g_base_time = {
	.tv_sec = 0,
	.tv_usec = 0
};

#define INIT_PERF(kb) \
	do { \
		const char *tmp; \
		struct timeval tv; \
		tmp = bundle_get_val(kb, AUL_K_STARTTIME); \
		if (tmp != NULL) \
			sscanf(tmp, "%ld/%ld", &tv.tv_sec, &tv.tv_usec); \
		else \
			gettimeofday(&tv, NULL); \
		__g_base_time.tv_sec = tv.tv_sec; \
		__g_base_time.tv_usec = tv.tv_usec; \
	} while (0)

#define PERF(fmt, arg...) \
	do { \
		struct timeval cur; \
		struct timeval res; \
		gettimeofday(&cur, NULL); \
		if (__g_base_time.tv_sec != 0) { \
			timersub(&cur, &__g_base_time, &res); \
			printf("%c[1;31m[%s,%d] %ld sec %ld msec "fmt \
					" %c[0m\n", 27, __func__, \
					__LINE__, res.tv_sec, \
					res.tv_usec/1000, ##arg, 27);\
		} \
	} while (0)

#else

#define INIT_PERF(kb)
#define PERF(fmt, arg...)

#endif

#endif /* __PERF_H__ */

