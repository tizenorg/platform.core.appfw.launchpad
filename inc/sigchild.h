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

#include <unistd.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <dirent.h>
#include <gio/gio.h>

#include "launchpad_common.h"

#define AUL_DBUS_PATH			"/aul/dbus_handler"
#define AUL_DBUS_SIGNAL_INTERFACE	"org.tizen.aul.signal"
#define AUL_DBUS_APPDEAD_SIGNAL		"app_dead"
#define AUL_DBUS_APPLAUNCH_SIGNAL	"app_launch"

static GDBusConnection *bus = NULL;
static sigset_t oldmask;

static inline void __socket_garbage_collector(void)
{
	DIR *dp;
	struct dirent *dentry;
	char tmp[MAX_LOCAL_BUFSZ];

	snprintf(tmp, sizeof(tmp), "/run/aul/apps/%d", getuid());
	dp = opendir(tmp);
	if (dp == NULL)
		return;

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(tmp, MAX_LOCAL_BUFSZ, "/proc/%s", dentry->d_name);
		if (access(tmp, F_OK) < 0) {	/* Flawfinder: ignore */
			_delete_sock_path(atoi(dentry->d_name), getuid());
			continue;
		}
	}
	closedir(dp);
}

static inline int __send_app_dead_signal_dbus(int dead_pid)
{
	GError *err = NULL;

	/* send over session dbus for other applications */
	if (bus == NULL) {
		bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (bus == NULL) {
			_E("Failed to connect to the D-BUS daemon: %s",
					err->message);
			g_error_free(err);
			return -1;
		}
	}

	if (g_dbus_connection_emit_signal(bus,
					NULL,
					AUL_DBUS_PATH,
					AUL_DBUS_SIGNAL_INTERFACE,
					AUL_DBUS_APPDEAD_SIGNAL,
					g_variant_new("(u)", dead_pid),
					&err) == FALSE) {
		_E("g_dbus_connection_emit_signal() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	if (g_dbus_connection_flush_sync(bus, NULL, &err) == FALSE) {
		_E("g_dbus_connection_flush_sync() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	_D("send_app_dead_signal_dbus done (pid=%d)", dead_pid);

	return 0;
}

static inline int __send_app_launch_signal_dbus(int launch_pid,
		const char *app_id)
{
	GError *err = NULL;
	GVariant *param;

	if (bus == NULL) {
		bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (bus == NULL) {
			_E("Failed to connect to the D-BUS daemon: %s",
					err->message);
			g_error_free(err);
			return -1;
		}
	}

	param = g_variant_new("(us)", launch_pid, app_id);
	if (g_dbus_connection_emit_signal(bus,
					NULL,
					AUL_DBUS_PATH,
					AUL_DBUS_SIGNAL_INTERFACE,
					AUL_DBUS_APPLAUNCH_SIGNAL,
					param,
					&err) == FALSE) {
		_E("g_dbus_connection_emit_signal() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	if (g_dbus_connection_flush_sync(bus, NULL, &err) == FALSE) {
		_E("g_dbus_connection_flush_sync() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	_D("send_app_launch_signal_dbus done (pid=%d)", launch_pid);

	return 0;
}

static int __sigchild_action(pid_t dead_pid)
{
	if (dead_pid <= 0)
		goto end;

	__send_app_dead_signal_dbus(dead_pid);

	_delete_sock_path(dead_pid, getuid());

	__socket_garbage_collector();
end:
	return 0;
}

static void __launchpad_process_sigchld(struct signalfd_siginfo *info)
{
	int status;
	pid_t child_pid;
	pid_t child_pgid;

	child_pgid = getpgid(info->ssi_pid);
	_D("dead_pid = %d pgid = %d signo = %d status = %d", info->ssi_pid,
		child_pgid, info->ssi_signo, info->ssi_status);

	while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (child_pid == child_pgid)
			killpg(child_pgid, SIGKILL);
		__sigchild_action(child_pid);
	}

	return;
}

static inline int __signal_init(void)
{
	int i;
	GError *error = NULL;

	bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!bus) {
		_E("Failed to connect to the D-BUS daemon: %s", error->message);
		g_error_free(error);
	}

	for (i = 0; i < _NSIG; i++) {
		switch (i) {
			/* controlled by sys-assert package*/
		case SIGQUIT:
		case SIGILL:
		case SIGABRT:
		case SIGBUS:
		case SIGFPE:
		case SIGSEGV:
		case SIGPIPE:
			break;
		default:
			signal(i, SIG_DFL);
			break;
		}
	}

	return 0;
}

static inline int __signal_get_sigchld_fd(void)
{
	sigset_t mask;
	int sfd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &oldmask) == -1)
		_E("failed to sigprocmask");

	sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd == -1) {
		_E("failed to create signal for SIGCHLD");
		return -1;
	}

	return sfd;
}

static inline int __signal_unblock_sigchld(void)
{
	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) {
		_E("SIG_SETMASK error");
		return -1;
	}

	_D("SIGCHLD unblocked");
	return 0;
}

static inline int __signal_fini(void)
{
	if (bus)
		g_object_unref(bus);

#ifndef PRELOAD_ACTIVATE
	int i;
	for (i = 0; i < _NSIG; i++)
		signal(i, SIG_DFL);
#endif
	return 0;
}

