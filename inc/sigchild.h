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

#include <dbus/dbus.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <dirent.h>

#define AUL_DBUS_PATH			"/aul/dbus_handler"
#define AUL_DBUS_SIGNAL_INTERFACE	"org.tizen.aul.signal"
#define AUL_DBUS_APPDEAD_SIGNAL		"app_dead"
#define AUL_DBUS_APPLAUNCH_SIGNAL	"app_launch"

static DBusConnection *bus = NULL;
static sigset_t oldmask;

static inline void __socket_garbage_collector()
{
	DIR *dp;
	struct dirent *dentry;
	char tmp[MAX_LOCAL_BUFSZ];

	snprintf(tmp, sizeof(tmp), "/run/user/%d", getuid());
	dp = opendir(tmp);
	if (dp == NULL)
		return;

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(tmp, MAX_LOCAL_BUFSZ, "/proc/%s", dentry->d_name);
		if (access(tmp, F_OK) < 0) {	/* Flawfinder: ignore */
			snprintf(tmp, MAX_LOCAL_BUFSZ, "/run/user/%d/%s", getuid(),
				 dentry->d_name);
			unlink(tmp);
			continue;
		}
	}
	closedir(dp);
}

static inline int __send_app_dead_signal_dbus(int dead_pid)
{
	DBusMessage *message;

	// send over session dbus for other applications
	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
					  AUL_DBUS_SIGNAL_INTERFACE,
					  AUL_DBUS_APPDEAD_SIGNAL);

	if (dbus_message_append_args(message,
				     DBUS_TYPE_UINT32, &dead_pid,
				     DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_D("send_app_dead_signal_dbus done (pid=%d)\n",dead_pid);

	return 0;
}

static inline int __send_app_launch_signal_dbus(int launch_pid, const char *app_id)
{
	DBusMessage *message;

	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
					  AUL_DBUS_SIGNAL_INTERFACE,
					  AUL_DBUS_APPLAUNCH_SIGNAL);

	if (dbus_message_append_args(message,
				     DBUS_TYPE_UINT32, &launch_pid,
				     DBUS_TYPE_STRING, &app_id,
				     DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_D("send_app_launch_signal_dbus done (pid=%d)",launch_pid);

	return 0;
}

static int __sigchild_action(void *data)
{
	pid_t dead_pid;
	char buf[MAX_LOCAL_BUFSZ];

	dead_pid = (pid_t)(intptr_t)data;
	if (dead_pid <= 0)
		goto end;

	__send_app_dead_signal_dbus(dead_pid);

	snprintf(buf, MAX_LOCAL_BUFSZ, "/run/user/%d/%d", getuid(), dead_pid);
	unlink(buf);

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
	_D("dead_pid = %d pgid = %d", info->ssi_pid, child_pgid);

	while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (child_pid == child_pgid)
			killpg(child_pgid, SIGKILL);
		__sigchild_action((void *)(intptr_t)child_pid);
	}

	return;
}

static inline int __signal_init(void)
{
	int i;
	DBusError error;

	dbus_error_init(&error);
	dbus_threads_init_default();
	bus = dbus_bus_get_private(DBUS_BUS_SESSION, &error);
	if (!bus) {
		_E("Failed to connect to the D-BUS daemon: %s", error.message);
		dbus_error_free(&error);
		return -1;
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
		dbus_connection_close(bus);

#ifndef PRELOAD_ACTIVATE
	int i;
	for (i = 0; i < _NSIG; i++)
		signal(i, SIG_DFL);
#endif
	return 0;
}

