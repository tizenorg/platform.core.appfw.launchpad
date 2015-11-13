#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <bundle_internal.h>
#include <aul.h>

#include "launchpad_common.h"
#include "launchpad.h"

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

static loader_lifecycle_callback_s *__loader_callbacks;
static loader_adapter_s *__loader_adapter;
static void *__loader_user_data;
static int __argc;
static char **__argv;
static bundle *__bundle;
static char *__appid;
static char *__pkgid;
static int __loader_type = LAUNCHPAD_TYPE_UNSUPPORTED;


static void __at_exit_to_release_bundle()
{
	if (__bundle) {
		bundle_free(__bundle);
		__bundle = NULL;
	}
}

static void __release_appid_at_exit(void)
{
	if (__appid != NULL) {
		free(__appid);
	}
	if (__pkgid != NULL) {
		free(__pkgid);
	}
}

static int __candidate_process_launchpad_main_loop(app_pkt_t* pkt,
	char* out_app_path, int* out_argc, char ***out_argv, int type)
{
	bundle *kb = NULL;
	app_info_from_db *menu_info = NULL;
	const char *app_id = NULL;
	const char *app_path = NULL;
	const char *pkg_id = NULL;
	int tmp_argc = 0;
	char **tmp_argv = NULL;
	int ret = -1;

	kb = bundle_decode(pkt->data, pkt->len);
	if (!kb) {
		_E("bundle decode error");
		exit(-1);
	}

	if (__bundle != NULL)
		bundle_free(__bundle);

	__bundle = kb;
	atexit(__at_exit_to_release_bundle);

	app_id = bundle_get_val(kb, AUL_K_APPID);
	if (app_id == NULL) {
		_E("Unable to get app_id");
		exit(-1);
	}

	menu_info = _get_app_info_from_bundle_by_pkgname(app_id, kb);
	if (menu_info == NULL) {
		_D("such pkg no found");
		exit(-1);
	}

	if (type < 0) {
		_E("Invalid launchpad type: %d", type);
		exit(-1);
	}

	SECURE_LOGD("app id: %s, launchpad type: %d", app_id, type);

	app_path = _get_app_path(menu_info);
	if (app_path == NULL) {
		_E("app_path is NULL");
		exit(-1);
	}

	if (app_path[0] != '/') {
		_E("app_path is not absolute path");
		exit(-1);
	}

	_modify_bundle(kb, /*cr.pid - unused parameter*/ 0, menu_info, pkt->cmd);

	app_id = _get_pkgname(menu_info);
	if (app_id == NULL) {
		_E("unable to get app_id from menu_info");
		exit(-1);
	}
	SECURE_LOGD("app id: %s", app_id);
	__appid = strdup(app_id);
	if (__appid == NULL) {
		_E("Out of memory");
		exit(-1);
	}
	aul_set_preinit_appid(__appid);

	pkg_id = _get_pkgid(menu_info);
	if (pkg_id == NULL) {
		_E("unable to get pkg_id from menu_info");
		exit(-1);
	}
	SECURE_LOGD("pkg id: %s", pkg_id);

	__pkgid = strdup(pkg_id);
	if (__pkgid == NULL) {
		_E("Out of memory");
		exit(-1);
	}
	aul_set_preinit_pkgid(__pkgid);
	atexit(__release_appid_at_exit);

	tmp_argv = _create_argc_argv(kb, &tmp_argc);

	if (__loader_callbacks->launch) {
		ret = __loader_callbacks->launch(tmp_argc, tmp_argv, app_path, __appid, __pkgid,
						menu_info->pkg_type, __loader_user_data);
	}

	/* SET ENVIROMENT*/
	_set_env(menu_info, kb);

	if (out_app_path != NULL && out_argc != NULL && out_argv != NULL) {
		int i = 0;

		memset(out_app_path, '\0', strlen(out_app_path));
		sprintf(out_app_path, "%s", app_path);

		*out_argv = tmp_argv;
		*out_argc = tmp_argc;
		(*out_argv)[0] = out_app_path;

		for (i = 0; i < *out_argc; i++)
			SECURE_LOGD("input argument %d : %s##", i, (*out_argv)[i]);
	} else
		exit(-1);

	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);

	return ret;
}

static void __receiver_cb(int fd)
{
	_D("[candidate] ECORE_FD_READ");
	app_pkt_t* pkt = (app_pkt_t*) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (!pkt) {
		_D("[candidate] out of memory1");
		exit(-1);
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	int ret = -1;
	int recv_ret = recv(fd, pkt, AUL_SOCK_MAXBUFF, 0);

	if (recv_ret == -1) {
		_D("[condidate] recv error!");
		close(fd);
		free(pkt);
		exit(-1);
	}
	_D("[candidate] recv_ret: %d, pkt->len: %d", recv_ret, pkt->len);

	__loader_adapter->remove_fd(__loader_user_data, fd);
	ret = __candidate_process_launchpad_main_loop(pkt, __argv[0], &__argc, &__argv,
	        __loader_type);
	SECURE_LOGD("[candidate] real app argv[0]: %s, real app argc: %d", __argv[0],
	            __argc);
	close(fd);
	free(pkt);

	if (ret >= 0) {
		__loader_adapter->loop_quit(__loader_user_data);
		_D("[candidate] ecore main loop quit");
	}
}

static int __before_loop(int argc, char **argv)
{
	int client_fd;

	client_fd = _connect_to_launchpad(__loader_type);
	if (client_fd == -1) {
		_D("Connecting to candidate process was failed.");
		return -1;
	}

	if (__loader_callbacks->create) {
		__loader_callbacks->create(argc, argv, __loader_type, __loader_user_data);
		__loader_adapter->add_fd(__loader_user_data, client_fd, __receiver_cb);
		return 0;
	}

	return -1;
}

static int __after_loop(void)
{
	if (__loader_callbacks->terminate) {
		return __loader_callbacks->terminate(__argc, __argv, __loader_user_data);
	}
	return -1;
}


API int launchpad_loader_main(int argc, char **argv,
				loader_lifecycle_callback_s *callbacks, loader_adapter_s *adapter,
				void *user_data)
{
	if (argc < 2) {
		_E("too few argument.");
		return -1;
	}

	__loader_type = argv[1][0] - '0';
	if (__loader_type < 0 || __loader_type >= LAUNCHPAD_TYPE_MAX) {
		_E("invalid argument. (type: %d)", __loader_type);
		return -1;
	}

	if (callbacks == NULL) {
		_E("invalid argument. callback is null");
		return -1;
	}

	if (adapter == NULL) {
		_E("invalid argument. adapter is null");
		return -1;
	}

	if (adapter->loop_begin == NULL || adapter->loop_quit == NULL
		|| adapter->add_fd == NULL || adapter->remove_fd == NULL) {
		_E("invalid argument. adapter callback is null");
		return -1;
	}

	__loader_callbacks = callbacks;
	__loader_adapter = adapter;
	__loader_user_data = user_data;
	__argc = argc;
	__argv = argv;

	//temp - this requires some optimization.
	sleep(1);
	_D("sleeping 1 sec...");

	if (__before_loop(argc, argv) != 0)
		return -1;

	_D("[candidate] ecore main loop begin");
	__loader_adapter->loop_begin(__loader_user_data);

	return __after_loop();
}


