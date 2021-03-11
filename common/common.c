/*
 * Copyright (C) 2018-2019 Gooroom <gooroom@gooroom.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */


#include "common.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>

#include <glib.h>
#include <gio/gio.h>

#include <polkit/polkit.h>
#include <json-c/json.h>

json_object *
JSON_OBJECT_GET (json_object *obj, const gchar *key)
{
	if (!obj) return NULL;

	json_object *ret_obj = NULL;

	json_object_object_get_ex (obj, key, &ret_obj);

	return ret_obj;
}

int
get_account_type (const char *user)
{
    int account_type = ACCOUNT_TYPE_LOCAL;
    struct passwd *user_entry = getpwnam (user);

    if (!user_entry)
        return ACCOUNT_TYPE_UNKNOWN;

    char **tokens = g_strsplit (user_entry->pw_gecos, ",", -1);
    if (tokens && (g_strv_length (tokens) > 4)) {
        if (tokens[4]) {
            if (g_str_equal (tokens[4], "gooroom-account")) {
                account_type = ACCOUNT_TYPE_GOOROOM;
            } else if (g_str_equal (tokens[4], "google-account")) {
                account_type = ACCOUNT_TYPE_GOOGLE;
            } else if (g_str_equal (tokens[4], "naver-account")) {
                account_type = ACCOUNT_TYPE_NAVER;
            } else {
                account_type = ACCOUNT_TYPE_LOCAL;
            }
        }
    }

    g_strfreev (tokens);

    return account_type;
}

gboolean
is_local_user (void)
{
	gboolean ret = TRUE;

	struct passwd *user_entry = getpwnam (g_get_user_name ());
	if (user_entry) {
		gchar **tokens = g_strsplit (user_entry->pw_gecos, ",", -1);

		if (g_strv_length (tokens) > 4 ) {
			if (tokens[4] && (g_str_equal (tokens[4], "gooroom-account") ||
                              g_str_equal (tokens[4], "google-account") ||
                              g_str_equal (tokens[4], "naver-account"))) {
				ret = FALSE;
			}
		}

		g_strfreev (tokens);
	}

	return ret;
}


gboolean
is_admin_group (void)
{
	gchar *cmd;
	gchar *program;
	gchar *output;
	gboolean ret = FALSE;

	program = g_find_program_in_path ("groups");
	cmd = g_strdup_printf ("%s", program);

	if (g_spawn_command_line_sync (cmd, &output, NULL, NULL, NULL)) {
		if (output) {
			guint i = 0;
			gchar **lines = g_strsplit (output, "\n", -1);
			for (i = 0; lines[i] != NULL; i++) {
				guint j = 0;
				gchar **groups = g_strsplit (lines[i], " ", -1);
				for (j = 0; groups[j] != NULL; j++) {
					if (g_strcmp0 (groups[j], "sudo") == 0) {
						ret = TRUE;
						break;
					}
				}
				g_strfreev (groups);
			}
			g_strfreev (lines);

			g_free (output);
		}
	}

	g_free (cmd);
	g_free (program);

	return ret;
}

gboolean
authenticate (const gchar *action_id)
{
	GPermission *permission;
	permission = polkit_permission_new_sync (action_id, NULL, NULL, NULL);

	if (!g_permission_get_allowed (permission)) {
		if (g_permission_acquire (permission, NULL, NULL)) {
			return TRUE;
		}
		return FALSE;
	}

	return TRUE;
}

void
send_taking_measure_signal_to_self (void)
{
	gchar *pkexec, *cmdline;

	pkexec = g_find_program_in_path ("pkexec");
	cmdline = g_strdup_printf ("%s %s", pkexec, GOOROOM_LOGPARSER_SEEKTIME_HELPER);

	g_spawn_command_line_sync (cmdline, NULL, NULL, NULL, NULL);

	g_free (pkexec);
	g_free (cmdline);
}

void
send_taking_measures_signal_to_agent (void)
{
	GVariant   *variant;
	GDBusProxy *proxy;
	GError     *error = NULL;
	gchar      *status = NULL;

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
			G_DBUS_CALL_FLAGS_NONE,
			NULL,
			"kr.gooroom.agent",
			"/kr/gooroom/agent",
			"kr.gooroom.agent",
			NULL,
			&error);

	if (!proxy) goto done;

	const gchar *arg = "{\"module\":{\"module_name\":\"log\",\"task\":{\"task_name\":\"clear_security_alarm\",\"in\":{}}}}";

	variant = g_dbus_proxy_call_sync (proxy, "do_task",
				g_variant_new ("(s)", arg),
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (variant) g_variant_unref (variant);

	g_object_unref (proxy);

done:
	if (error)
		g_error_free (error);
}

static void
run_security_log_parser_async_done (GPid pid, gint status, gpointer data)
{
    g_spawn_close_pid (pid);
}

gboolean
run_security_log_parser_async (gchar *seektime, GIOFunc callback_func, gpointer data)
{
	GPid pid;
	gboolean ret = FALSE;
	gint stdout_fd;
	gchar *pkexec, *cmdline = NULL;
	const gchar *lang;

    pkexec = g_find_program_in_path ("pkexec");
	lang = g_getenv ("LANG");

    if (seektime)
        cmdline = g_strdup_printf ("%s %s %s %s", pkexec,
                                   GOOROOM_SECURITY_LOGPARSER_WRAPPER, seektime, lang);
    else
        cmdline = g_strdup_printf ("%s %s %s", pkexec,
                                   GOOROOM_SECURITY_LOGPARSER_WRAPPER, lang);

	gchar **arr_cmd = g_strsplit (cmdline, " ", -1);

	if (g_spawn_async_with_pipes (NULL,
                                  arr_cmd,
                                  NULL,
                                  G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD,
                                  NULL,
                                  NULL,
                                  &pid,
                                  NULL,
                                  &stdout_fd,
                                  NULL,
                                  NULL)) {

		g_child_watch_add (pid, (GChildWatchFunc)run_security_log_parser_async_done, data);

		GIOChannel *io_channel = g_io_channel_unix_new (stdout_fd);
		g_io_channel_set_flags (io_channel, G_IO_FLAG_NONBLOCK, NULL);
		g_io_channel_set_encoding (io_channel, NULL, NULL);
		g_io_channel_set_buffered (io_channel, FALSE);
		g_io_channel_set_close_on_unref (io_channel, TRUE);
		g_io_add_watch (io_channel, G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP, callback_func, data);
		g_io_channel_unref (io_channel);
		ret = TRUE;
	}

	g_strfreev (arr_cmd);

	g_free (pkexec);
	g_free (cmdline);

	return ret;
}

static gboolean
get_object_path (gchar **object_path, const gchar *service_name)
{
	GVariant   *variant;
	GDBusProxy *proxy;
	GError     *error = NULL;

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
			G_DBUS_CALL_FLAGS_NONE, NULL,
			"org.freedesktop.systemd1",
			"/org/freedesktop/systemd1",
			"org.freedesktop.systemd1.Manager",
			NULL, &error);

	if (!proxy) {
		g_error_free (error);
		return FALSE;
	}

	variant = g_dbus_proxy_call_sync (proxy, "GetUnit",
			g_variant_new ("(s)", service_name),
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (!variant) {
		g_error_free (error);
	} else {
		g_variant_get (variant, "(o)", object_path);
		g_variant_unref (variant);
	}

	g_object_unref (proxy);

	return TRUE;
}

gboolean
is_systemd_service_available (const gchar *service_name)
{
	gboolean    ret = TRUE;
	GVariant   *variant;
	GDBusProxy *proxy;
	GError     *error = NULL;

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
			G_DBUS_CALL_FLAGS_NONE, NULL,
			"org.freedesktop.systemd1",
			"/org/freedesktop/systemd1",
			"org.freedesktop.systemd1.Manager",
			NULL, &error);

	if (!proxy) {
		g_error_free (error);
		return FALSE;
	}

	variant = g_dbus_proxy_call_sync (proxy, "GetUnitFileState",
			g_variant_new ("(s)", service_name),
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (!variant) {
		g_error_free (error);
		ret = FALSE;
	}

	g_object_unref (proxy);

	return ret;
}


gboolean
is_standalone_mode (void)
{
	gboolean ret = FALSE;
	GError *error = NULL;
	GKeyFile *keyfile = NULL;
	gchar *client_name = NULL;

	keyfile = g_key_file_new ();
	g_key_file_load_from_file (keyfile, GOOROOM_MANAGEMENT_SERVER_CONF, G_KEY_FILE_KEEP_COMMENTS, &error);

	if (error == NULL) {
		if (g_key_file_has_group (keyfile, "certificate")) {
			client_name = g_key_file_get_string (keyfile, "certificate", "client_name", NULL);
		}
	} else {
		g_clear_error (&error);
	}

	ret = (client_name == NULL) ? TRUE : FALSE;

	g_key_file_free (keyfile);
	g_free (client_name);

	return ret;
}

gboolean
is_systemd_service_active (const gchar *service_name)
{
	gboolean ret = FALSE;

	GVariant   *variant;
	GDBusProxy *proxy;
	GError     *error = NULL;
	gchar      *obj_path = NULL;

	get_object_path (&obj_path, service_name);
	if (!obj_path) {
		goto done;
	}

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
			G_DBUS_CALL_FLAGS_NONE, NULL,
			"org.freedesktop.systemd1",
			obj_path,
			"org.freedesktop.DBus.Properties",
			NULL, &error);

	if (!proxy) {
		goto done;
	}

	variant = g_dbus_proxy_call_sync (proxy, "GetAll",
			g_variant_new ("(s)", "org.freedesktop.systemd1.Unit"),
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (variant) {
		gchar *output = NULL;
		GVariant *asv = g_variant_get_child_value(variant, 0);
		GVariant *value = g_variant_lookup_value(asv, "ActiveState", NULL);
		if(value && g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
			output = g_variant_dup_string(value, NULL);
			if (g_strcmp0 (output, "active") == 0) {
				ret = TRUE;;
			}
			g_free (output);
		}

		g_variant_unref (variant);
	}

	g_object_unref (proxy);

done:
	if (error)
		g_error_free (error);

	return ret;
}
