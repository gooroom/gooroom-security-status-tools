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
#include "rpd-dialog.h"
#include "calendar-popover.h"
#include "logfilter-popover.h"
#include "sysinfo-window.h"

#include <stdlib.h>
#include <sys/utsname.h> 
#include <shadow.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>


#include <config.h>

#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <gio/gio.h>

#include <json-c/json.h>

#define GRM_USER                                 ".grm-user"

#define	UPDATE_PACKAGES_CHECK_TIMEOUT			 60000
#define	AGENT_CONNECTION_STATUS_CHECK_TIMEOUT	 10000

#define GOOROOM_SECURITY_STATUS_VULNERABLE       "/var/tmp/GOOROOM-SECURITY-STATUS-VULNERABLE"
#define GOOROOM_SECURITY_LOGPARSER_NEXT_SEEKTIME "/var/tmp/GOOROOM-SECURITY-LOGPARSER-NEXT-SEEKTIME"


static struct {
	const char *tr_type;
	const char *type;
	guint level;
} LOG_DATA[] = {
	{ "DEBUG"   ,"debug"   ,LOG_LEVEL_DEBUG   },
	{ "INFO"    ,"info"    ,LOG_LEVEL_INFO    },
	{ "NOTICE"  ,"notice"  ,LOG_LEVEL_NOTICE  },
	{ "WARNING" ,"warning" ,LOG_LEVEL_WARNING },
	{ "ERR"     ,"err"     ,LOG_LEVEL_ERR     },
	{ "CRIT"    ,"crit"    ,LOG_LEVEL_CRIT    },
	{ "ALERT"   ,"alert"   ,LOG_LEVEL_ALERT   },
	{ "EMERG"   ,"emerg"   ,LOG_LEVEL_EMERG   },
	{ NULL      ,NULL      ,0                 }
};



static void     log_filter_clicked_cb        (GtkToggleButton *button, gpointer data);
static void     btn_calendar_to_clicked_cb   (GtkToggleButton *button, gpointer data);
static void     btn_calendar_from_clicked_cb (GtkToggleButton *button, gpointer data);
static void     run_iptables_command         (const char *command, SysinfoWindow *window);
static gboolean on_push_update_changed       (GtkSwitch *widget, gboolean state, gpointer data);



struct _SysinfoWindowPrivate {
	GSettings *settings;

	GtkWidget *stack;

	GtkWidget *frm_push_update;

	GtkWidget *lbl_res_ctrl;
	GtkWidget *box_res_ctrl;
	GtkWidget *btn_more;
	GtkWidget *btn_search;
	GtkWidget *btn_calendar_from;
	GtkWidget *btn_calendar_to;
	GtkWidget *trv_res_ctrl;
	GtkWidget *lbl_browser_urls;
	GtkWidget *scl_browser_urls;
	GtkWidget *trv_browser_urls;
	GtkWidget *lbl_firewall4;
	GtkWidget *lbl_firewall4_policy;
	GtkWidget *scl_firewall4;
	GtkWidget *trv_firewall4;
	GtkWidget *lbl_firewall6;
	GtkWidget *lbl_firewall6_policy;
	GtkWidget *scl_firewall6;
	GtkWidget *trv_firewall6;
	GtkWidget *trv_security_log;
	GtkWidget *lbl_sec_status;

	GtkWidget *lbl_search_date_from;
	GtkWidget *lbl_search_date_to;

	GtkWidget *lbl_device_id;
	GtkWidget *lbl_os;
	GtkWidget *lbl_server_ip;
	GtkWidget *lbl_machine_id;
	GtkWidget *lbl_conn_status;
	GtkWidget *lbl_op_mode;
	GtkWidget *lbl_port_num;
	GtkWidget *lbl_kernel_ver;

	GtkWidget *box_device_id;
	GtkWidget *box_server_ip;
	GtkWidget *box_conn_status;
	GtkWidget *box_port_num;
	GtkWidget *box_pkgs_change_blocking;

	GtkWidget *box_change_pw_cycle;
	GtkWidget *lbl_change_pw_cycle;
	GtkWidget *lbl_screen_saver_time;
	GtkWidget *lbl_pkgs_change_blocking;

	GtkWidget *chk_os;
	GtkWidget *chk_exe;
	GtkWidget *chk_boot;
	GtkWidget *chk_media;
	GtkWidget *rdo_os;
	GtkWidget *rdo_exe;
	GtkWidget *rdo_boot;
	GtkWidget *rdo_media;
	GtkWidget *chk_log_debug;
	GtkWidget *chk_log_info;
	GtkWidget *chk_log_notice;
	GtkWidget *chk_log_warning;
	GtkWidget *chk_log_err;
	GtkWidget *chk_log_crit;
	GtkWidget *chk_log_alert;
	GtkWidget *chk_log_emerg;
	GtkWidget *btn_view_log;
	GtkWidget *btn_safety_measure;
	GtkWidget *lbl_update;
	GtkWidget *swt_push_update;
	GtkWidget *btn_log_filter;

	CalendarPopover *calendar_popover;
	LogfilterPopover *logfilter_popover;

	guint agent_check_timeout_id;
	guint update_check_timeout_id;
	guint prev_log_filter;

	guint security_status;
	guint security_item_run;

	guint os_notify_level;
	guint exe_notify_level;
	guint boot_notify_level;
	guint media_notify_level;

	gint64 search_to_utime;
	gint64 search_from_utime;

	gboolean standalone_mode;

	gboolean iptable_cmd_lock;
	gboolean setting_ipv4;

	gboolean log_date_from;
};


G_DEFINE_TYPE_WITH_PRIVATE (SysinfoWindow, sysinfo_window, GTK_TYPE_APPLICATION_WINDOW)


static gint
str_compare_func (gconstpointer a, gconstpointer b)
{
	gchar *a1, *b1;
	gint ret;

	a1 = g_utf8_collate_key_for_filename ((gchar *) a, -1);
	b1 = g_utf8_collate_key_for_filename ((gchar *) b, -1);
	ret = g_strcmp0 (a1, b1);
	g_free (a1);
	g_free (b1);

	return ret;
}

static void
g_spawn_async_done_cb (GPid pid, gint status, gpointer data)
{
	g_spawn_close_pid (pid);
}

static void
iptables_command_done_cb (GPid pid, gint status, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);

	g_spawn_close_pid (pid);

	window->priv->iptable_cmd_lock = FALSE;
}

static gchar *
stripped_double_quoations (const char *str)
{
	gchar *ret = NULL;

	if (g_str_has_prefix (str, "\"") && g_str_has_suffix (str, "\"")) {
		gchar **tokens = g_strsplit (str, "\"", -1);

		if (tokens != NULL && tokens[1] != NULL) {
			ret = g_strdup (tokens[1]);
		}

		g_strfreev (tokens);
	}

	return ret;
}

static void
set_log_search_date (SysinfoWindow *window, gint year, gint month, gint day, gboolean from)
{
	gint y, m, d;
	gchar *markup = NULL;

	SysinfoWindowPrivate *priv = window->priv;

	y = (year < DEFAULT_YEAR || year > 9999) ? DEFAULT_YEAR : year;
	m = (month < 1 || month > 12) ? DEFAULT_MONTH : month;
	d = (day < 1 || day > 31) ? DEFAULT_DAY : day;

	markup = g_markup_printf_escaped ("<i>%d-%02d-%02d</i>", y, m, d);

	if (from) {
		gtk_label_set_markup (GTK_LABEL (priv->lbl_search_date_from), markup);
		GDateTime *dt = g_date_time_new_local (y, m, d, 0, 0, 0);
		gint64 utime = g_date_time_to_unix (dt);
		g_date_time_unref (dt);

		priv->search_from_utime = utime;
	} else {
		gtk_label_set_markup (GTK_LABEL (priv->lbl_search_date_to), markup);
		GDateTime *dt = g_date_time_new_local (y, m, d, 23, 59, 59);
		gint64 utime = g_date_time_to_unix (dt);
		g_date_time_unref (dt);

		priv->search_to_utime = utime;
	}

	g_free (markup);
}

static gboolean
get_log_search_date (SysinfoWindow *window, gint *year, gint *month, gint *day, gboolean from)
{
	SysinfoWindowPrivate *priv = window->priv;

	const gchar *strdate;

	if (from) {
		strdate = gtk_label_get_text (GTK_LABEL (priv->lbl_search_date_from));
	} else {
		strdate = gtk_label_get_text (GTK_LABEL (priv->lbl_search_date_to));
	}

	if (!strdate || sscanf (strdate, "%d-%02d-%02d", year, month, day) == 0) { 
		return FALSE;
	}

	return TRUE;
}

static gchar *
seek_time_get (SysinfoWindow *window)
{
	SysinfoWindowPrivate *priv = window->priv;

	gint y = DEFAULT_YEAR, m = DEFAULT_MONTH, d = DEFAULT_DAY;
	get_log_search_date (window, &y, &m, &d, TRUE);

	gchar *timestamp = g_strdup_printf ("%d%02d%02d-000000.000000", y, m, d);

	return timestamp;
}

static void
on_togglebutton_state_changed (GtkToggleButton *button, gpointer data)
{
	g_signal_handlers_block_by_func (button, on_togglebutton_state_changed, data);

	gboolean status = gtk_toggle_button_get_active (button);
	gtk_toggle_button_set_active (button, !status);

	g_signal_handlers_unblock_by_func (button, on_togglebutton_state_changed, data);
}

static void
on_security_item_changed (GtkWidget *button, gpointer data)
{
	guint level = 0;
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	if (!gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button)))
		return;

	if (button == priv->rdo_os) {
		level = priv->os_notify_level;
	} else if (button == priv->rdo_exe) {
		level = priv->exe_notify_level;
	} else if (button == priv->rdo_boot) {
		level = priv->boot_notify_level;
	} else if (button == priv->rdo_media) {
		level = priv->media_notify_level;
	} else {
		return;
	}

	GHashTable *table;
	GHashTableIter iter;
	gpointer key, value;

	table = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, NULL);
	g_hash_table_insert (table, priv->chk_log_debug, GUINT_TO_POINTER (LOG_LEVEL_DEBUG));
	g_hash_table_insert (table, priv->chk_log_info, GUINT_TO_POINTER (LOG_LEVEL_INFO));
	g_hash_table_insert (table, priv->chk_log_notice, GUINT_TO_POINTER (LOG_LEVEL_NOTICE));
	g_hash_table_insert (table, priv->chk_log_warning, GUINT_TO_POINTER (LOG_LEVEL_WARNING));
	g_hash_table_insert (table, priv->chk_log_err, GUINT_TO_POINTER (LOG_LEVEL_ERR));
	g_hash_table_insert (table, priv->chk_log_crit, GUINT_TO_POINTER (LOG_LEVEL_ALERT));
	g_hash_table_insert (table, priv->chk_log_alert, GUINT_TO_POINTER (LOG_LEVEL_CRIT));
	g_hash_table_insert (table, priv->chk_log_emerg, GUINT_TO_POINTER (LOG_LEVEL_EMERG));

	g_hash_table_iter_init (&iter, table);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		GtkToggleButton *w = GTK_TOGGLE_BUTTON (key);
		guint log_level = GPOINTER_TO_UINT (value);

		if (w) {
			g_signal_handlers_block_by_func (w, on_togglebutton_state_changed, data);
			gtk_toggle_button_set_active (w, level & log_level);
			g_signal_handlers_unblock_by_func (w, on_togglebutton_state_changed, data);
		}
	}

	g_hash_table_destroy (table);
}

static void
set_password_max_day (int maxdays, SysinfoWindow *window)
{
	gchar *text = NULL;
	SysinfoWindowPrivate *priv = window->priv;

	if (maxdays < 0 || maxdays >= 99999) {
		text = g_strdup (_("unset"));
	} else {
		if (maxdays == 0)
			text = g_strdup (_("immediately"));
		else if (maxdays == 1)
			text = g_strdup_printf ("%d %s", maxdays, _("day"));
		else
			text = g_strdup_printf ("%d %s", maxdays, _("days"));
	}

	gtk_label_set_text (GTK_LABEL (priv->lbl_change_pw_cycle), text);
	g_free (text);
}

static gboolean
parse_chage_l_cb (GIOChannel   *source,
                  GIOCondition  condition,
                  gpointer      data)
{
	gchar buff[1024] = {0, };
	gsize bytes_read;
	GString *outputs = g_string_new ("");

	while (g_io_channel_read_chars (source, buff, sizeof (buff), &bytes_read, NULL) == G_IO_STATUS_NORMAL)
		outputs = g_string_append_len (outputs, buff, bytes_read);

	guint i = 0;
	gchar **lines = g_strsplit (outputs->str, "\n", -1);
	for (i = 0; i < g_strv_length (lines); i++) {
		if (g_str_has_prefix (lines[i], "Maximum number of days between password change")) {
			gchar **tokens = g_strsplit (lines[i], ":", -1);
			if (tokens[1] != NULL) {
				int maxdays = 99999;
				maxdays = atoi (g_strstrip (tokens[1]));
				set_password_max_day (maxdays, SYSINFO_WINDOW (data));
				break;
			}
			g_strfreev (tokens);
		}
	}
	g_strfreev (lines);

	return FALSE;
}

static void
set_password_max_days_from_command (SysinfoWindow *window)
{
	GPid pid;
	gint stdout_fd;
	gchar *cmd, *cmdline;
    gchar **arr_cmd, **envp;

	cmd = g_find_program_in_path ("chage");
	cmdline = g_strdup_printf ("%s -l %s", cmd, g_get_user_name ());

	arr_cmd = g_strsplit (cmdline, " ", -1);
	envp = g_environ_setenv (envp, "LANG", "C", TRUE);

	if (g_spawn_async_with_pipes (NULL,
                                  arr_cmd,
                                  envp,
                                  G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD,
                                  NULL,
                                  NULL,
                                  &pid,
                                  NULL,
                                  &stdout_fd,
                                  NULL,
                                  NULL)) {

		g_child_watch_add (pid, (GChildWatchFunc)g_spawn_async_done_cb, NULL);

		GIOChannel *io_channel = g_io_channel_unix_new (stdout_fd);
		g_io_channel_set_flags (io_channel, G_IO_FLAG_NONBLOCK, NULL);
		g_io_channel_set_encoding (io_channel, NULL, NULL);
		g_io_channel_set_buffered (io_channel, FALSE);
		g_io_channel_set_close_on_unref (io_channel, TRUE);
		g_io_add_watch (io_channel, G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP, (GIOFunc) parse_chage_l_cb, window);
		g_io_channel_unref (io_channel);
	}

	g_free (cmd);
	g_free (cmdline);
	g_strfreev (envp);
	g_strfreev (arr_cmd);
}

static int
get_password_max_days_for_online_user (void)
{
	gint maxdays = -1;
	gchar *file = NULL;
	gchar *data = NULL;

	file = g_strdup_printf ("%s/.gooroom/%s", g_get_home_dir (), GRM_USER);

	if (!g_file_test (file, G_FILE_TEST_EXISTS)) {
		g_error ("No such file or directory : %s", file);
		goto done;
	}

	g_file_get_contents (file, &data, NULL, NULL);

	if (data) {
		enum json_tokener_error jerr = json_tokener_success;
		json_object *root_obj = json_tokener_parse_verbose (data, &jerr);
		if (jerr == json_tokener_success) {
			gboolean passwd_init = FALSE;
			json_object *obj1 = NULL, *obj2 = NULL, *obj3 = NULL;

			obj1 = JSON_OBJECT_GET (root_obj, "data");
			obj2 = JSON_OBJECT_GET (obj1, "loginInfo");
			obj3 = JSON_OBJECT_GET (obj2, "pwd_max_day");

			if (obj3) {
				maxdays = json_object_get_int (obj3);
			}
			json_object_put (root_obj);
		}
	}
	g_free (data);


done:
	g_free (file);

	return maxdays;
}

static void
open_help (GtkAccelGroup *accel, GObject *acceleratable,
           guint keyval, GdkModifierType modifier,
           gpointer user_data)
{
    gtk_show_uri_on_window (GTK_WINDOW(user_data), "help:gooroom-sysinfo",
                            gtk_get_current_event_time(), NULL);
}

static void
accel_init (SysinfoWindow *window)
{
    GtkAccelGroup *accel_group;
    guint accel_key;
    GdkModifierType accel_mod;
    GClosure *clouser;

    accel_group = gtk_accel_group_new();
    gtk_accelerator_parse ("F1", &accel_key, &accel_mod);
    clouser = g_cclosure_new_object ( G_CALLBACK(open_help), G_OBJECT(window));
    gtk_accel_group_connect (accel_group, accel_key, accel_mod, GTK_ACCEL_VISIBLE, clouser);
    gtk_window_add_accel_group (GTK_WINDOW(window), accel_group);
}

static void
done_agent_proxy_cb (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	gchar *status = NULL;
	GVariant *variant, *v;

	SysinfoWindow *window = SYSINFO_WINDOW (user_data);
	SysinfoWindowPrivate *priv = window->priv;

	GDBusProxy *proxy = G_DBUS_PROXY (source_object);

	variant = g_dbus_proxy_call_finish (proxy, res, NULL);

	if (variant) {
		g_variant_get (variant, "(v)", &v);
		gchar *data = g_variant_dup_string (v, NULL);
		g_variant_unref (v);
		g_variant_unref (variant);

		if (data) {
			enum json_tokener_error jerr = json_tokener_success;
			json_object *root_obj = json_tokener_parse_verbose (data, &jerr);

			if (jerr == json_tokener_success) {
				json_object *obj1 = NULL, *obj2 = NULL, *obj3 = NULL, *obj4 = NULL;
				obj1 = JSON_OBJECT_GET (root_obj, "module");
				obj2 = JSON_OBJECT_GET (obj1, "task");
				obj3 = JSON_OBJECT_GET (obj2, "out");
				obj4 = JSON_OBJECT_GET (obj3, "status");
				if (obj4) {
					const char *val = json_object_get_string (obj4);
					if (val && g_strcmp0 (val, "200") == 0) {
						status = g_strdup (_("Connected"));
					} else {
						status = g_strdup (_("Disconnected"));
					}
				}
				json_object_put (root_obj);
			}
		}

		g_free (data);
	}

	g_object_unref (proxy);

	gtk_label_set_text (GTK_LABEL (priv->lbl_conn_status), (status != NULL) ? status : _("Unknown"));

	g_free (status);
}

static void
got_agent_proxy_cb (GObject      *source_object,
                    GAsyncResult *res,
                    gpointer      data)
{
	GError *error = NULL;
	GDBusProxy *proxy;
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	proxy = g_dbus_proxy_new_for_bus_finish (res, &error);
	if (proxy == NULL) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning ("Error creating agent proxy: %s\n", error->message);

		gtk_label_set_text (GTK_LABEL (priv->lbl_conn_status), _("Unknown"));

		g_error_free (error);
		return;
	}

	const gchar *arg = "{\"module\":{\"module_name\":\"SERVER\",\"task\":{\"task_name\":\"grm_heartbit\",\"in\":{}}}}";

	g_dbus_proxy_call (proxy,
                       "do_task",
                       g_variant_new ("(s)", arg),
                       G_DBUS_CALL_FLAGS_NONE,
                       -1,
                       NULL,
                       done_agent_proxy_cb,
                       window);
}


static void
agent_connection_status_check (gpointer data)
{
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
                              G_DBUS_CALL_FLAGS_NONE,
                              NULL,
                              "kr.gooroom.agent",
                              "/kr/gooroom/agent",
                              "kr.gooroom.agent",
                              NULL,
                              got_agent_proxy_cb,
                              data);

//	GDBusProxy *proxy;
//	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
//			G_DBUS_CALL_FLAGS_NONE,
//			NULL,
//			"kr.gooroom.agent",
//			"/kr/gooroom/agent",
//			"kr.gooroom.agent",
//			NULL,
//			NULL);
//
//	if (!proxy) {
//		gtk_label_set_text (GTK_LABEL (priv->lbl_conn_status), _("Unknown"));
//		return;
//	}
//
//	const gchar *arg = "{\"module\":{\"module_name\":\"SERVER\",\"task\":{\"task_name\":\"grm_heartbit\",\"in\":{}}}}";
//
//	g_dbus_proxy_call (proxy,
//						"do_task",
//						g_variant_new ("(s)", arg),
//						G_DBUS_CALL_FLAGS_NONE,
//						-1,
//						NULL,
//						done_agent_proxy_cb,
//						data);
}

static gboolean
agent_connection_status_check_continually (gpointer data)
{
	agent_connection_status_check (data);

	return TRUE;
}

static gboolean
get_date (gchar *strdate, gint *yy, gint *mm, gint *dd)
{
	if (!strdate || sscanf (strdate, "%d-%d-%d", yy, mm, dd) == 0)
		return FALSE;

	return TRUE;
}

static gboolean
get_time (gchar *strtime, gint *h, gint *m, gint *s)
{
	if (!strtime || sscanf (strtime, "%d:%d:%d", h, m, s) == 0)
		return FALSE;

	return TRUE;
}

static void
show_log (GtkWidget *treeview, json_object *root_obj, gint64 search_to_utime, GList *filters)
{
	g_return_if_fail (root_obj != NULL);

	GtkTreeIter iter;
	GtkTreeModel *model;
	model = gtk_tree_view_get_model (GTK_TREE_VIEW (treeview));

	int i = 0, len = 0;
	len = json_object_array_length (root_obj);
	for (i = 0; i < len; i++) {
		json_object *obj1 = json_object_array_get_idx (root_obj, i);
		json_object *obj1_1 = JSON_OBJECT_GET (obj1, "level");
		json_object *obj1_2 = JSON_OBJECT_GET (obj1, "log");

		if (!obj1_1)
			continue;

		const gchar *str_type = json_object_get_string (obj1_1);

		if (!g_list_find_custom (filters, str_type, (GCompareFunc)g_strcmp0))
			continue;

		guint j = 0;
		gchar *display_type = NULL;
		for (j = 0; LOG_DATA[j].type != NULL; j++) {
			if (g_str_equal (str_type, LOG_DATA[j].type)) {
				display_type = g_strdup (_(LOG_DATA[j].tr_type));
				break;
			}
		}
		if (!display_type)
			display_type = g_strdup (_("Unknown"));

		gint64 utime;
		gchar *date = NULL, *time = NULL, *desc = NULL;

		if (obj1_2) {
			const char *str_log = json_object_get_string (obj1_2);

			gchar **lines = g_strsplit (str_log, " ", -1);
			GDateTime *dt = NULL;
			gint yy = 0, mm = 0, dd = 0, h = 0, m = 0, s = 0;
			if (lines[0]) {
				date = g_strdup (lines[0]);
				get_date (date, &yy, &mm, &dd);
			}
			if (lines[1]) {
				time = g_strdup (lines[1]);
				get_time (time, &h, &m, &s);
			}
			dt = g_date_time_new_local (yy, mm, dd, h, m, s);
			utime = g_date_time_to_unix (dt);

			if (lines[2] != NULL) {
				GString *cnt = g_string_new (lines[2]);

				guint j = 3;
				while (lines[j] != NULL) {
					g_string_append_printf (cnt, " %s", lines[j]);
					j++;
				}

				desc = g_strdup (cnt->str);

				g_string_free (cnt, TRUE);
			}

			g_strfreev (lines);

			g_date_time_unref (dt);
		}

		if (utime <= search_to_utime) {
			gtk_list_store_append (GTK_LIST_STORE (model), &iter);
			gtk_list_store_set (GTK_LIST_STORE (model), &iter,
					0, date,
					1, time,
					2, display_type,
					3, desc,
					4, utime,
					-1);
		}

		g_free (date);
		g_free (time);
		g_free (display_type);
		g_free (desc);
	}
}

static gboolean
update_watch_output (GIOChannel   *source,
                     GIOCondition  condition,
                     gpointer      data)
{
	gchar     buff[1024] = {0, };
	gsize     bytes_read;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	GString *outputs = g_string_new ("");

	while (g_io_channel_read_chars (source, buff, sizeof (buff), &bytes_read, NULL) == G_IO_STATUS_NORMAL) {
		outputs = g_string_append_len (outputs, buff, bytes_read);
	}

	gchar *pkgs = g_strdup ("-1");

	if (outputs->str && outputs->len > 0) {
		guint i = 0;
		gchar **lines = g_strsplit (outputs->str, "\n", -1);
		for (i = 0; lines[i] != NULL; i++) {
			if (g_str_has_prefix (lines[i], "packages=")) {
				gchar **tokens = g_strsplit (lines[i], "=", -1);
				if (tokens[1]) {
					pkgs = g_strdup (tokens[1]);
				}
				g_strfreev (tokens);
			}
		}
		g_strfreev (lines);
	}

	g_string_free (outputs, TRUE);

	if (g_strcmp0 (pkgs, "-1") == 0) {
		gtk_label_set_text (GTK_LABEL (priv->lbl_update), _("Unknown"));
	} else if (g_strcmp0 (pkgs, "0") == 0) {
		gtk_label_set_text (GTK_LABEL (priv->lbl_update), _("Latest"));
	} else {
		gchar *text = NULL;
		if (g_strcmp0 (pkgs, "1") == 0) {
			text = g_strdup_printf (_("There is %s package to update."), pkgs);
		} else {
			text = g_strdup_printf (_("There are %s packages to update."), pkgs);
		}
		gtk_label_set_text (GTK_LABEL (priv->lbl_update), text);
		g_free (text);
	}

	return FALSE;
}

static int
check_function_from_agent (SysinfoWindow *window, const gchar *task_name)
{
	GDBusProxy *proxy = NULL;

	SysinfoWindowPrivate *priv = window->priv;

	proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
			G_DBUS_CALL_FLAGS_NONE,
			NULL,
			"kr.gooroom.agent",
			"/kr/gooroom/agent",
			"kr.gooroom.agent",
			NULL,
			NULL);

	if (!proxy) return 0;

	gint ret = -1;
	gchar *result = NULL;
	GVariant *variant = NULL;
	gchar *arg = g_strdup_printf ("{\"module\":{\"module_name\":\"config\",\"task\":{\"task_name\":\"%s\",\"in\":{}}}}", task_name);

	variant = g_dbus_proxy_call_sync (proxy, "do_task",
									g_variant_new ("(s)", arg),
									G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);

	g_free (arg);

	if (variant) {
		GVariant *v = NULL;
		g_variant_get (variant, "(v)", &v);
		if (v) {
			result = g_variant_dup_string (v, NULL);
			g_variant_unref (v);
		}
		g_variant_unref (variant);
	}

	if (result) {
		enum json_tokener_error jerr = json_tokener_success;
		json_object *root_obj = json_tokener_parse_verbose (result, &jerr);

		if (jerr == json_tokener_success) {
			json_object *obj1 = NULL, *obj2 = NULL, *obj3 = NULL, *obj4 = NULL, *obj5 = NULL;
			obj1 = JSON_OBJECT_GET (root_obj, "module");
			obj2 = JSON_OBJECT_GET (obj1, "task");
			obj3 = JSON_OBJECT_GET (obj2, "out");
			obj4 = JSON_OBJECT_GET (obj3, "operation");
			obj5 = JSON_OBJECT_GET (obj3, "status");
			if (obj5) {
				const char *status = json_object_get_string (obj5);
				if (status && g_strcmp0 (status, "200") == 0) {
					const char *operation = json_object_get_string (obj4);
					if (operation && g_strcmp0 (operation, "enable") == 0) {
						ret = 1;
					}
				}
			}
			json_object_put (root_obj);
		}

		g_free (result);
	}

	g_object_unref (proxy);

	return ret;
}

static gboolean
iptables_policy_parse (GtkTreeView *treeview, const gchar *direction, const gchar *policy, gboolean ipv6)
{
	g_return_val_if_fail (policy != NULL, FALSE);

	gint argc;
	gchar **argv;
	gboolean ret = FALSE;

	if (!g_shell_parse_argv (policy, &argc, &argv, NULL))
		goto error;

	if (argc < 4)
		goto error;

	const gchar *status, *src, *dst, *prot;

	if (strstr (argv[0], "ACCEPT") != NULL) {
		status = _("ACCEPT");
	} else if (strstr (argv[0], "DROP") != NULL) {
		status = _("DROP");
	} else if (strstr (argv[0], "REJECT") != NULL) {
		status = _("REJECT");
	} else {
		goto error;
	}

	GtkTreeIter iter;
	GtkTreeModel *model = gtk_tree_view_get_model (treeview);

	/* ignore "opt" */
	prot = argv[1];
	src  = argv[3];
	dst  = argv[4];
	if (ipv6) {
		src  = argv[2];
		dst  = argv[3];
	}

	gtk_list_store_append (GTK_LIST_STORE (model), &iter);
	gtk_list_store_set (GTK_LIST_STORE (model), &iter,
			0, status,
			1, direction,
			2, src,
			3, dst,
			4, prot,
			-1);

	ret = TRUE;

error:
	g_strfreev (argv);

	return ret;
}

static gboolean
iptables_output_parse (GIOChannel   *source,
                       GIOCondition  condition,
                       gpointer      data)
{
	gchar  buff[1024] = {0, };
	gsize  bytes_read;
	gboolean visible = FALSE;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	GString *outputs = g_string_new ("");

	while (g_io_channel_read_chars (source, buff, sizeof (buff), &bytes_read, NULL) == G_IO_STATUS_NORMAL) {
		outputs = g_string_append_len (outputs, buff, bytes_read);
	}

	if (outputs->str && outputs->len > 0) {
		gint i = 0;
		gchar **lines = g_strsplit (outputs->str, "\n", -1);
		gboolean input = FALSE, output = FALSE, forward = FALSE;
		for (i = 0; lines[i] != NULL; i++) {
			if (strstr (lines[i], "Chain INPUT") != NULL) {
				input = TRUE; output = FALSE; forward = FALSE;

				gchar *markup;
				if (strstr (lines[i], "(policy ACCEPT)") != NULL) {
					markup = g_markup_printf_escaped ("<i><span foreground=\"#0000ff\">(%s)</span></i>", _("Accept"));
				} else if (strstr (lines[i], "(policy DROP)") != NULL) {
					markup = g_markup_printf_escaped ("<i><span foreground=\"#0000ff\">(%s)</span></i>", _("Drop"));
				} else {
					markup = g_markup_printf_escaped ("<i>""</i>");
				}
				if (priv->setting_ipv4) {
					gtk_label_set_markup (GTK_LABEL (priv->lbl_firewall4_policy), markup);
				} else {
					gtk_label_set_markup (GTK_LABEL (priv->lbl_firewall6_policy), markup);
				}
				g_free (markup);

				++i; // skip next line;

				continue;
			}

			if (strstr (lines[i], "Chain OUTPUT") != NULL) {
				input = FALSE; output = TRUE; forward = FALSE;
				++i; // skip next line;
				continue;
			}

			if (strstr (lines[i], "Chain FORWARD") != NULL) {
				input = FALSE; output = FALSE; forward = TRUE;
				++i; // skip next line;
				continue;
			}

			if (g_str_has_prefix (lines[i], "ACCEPT") ||
                g_str_has_prefix (lines[i], "DROP")   ||
                g_str_has_prefix (lines[i], "REJECT"))
			{
				if (input || output || forward) {
					const gchar *direction;

					if (input) direction = _("INPUT");
					else if (output) direction =  _("OUTPUT");
					else if (forward) direction =  _("FORWARD");
					else continue;

					if (priv->setting_ipv4) {
						visible = iptables_policy_parse (GTK_TREE_VIEW (priv->trv_firewall4), direction, lines[i], FALSE);
					} else {
						visible = iptables_policy_parse (GTK_TREE_VIEW (priv->trv_firewall6), direction, lines[i], TRUE);
					}
				}
			}
		}

		g_strfreev (lines);
	}

	g_string_free (outputs, TRUE);

	if (visible) {
		if (priv->setting_ipv4) {
			gtk_widget_show (priv->scl_firewall4);
			gtk_widget_hide (priv->lbl_firewall4);
		} else {
			gtk_widget_show (priv->scl_firewall6);
			gtk_widget_hide (priv->lbl_firewall6);
		}
	} else {
		gchar *markup = g_markup_printf_escaped ("<i>%s</i>", _("Could not find firewall policy."));

		if (priv->setting_ipv4) {
			gtk_widget_show (priv->lbl_firewall4);
			gtk_widget_hide (priv->scl_firewall4);
			gtk_label_set_markup (GTK_LABEL (priv->lbl_firewall4), markup);
		} else {
			gtk_widget_show (priv->lbl_firewall6);
			gtk_widget_hide (priv->scl_firewall6);
			gtk_label_set_markup (GTK_LABEL (priv->lbl_firewall6), markup);
		}

		g_free (markup);
	}

	return FALSE;
}


static void
run_iptables_command (const char *command, SysinfoWindow *window)
{
	GPid pid;
	gint stdout_fd;
	gchar **arr_cmd;
	gchar *pkexec, *cmdline = NULL;

	SysinfoWindowPrivate *priv = window->priv;

	if (g_str_equal (command, GOOROOM_IPTABLES_WRAPPER)) {
		priv->setting_ipv4 = TRUE;
	} else if (g_str_equal (command, GOOROOM_IP6TABLES_WRAPPER)) {
		priv->setting_ipv4 = FALSE;
	} else {
		goto done;
	}

	pkexec = g_find_program_in_path ("pkexec");
	cmdline = g_strdup_printf ("%s %s", pkexec, command);

	arr_cmd = g_strsplit (cmdline, " ", -1);

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
                                  NULL))
	{
		priv->iptable_cmd_lock = TRUE;

		g_child_watch_add (pid, (GChildWatchFunc)iptables_command_done_cb, window);

		GIOChannel *io_channel = g_io_channel_unix_new (stdout_fd);
		g_io_channel_set_flags (io_channel, G_IO_FLAG_NONBLOCK, NULL);
		g_io_channel_set_encoding (io_channel, NULL, NULL);
		g_io_channel_set_buffered (io_channel, FALSE);
		g_io_channel_set_close_on_unref (io_channel, TRUE);
		g_io_add_watch (io_channel, G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP, iptables_output_parse, window);
		g_io_channel_unref (io_channel);
	}
	else
	{
		goto done;
	}

	g_free (pkexec);
	g_free (cmdline);

	g_strfreev (arr_cmd);

	return;

done:
	priv->iptable_cmd_lock = FALSE;
}

static void
system_firewall_check (SysinfoWindow *window)
{
	window->priv->iptable_cmd_lock = FALSE;

	run_iptables_command (GOOROOM_IPTABLES_WRAPPER, window);

	while (window->priv->iptable_cmd_lock)
		gtk_main_iteration ();

	run_iptables_command (GOOROOM_IP6TABLES_WRAPPER, window);
}

static void
package_updating_check (gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	GPid pid;
	gint stdout_fd;
	gchar *arr_cmd[] = { GOOROOM_UPDATE_CHECKER, NULL };

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

		g_child_watch_add (pid, (GChildWatchFunc)g_spawn_async_done_cb, NULL);

		GIOChannel *io_channel = g_io_channel_unix_new (stdout_fd);
		g_io_channel_set_flags (io_channel, G_IO_FLAG_NONBLOCK, NULL);
		g_io_channel_set_encoding (io_channel, NULL, NULL);
		g_io_channel_set_buffered (io_channel, FALSE);
		g_io_channel_set_close_on_unref (io_channel, TRUE);
		g_io_add_watch (io_channel, G_IO_IN | G_IO_PRI | G_IO_ERR | G_IO_HUP, (GIOFunc) update_watch_output, window);
		g_io_channel_unref (io_channel);
	}
}

static gboolean
package_updating_check_continually (gpointer data)
{
	package_updating_check (data);

	return TRUE;
}

static guint
get_loglevel_from_string (const char *strloglevel)
{
	guint i, loglevel = 0;
	gboolean contain = FALSE;

	const struct {
		const char *type;
		guint level;
	} LOGINFO [] = {
		{ "debug"   ,LOG_LEVEL_DEBUG   },
		{ "info"    ,LOG_LEVEL_INFO    },
		{ "notice"  ,LOG_LEVEL_NOTICE  },
		{ "warning" ,LOG_LEVEL_WARNING },
		{ "err"     ,LOG_LEVEL_ERR     },
		{ "crit"    ,LOG_LEVEL_ALERT   },
		{ "alert"   ,LOG_LEVEL_CRIT    },
		{ "emerg"   ,LOG_LEVEL_EMERG   },
		{ NULL      ,0                 }
	};

	for (i = 0; LOGINFO[i].type != NULL; i++) {
		if (g_str_equal (strloglevel, LOGINFO[i].type)) {
			contain = TRUE;
		}

		if (contain) {
			loglevel |= LOGINFO[i].level;
		}
	}

	return loglevel;
}

static guint
security_item_run_get (json_object *os_obj, json_object *exe_obj, json_object *boot_obj, json_object *media_obj)
{
	guint run = 0;

	if (os_obj) {
		const char *val = json_object_get_string (os_obj);
		if (val) {
			if (g_strcmp0 (val, "run") == 0) {
				run |= SECURITY_ITEM_OS_RUN;
			}
		}
	}
	if (exe_obj) {
		const char *val = json_object_get_string (exe_obj);
		if (val) {
			if (g_strcmp0 (val, "run") == 0) {
				run |= SECURITY_ITEM_EXE_RUN;
			}
		}
	}
	if (boot_obj) {
		const char *val = json_object_get_string (boot_obj);
		if (val) {
			if (g_strcmp0 (val, "run") == 0) {
				run |= SECURITY_ITEM_BOOT_RUN;
			}
		}
	}
	if (media_obj) {
		const char *val = json_object_get_string (media_obj);
		if (val) {
			if (g_strcmp0 (val, "run") == 0) {
				run |= SECURITY_ITEM_MEDIA_RUN;
			}
		}
	}

	return run;
}

static guint
log_level_get (json_object *obj)
{
	const char *val;
	guint loglevel = 0;

	if (obj) {
		val = json_object_get_string (obj);
		loglevel = get_loglevel_from_string (val);
	}

	return loglevel;
}


static void
system_security_function_update (SysinfoWindow *window)
{
	SysinfoWindowPrivate *priv = window->priv;

	g_signal_handlers_block_by_func (priv->chk_os, on_togglebutton_state_changed, window);
	g_signal_handlers_block_by_func (priv->chk_exe, on_togglebutton_state_changed, window);
	g_signal_handlers_block_by_func (priv->chk_boot, on_togglebutton_state_changed, window);
	g_signal_handlers_block_by_func (priv->chk_media, on_togglebutton_state_changed, window);

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_os), priv->security_item_run & SECURITY_ITEM_OS_RUN);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_exe), priv->security_item_run & SECURITY_ITEM_EXE_RUN);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_boot), priv->security_item_run & SECURITY_ITEM_BOOT_RUN);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_media), priv->security_item_run & SECURITY_ITEM_MEDIA_RUN);

	g_signal_handlers_unblock_by_func (priv->chk_os, on_togglebutton_state_changed, window);
	g_signal_handlers_unblock_by_func (priv->chk_exe, on_togglebutton_state_changed, window);
	g_signal_handlers_unblock_by_func (priv->chk_boot, on_togglebutton_state_changed, window);
	g_signal_handlers_unblock_by_func (priv->chk_media, on_togglebutton_state_changed, window);

	on_security_item_changed (priv->rdo_boot, window);
}

static void
system_security_status_update (SysinfoWindow *window)
{
	gchar *markup = NULL;
	gboolean sensitive = FALSE;
	SysinfoWindowPrivate *priv = window->priv;

	if (priv->security_status == SECURITY_STATUS_SAFETY) {
		markup = g_markup_printf_escaped ("<b><i><span foreground=\"#0000ff\">%s</span></i></b>", _("Safety"));
	} else if (priv->security_status == SECURITY_STATUS_VULNERABLE) {
		markup = g_markup_printf_escaped ("<b><i><span foreground=\"#dc322f\">%s</span></i></b>", _("Vulnerable"));
		sensitive = TRUE;
	} else {
		markup = g_markup_printf_escaped ("<b><i>%s</i></b>", _("Unknown"));
	}

	if (gtk_widget_get_visible (priv->btn_safety_measure))
		gtk_widget_set_sensitive (priv->btn_safety_measure, sensitive);

	gtk_label_set_markup (GTK_LABEL (priv->lbl_sec_status), markup);
	g_free (markup);
}

static guint
last_vulnerable_get (void)
{
	guint vulnerable = 0;
	gchar *str_vulnerable = NULL;

	if (g_file_test (GOOROOM_SECURITY_STATUS_VULNERABLE, G_FILE_TEST_EXISTS)) {
		g_file_get_contents (GOOROOM_SECURITY_STATUS_VULNERABLE, &str_vulnerable, NULL, NULL);

		if (1 == sscanf (str_vulnerable, "%"G_GUINT32_FORMAT, &vulnerable)) {
			if ((vulnerable < (1 << 0)) ||
                (vulnerable >= (1 << 4))) { // 1 <= vulnerable < 16
				vulnerable = 0;
			}
		}
	}

	g_free (str_vulnerable);

	return vulnerable;
}

static gboolean
security_logparser_async_done (GIOChannel   *source,
                               GIOCondition  condition,
                               gpointer      data)
{
	gchar buff[1024] = {0, };
	gsize bytes_read;
	guint last_vulnerable = 0;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	GString *outputs = g_string_new ("");

	while (g_io_channel_read_chars (source, buff, sizeof (buff), &bytes_read, NULL) == G_IO_STATUS_NORMAL)
		outputs = g_string_append_len (outputs, buff, bytes_read);

	if (!outputs->str || outputs->len <= 0) {
		priv->security_status = SECURITY_STATUS_UNKNOWN;
		priv->security_item_run = 0;
		priv->os_notify_level = 0;
		priv->exe_notify_level = 0;
		priv->boot_notify_level = 0;
		priv->media_notify_level = 0;
		goto done;
	}

	gchar *json_output = strstr (outputs->str, "JSON-ANCHOR=");
	if (json_output) {
		gchar *json_string = json_output + strlen ("JSON-ANCHOR=");
		enum json_tokener_error jerr = json_tokener_success;
		json_object *root_obj = json_tokener_parse_verbose (json_string, &jerr);
		if (jerr == json_tokener_success) {
			json_object *summary_obj;
			json_object *os_run_obj, *exe_run_obj, *boot_run_obj, *media_run_obj;
			json_object *os_notify_level_obj, *exe_notify_level_obj, *boot_notify_level_obj, *media_notify_level_obj;

			summary_obj = JSON_OBJECT_GET (root_obj, "status_summary");
			os_run_obj = JSON_OBJECT_GET (root_obj, "os_run");
			exe_run_obj = JSON_OBJECT_GET (root_obj, "exe_run");
			boot_run_obj = JSON_OBJECT_GET (root_obj, "boot_run");
			media_run_obj = JSON_OBJECT_GET (root_obj, "media_run");
			os_notify_level_obj = JSON_OBJECT_GET (root_obj, "os_notify_level");
			exe_notify_level_obj = JSON_OBJECT_GET (root_obj, "exe_notify_level");
			boot_notify_level_obj = JSON_OBJECT_GET (root_obj, "boot_notify_level");
			media_notify_level_obj = JSON_OBJECT_GET (root_obj, "media_notify_level");

			if (summary_obj) {
				const char *val = json_object_get_string (summary_obj);
				if (val) {
					if (g_str_equal (val, "safe")) {
						priv->security_status = SECURITY_STATUS_SAFETY;
					} else if (g_str_equal (val, "vulnerable")) {
						priv->security_status = SECURITY_STATUS_VULNERABLE;
					} else {
						priv->security_status = SECURITY_STATUS_UNKNOWN;
					}
				}
			}

			priv->security_item_run = security_item_run_get (os_run_obj, exe_run_obj, boot_run_obj, media_run_obj);

			priv->os_notify_level = log_level_get (os_notify_level_obj);
			priv->exe_notify_level = log_level_get (exe_notify_level_obj);
			priv->boot_notify_level = log_level_get (boot_notify_level_obj);
			priv->media_notify_level = log_level_get (media_notify_level_obj);

			json_object_put (root_obj);
		}
	}


done:
	last_vulnerable = last_vulnerable_get ();

    if (last_vulnerable != 0)
		priv->security_status = SECURITY_STATUS_VULNERABLE;

	system_security_status_update (window);
	system_security_function_update (window);

	g_string_free (outputs, TRUE);

	return FALSE;
}

static gboolean
security_status_update_idle (gpointer data)
{
	gchar *seektime = NULL;
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	g_file_get_contents (GOOROOM_SECURITY_LOGPARSER_NEXT_SEEKTIME, &seektime, NULL, NULL);

	if (!run_security_log_parser_async (seektime, security_logparser_async_done, window)) {
		if (gtk_widget_get_visible (priv->btn_safety_measure))
			gtk_widget_set_sensitive (priv->btn_safety_measure, FALSE);

		gchar *markup = g_markup_printf_escaped ("<b><i>%s</i></b>", _("Unknown"));
		gtk_label_set_markup (GTK_LABEL (priv->lbl_sec_status), markup);
		g_free (markup);
	}

	return FALSE;
}

static void
system_basic_info_update (SysinfoWindow *window)
{
	SysinfoWindowPrivate *priv = window->priv;

	/* kernel version */
	struct utsname buf;
	uname (&buf);

	gtk_label_set_text (GTK_LABEL (priv->lbl_kernel_ver), buf.version);

	/* OS Info */
	{
		gchar *os_info = NULL;
		gchar *contents = NULL;
		g_file_get_contents ("/etc/lsb-release", &contents, NULL, NULL);
		if (contents) {
			guint i = 0;
			gchar **lines = g_strsplit (contents, "\n", -1);
			for (i = 0; lines[i] != NULL; i++) {
				if (g_str_has_prefix (lines[i], "DISTRIB_DESCRIPTION=")) {
					gchar **tokens = g_strsplit (lines[i], "=", -1);
					if (tokens[1]) {
						os_info = stripped_double_quoations (tokens[1]);
					}
					g_strfreev (tokens);
					break;
				}
			}
			g_strfreev (lines);
		}

		if (!os_info) os_info = g_strdup (_("Unknown"));

		gtk_label_set_text (GTK_LABEL (priv->lbl_os), os_info);

		g_free (os_info);
		g_free (contents);
	}


	/* product uuid */
	{
		gchar *product_uuid = NULL;
		gchar *pkexec, *cmdline, *output = NULL;

		pkexec = g_find_program_in_path ("pkexec");
		cmdline = g_strdup_printf ("%s %s", pkexec, GOOROOM_PRODUCT_UUID_HELPER);

		if (g_spawn_command_line_sync (cmdline, &output, NULL, NULL, NULL)) {
			gchar **lines = g_strsplit (output, "\n", -1);
			if (g_strv_length (lines) > 0)
				product_uuid = g_strdup (lines[0]);
			g_strfreev (lines);
		}

		g_free (output);
		g_free (pkexec);
		g_free (cmdline);

		if (product_uuid && g_strcmp0 (product_uuid, "") != 0) {
			gtk_label_set_text (GTK_LABEL (priv->lbl_machine_id), product_uuid);
			g_free (product_uuid);
		} else {
			/* Machine ID */
			gchar *net_device = NULL;
			const gchar *dirname = "/sys/class/net";

			GDir *gdir = g_dir_open (dirname, 0, NULL);
			if (gdir) {
				const gchar *entry;
				GList *l = NULL, *files = NULL;
				while ((entry = g_dir_read_name (gdir))) {
					files = g_list_insert_sorted (files, g_strdup (entry), str_compare_func);
				}
				g_dir_close (gdir);

				for (l = files; l != NULL; l = l->next) {
					gchar *entry = (gchar *)l->data;
					if (g_strcmp0 (entry, "lo") != 0) {
						net_device = g_strdup (entry);
						break;
					}
				}
				g_list_free_full (files, g_free);
			}

			if (net_device) {
				gchar *output = NULL;
				gchar *path = g_strdup_printf ("%s/%s/address", dirname, net_device);
				g_file_get_contents (path, &output, NULL, NULL);
				if (output) {
					guint i = 0;
					gchar **lines = g_strsplit (output, "\n", -1);
					for (i = 0; lines[i] != NULL; i++) {
						if (lines[i] != NULL) {
							gtk_label_set_text (GTK_LABEL (priv->lbl_machine_id), lines[i]);
							break;
						}
					}
					g_strfreev (lines);
				}
				g_free (output);
				g_free (path);
			} else {
				gtk_label_set_text (GTK_LABEL (priv->lbl_machine_id), _("Unknown"));
			}

			g_free (net_device);
		}
	}


	/* Set Operation Mode */
	{
		if (priv->standalone_mode) {
			gtk_label_set_text (GTK_LABEL (priv->lbl_op_mode), _("Standalone Mode"));
		} else {
			gtk_label_set_text (GTK_LABEL (priv->lbl_op_mode), _("Server Managed Mode"));
			/* Device ID & GOOROOM Management Server IP/PORT */
			GError *error = NULL;
			GKeyFile *keyfile = NULL;
			gchar *device_id = NULL, *ip = NULL, *port = NULL;

			keyfile = g_key_file_new ();
			g_key_file_load_from_file (keyfile, GOOROOM_MANAGEMENT_SERVER_CONF, G_KEY_FILE_KEEP_COMMENTS, &error);

			if (error == NULL) {
				if (g_key_file_has_group (keyfile, "certificate")) {
					device_id = g_key_file_get_string (keyfile, "certificate", "client_name", NULL);
				}

				if (g_key_file_has_group (keyfile, "domain")) {
					gchar *grm = g_key_file_get_string (keyfile, "domain", "grm", NULL);
					if (grm) ip = g_strdup (grm);
					port = g_strdup ("443");
					g_free (grm);
				}
			}

			if (!device_id) device_id = g_strdup (_("Unknown"));
			if (!ip) ip = g_strdup (_("Unknown"));
			if (!port) port = g_strdup (_("Unknown"));

			gtk_label_set_text (GTK_LABEL (priv->lbl_device_id), device_id);
			gtk_label_set_text (GTK_LABEL (priv->lbl_server_ip), ip);
			gtk_label_set_text (GTK_LABEL (priv->lbl_port_num), port);

			g_free (device_id);
			g_free (ip);
			g_free (port);
			g_key_file_free (keyfile);
			g_clear_error (&error);
		}
	}

	gtk_label_set_text (GTK_LABEL (priv->lbl_conn_status), _("Unknown"));

	/* Agent Connection Status */
	agent_connection_status_check (window);

	/* check update pacakges */
	package_updating_check (window);

	/* execute iptables or ip6tables command */
	system_firewall_check (window);

	priv->agent_check_timeout_id = g_timeout_add (AGENT_CONNECTION_STATUS_CHECK_TIMEOUT, (GSourceFunc) agent_connection_status_check_continually, window);
	priv->update_check_timeout_id = g_timeout_add (UPDATE_PACKAGES_CHECK_TIMEOUT, (GSourceFunc) package_updating_check_continually, window);
}

static gboolean
security_log_get (GIOChannel   *source,
                  GIOCondition  condition,
                  gpointer      data)
{
	gchar  buff[1024] = {0, };
	gsize  bytes_read;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	GString *outputs = g_string_new ("");

	while (g_io_channel_read_chars (source, buff, sizeof (buff), &bytes_read, NULL) == G_IO_STATUS_NORMAL) {
		outputs = g_string_append_len (outputs, buff, bytes_read);
	}

	if (!outputs->str || outputs->len <= 0) {
		goto done;
	}

	gchar *json_output = strstr (outputs->str, "JSON-ANCHOR=");
	if (json_output) {
		gchar *json_string = json_output + strlen ("JSON-ANCHOR=");
		enum json_tokener_error jerr = json_tokener_success;
		json_object *root_obj = json_tokener_parse_verbose (json_string, &jerr);
		if (jerr == json_tokener_success) {
			json_object *os_obj = NULL, *exe_obj = NULL, *boot_obj = NULL, *media_obj = NULL, *agent_obj = NULL;
			json_object_object_get_ex (root_obj, "os_log", &os_obj);
			json_object_object_get_ex (root_obj, "exe_log", &exe_obj);
			json_object_object_get_ex (root_obj, "boot_log", &boot_obj);
			json_object_object_get_ex (root_obj, "media_log", &media_obj);
			json_object_object_get_ex (root_obj, "agent_log", &agent_obj);

			GtkTreeModel *model = gtk_tree_view_get_model (GTK_TREE_VIEW (priv->trv_security_log));
			gtk_list_store_clear (GTK_LIST_STORE (model));

			guint i = 0;
			GList *filters = NULL;
			guint log_filter = 0;
			if (priv->settings)
				log_filter = g_settings_get_uint (priv->settings, "log-filter");

			for (i = 0; LOG_DATA[i].level != 0; i++) {
				if (log_filter & LOG_DATA[i].level) {
					filters = g_list_append (filters, g_strdup (LOG_DATA[i].type));
				}
			}

			show_log (priv->trv_security_log, os_obj, priv->search_to_utime, filters);
			show_log (priv->trv_security_log, exe_obj, priv->search_to_utime, filters);
			show_log (priv->trv_security_log, boot_obj, priv->search_to_utime, filters);
			show_log (priv->trv_security_log, media_obj, priv->search_to_utime, filters);
			show_log (priv->trv_security_log, agent_obj, priv->search_to_utime, filters);

			g_list_free_full (filters, g_free);

			json_object_put (root_obj);
		}
	}

done:
	g_string_free (outputs, TRUE);

	gtk_widget_set_sensitive (GTK_WIDGET (priv->btn_search), TRUE);
	gdk_window_set_cursor (gtk_widget_get_window (GTK_WIDGET (window)), NULL);

	return FALSE;
}

static void
system_security_log_update (SysinfoWindow *window)
{
	SysinfoWindowPrivate *priv = window->priv;

	GdkDisplay *display = gtk_widget_get_display (GTK_WIDGET (window));
	GdkCursor *cursor   = gdk_cursor_new_for_display (display, GDK_WATCH);

	gdk_window_set_cursor (gtk_widget_get_window (GTK_WIDGET (window)), cursor);

	gtk_widget_set_sensitive (GTK_WIDGET (priv->btn_search), FALSE);

	gchar *seektime = seek_time_get (window);
	if (!run_security_log_parser_async (seektime, security_log_get, window)) {
		gtk_widget_set_sensitive (GTK_WIDGET (priv->btn_search), TRUE);
		gdk_window_set_cursor (gtk_widget_get_window (GTK_WIDGET (window)), NULL);
	}
	g_free (seektime);
}

static void
system_device_security_update (SysinfoWindow *window)
{
	SysinfoWindowPrivate *priv = window->priv;

	gchar *text = NULL;

	int account_type = get_account_type (g_get_user_name ());

	if (account_type == ACCOUNT_TYPE_GOOROOM) {
		int maxdays = get_password_max_days_for_online_user ();
		set_password_max_day (maxdays, window);
	} else if (account_type == ACCOUNT_TYPE_LOCAL) {
		set_password_max_days_from_command (window);
	} else if (account_type == ACCOUNT_TYPE_GOOGLE ||
               account_type == ACCOUNT_TYPE_NAVER) {
		gtk_widget_hide (priv->box_change_pw_cycle);
	} else {
	}

	/* get screensaver time */
	GSettings *settings = NULL;
    GSettingsSchema *schema = NULL;

	schema = g_settings_schema_source_lookup (g_settings_schema_source_get_default (), "org.gnome.desktop.session", TRUE);
	if (schema) {
		settings = g_settings_new_full (schema, NULL, NULL);
		g_settings_schema_unref (schema);
	}

	if (settings) {
		guint val = g_settings_get_uint (settings, "idle-delay");

		if (val == 0) {
			text = g_strdup (_("unset"));
		} else if (val == 60) {
			text = g_strdup_printf ("1 %s",  _("minute"));
		} else {
			text = g_strdup_printf ("%u %s", val/60, _("minutes"));
		}

		gtk_label_set_text (GTK_LABEL (priv->lbl_screen_saver_time), text);
		g_free (text);
	}

	/* check function to stop changing packages */
	gint ret = check_function_from_agent (window, "tell_update_operation");
	if (ret == 1) {
		gtk_label_set_text (GTK_LABEL (priv->lbl_pkgs_change_blocking), _("Enabled"));
	} else if (ret == -1) {
		gtk_label_set_text (GTK_LABEL (priv->lbl_pkgs_change_blocking), _("Disabled"));
	} else {
		gtk_label_set_text (GTK_LABEL (priv->lbl_pkgs_change_blocking), _("Unknown"));
	}
}

static void
system_browser_policy_update (SysinfoWindow *window)
{
	gchar *file = NULL;
	gchar *data = NULL;
	gboolean ret = FALSE;

	SysinfoWindowPrivate *priv = window->priv;

	file = g_strdup_printf ("/usr/share/gooroom/browser/policies/mainpref.json");

	if (!g_file_test (file, G_FILE_TEST_EXISTS)) {
		goto error;
	}

	g_file_get_contents (file, &data, NULL, NULL);

	if (!data) {
		goto error;
	}

	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (data, &jerr);
	if (jerr != json_tokener_success) {
		goto error;
	}

	json_object *obj1 = JSON_OBJECT_GET (root_obj, "gooroom");
	json_object *obj2 = JSON_OBJECT_GET (obj1, "policy");
	json_object *obj2_1 = JSON_OBJECT_GET (obj2, "whitelist");
	if (obj2_1) {
		GtkTreeIter iter;
		GtkTreeModel *model;
		model = gtk_tree_view_get_model (GTK_TREE_VIEW (priv->trv_browser_urls));

		int i = 0, len = 0;
		len = json_object_array_length (obj2_1);
		for (i = 0; i < len; i++) {
			json_object *t_url_obj = json_object_array_get_idx (obj2_1, i);
			const char *url = json_object_get_string (t_url_obj);

			gtk_list_store_append (GTK_LIST_STORE (model), &iter);
			gtk_list_store_set (GTK_LIST_STORE (model), &iter,
					0, url,
					-1);
		}

		ret = TRUE;
	}
	json_object_put (root_obj);

error:
	g_free (data);
	g_free (file);

	if (!ret) {
		gtk_widget_show (priv->lbl_browser_urls);
		gtk_widget_hide (priv->scl_browser_urls);

		gchar *markup = g_markup_printf_escaped ("<i>%s</i>", _("Could not find trusted urls information."));
		gtk_label_set_markup (GTK_LABEL (priv->lbl_browser_urls), markup);
		g_free (markup);
	}
}

static void
create_item (SysinfoWindow *window, char *key, const char *val)
{
	GtkTreeIter iter;
	GtkTreeModel *model;

	SysinfoWindowPrivate *priv = window->priv;

	model = gtk_tree_view_get_model (GTK_TREE_VIEW (priv->trv_res_ctrl));
	gtk_tree_store_append (GTK_TREE_STORE (model), &iter, NULL);

	if (val) {
		const gchar *tr_state;
		if (g_strcmp0 (val, "read_only") == 0) {
			tr_state = _("ReadOnly");
		} else if ((g_strcmp0 (val, "allow") == 0) || (g_strcmp0 (val, "accept") == 0)) {
			tr_state = _("Allow");
		} else if (g_strcmp0 (val, "disallow") == 0) {
			tr_state = _("Disallow");
		} else {
			tr_state = _("Unknown");
		}

		gtk_tree_store_set (GTK_TREE_STORE (model), &iter,
                            0, _(key),
                            1, _(tr_state),
                            2, key,
                            3, FALSE,
                            -1);
	}
}

static void
create_item_with_whitelist (SysinfoWindow *window, char *key, json_object *val, const char *wlname)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gboolean allow = FALSE, more = TRUE;
	const gchar *state_val;
	json_object *obj1 = NULL, *obj2 = NULL;

	SysinfoWindowPrivate *priv = window->priv;

	model = gtk_tree_view_get_model (GTK_TREE_VIEW (priv->trv_res_ctrl));
	gtk_tree_store_append (GTK_TREE_STORE (model), &iter, NULL);

	obj1 = JSON_OBJECT_GET (val, "state");
	if (wlname)
		obj2 = JSON_OBJECT_GET (val, wlname);

	state_val = (obj1) ? json_object_get_string (obj1) : NULL;

	if (state_val) {
		const gchar *tr_state;
		if (g_strcmp0 (state_val, "read_only") == 0) {
			tr_state = _("ReadOnly");
		} else if ((g_strcmp0 (state_val, "allow") == 0) || (g_strcmp0 (state_val, "accept") == 0)) {
			tr_state = _("Allow");
			allow = TRUE;
		} else if (g_strcmp0 (state_val, "disallow") == 0) {
			tr_state = _("Disallow");
		} else {
			tr_state = _("Unknown");
		}

		if (g_str_equal (key, "network") && obj2) {
			more = TRUE;
		} else if (g_str_equal (key, "usb_network") && obj2 && !allow) {
			more = TRUE;
		} else {
			more = FALSE;
		}

		gtk_tree_store_set (GTK_TREE_STORE (model), &iter,
                            0, _(key),
                            1, _(tr_state),
                            2, key,
                            3, more,
                            -1);
	}

	if (obj2 && !allow && !more) {
		guint i, len;
		const char *device;
		GtkTreeIter child_iter;
		len = json_object_array_length (obj2);
		for (i = 0; i < len; i++) {
			json_object *serial_obj = json_object_array_get_idx (obj2, i);
			device = json_object_get_string (serial_obj);

			gtk_tree_store_append (GTK_TREE_STORE (model), &child_iter, &iter);
			gtk_tree_store_set (GTK_TREE_STORE (model), &child_iter,
                                0, device,
                                1, _("Allow"),
                                2, device,
                                3, FALSE,
                                -1);
		}
	}
}

static void
system_resource_control_update (SysinfoWindow *window)
{
	SysinfoWindowPrivate *priv = window->priv;

	gboolean ret = FALSE;
	gchar *grac_rules = NULL, *data = NULL, *output = NULL;

	if (g_spawn_command_line_sync (GOOROOM_WHICH_GRAC_RULE, &output, NULL, NULL, NULL)) {
		gchar **lines = g_strsplit (output, "\n", -1);
		if (g_strv_length (lines) > 0)
			grac_rules = g_strdup (lines[0]);
		g_strfreev (lines);
	}

	if (grac_rules && g_file_test (grac_rules, G_FILE_TEST_EXISTS))
		g_file_get_contents (grac_rules, &data, NULL, NULL);

	g_free (output);
	g_free (grac_rules);

	if (!data) goto error;

	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (data, &jerr);
	if (jerr != json_tokener_success) {
		goto error;
	}

	json_object_object_foreach (root_obj, key, val) {
		enum json_type type = json_object_get_type (val);
		if (type == json_type_string) {
			const char *value = json_object_get_string ((json_object *)val);
			create_item (window, key, value);
		} else {
			if (g_str_equal (key, "usb_memory") ) {
				create_item_with_whitelist (window, key, val, "usb_serialno");
			} else if (g_str_equal (key, "usb_network") ) {
				create_item_with_whitelist (window, key, val, "whitelist");
			} else if (g_str_equal (key, "network") ) {
				create_item_with_whitelist (window, key, val, "rules");
			} else if (g_str_equal (key, "bluetooth")) {
				create_item_with_whitelist (window, key, val, "mac_address");
			} else {
			}
		}
	}
	ret = TRUE;
	json_object_put (root_obj);

error:
	g_free (data);

	if (!ret) {
		gtk_widget_show (priv->lbl_res_ctrl);
		gtk_widget_hide (priv->box_res_ctrl);

		gchar *markup = g_markup_printf_escaped ("<i>%s</i>", _("Could not find information."));
		gtk_label_set_markup (GTK_LABEL (priv->lbl_res_ctrl), markup);
		g_free (markup);
	}
}

static void
system_push_update_update (gpointer data)
{
	gboolean allow_push_update = FALSE;
	gboolean sensitive_swt_push_update = TRUE;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	gint ret = check_function_from_agent (window, "get_package_operation");

	if (ret == -1) {
		allow_push_update = FALSE;
	} else if (ret == 1) {
		allow_push_update = TRUE;
	} else {
		sensitive_swt_push_update = FALSE;
	}

	g_signal_handlers_block_by_func (priv->swt_push_update, on_push_update_changed, window);
	gtk_switch_set_active (GTK_SWITCH (priv->swt_push_update), allow_push_update);
	g_signal_handlers_unblock_by_func (priv->swt_push_update, on_push_update_changed, window);

	gtk_widget_set_sensitive (priv->swt_push_update, sensitive_swt_push_update);
}

static gboolean
system_push_update_set_cb (gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	system_push_update_update (window);

	gtk_widget_set_sensitive (priv->swt_push_update, TRUE);

	return FALSE;
}

static gboolean
system_push_update_allow_or_deny (gpointer data)
{
	gint response;
	GtkWidget *dlg;
	const gchar *message;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	gboolean active = gtk_switch_get_active (GTK_SWITCH (priv->swt_push_update));

	if (!authenticate ("kr.gooroom.security.status.tools.set-push-update")) {
		g_signal_handlers_block_by_func (priv->swt_push_update, on_push_update_changed, window);
		gtk_switch_set_active (GTK_SWITCH (priv->swt_push_update), !active);
		g_signal_handlers_unblock_by_func (priv->swt_push_update, on_push_update_changed, window);
		return FALSE;
	}

	message = (active) ? _("Do you want to allow push update?") : _("Do you want to deny push update?");

	dlg = gtk_message_dialog_new (GTK_WINDOW (window),
			GTK_DIALOG_MODAL,
			GTK_MESSAGE_QUESTION,
			GTK_BUTTONS_NONE,
			NULL);

	gtk_message_dialog_format_secondary_markup (GTK_MESSAGE_DIALOG (dlg), "%s", message);

	gtk_dialog_add_buttons (GTK_DIALOG (dlg),
			_("_Yes"), GTK_RESPONSE_YES,
			_("_No"), GTK_RESPONSE_NO,
			NULL);

	gtk_window_set_title (GTK_WINDOW (dlg), _("Push Update Settings"));

	response = gtk_dialog_run (GTK_DIALOG (dlg));
	gtk_widget_destroy (dlg);

	if (response == GTK_RESPONSE_YES) {
		gtk_widget_set_sensitive (priv->swt_push_update, FALSE);

		GVariant   *variant;
		GDBusProxy *proxy;

		proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
				G_DBUS_CALL_FLAGS_NONE,
				NULL,
				"kr.gooroom.agent",
				"/kr/gooroom/agent",
				"kr.gooroom.agent",
				NULL,
				NULL);

		if (proxy) {
			const gchar *op = active ? "enable" : "disable";
			const gchar *json = "{\"module\":{\"module_name\":\"config\",\"task\":{\"task_name\":\"set_package_operation\",\"in\":{\"operation\":\"%s\"}}}}";

			gchar *arg = g_strdup_printf (json, op);

			variant = g_dbus_proxy_call_sync (proxy, "do_task",
					g_variant_new ("(s)", arg),
					G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);

			g_free (arg);

			if (variant) {
				g_variant_unref (variant);
			}
		}
	}

	g_idle_add ((GSourceFunc) system_push_update_set_cb, window);

	return FALSE;
}

static gboolean
on_push_update_changed (GtkSwitch *widget, gboolean state, gpointer data)
{
	g_idle_add ((GSourceFunc) system_push_update_allow_or_deny, data);

	return FALSE;
}

static gboolean
update_ui (gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	security_status_update_idle (window);

	system_basic_info_update (window);
	system_device_security_update (window);

	system_push_update_update (window);
	system_resource_control_update (window);
	system_browser_policy_update (window);

	system_security_log_update (window);

	return FALSE;
}

static void
on_view_log_button_clicked (GtkButton *button, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	gtk_stack_set_visible_child_name (GTK_STACK (priv->stack), "log-page");
}

static void
treeview_cursor_changed_cb (GtkTreeView       *tree_view,
                            gpointer           data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gboolean selected;
	gboolean sensitive = FALSE;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	selected = gtk_tree_selection_get_selected (gtk_tree_view_get_selection (tree_view), &model, &iter);
	if (selected) {
		gboolean more = FALSE;
		gtk_tree_model_get (model, &iter, 3, &more, -1);
		sensitive = more;
	}

	gtk_widget_set_sensitive (priv->btn_more, sensitive);
}

static void
treeview_row_activated_cb (GtkTreeView       *tree_view,
                           GtkTreePath       *path,
                           GtkTreeViewColumn *column,
                           gpointer           data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	gboolean selected;
	gchar *key = NULL;
	gboolean more = FALSE;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	selected = gtk_tree_selection_get_selected (gtk_tree_view_get_selection (tree_view), &model, &iter);

	if (selected) {
		gtk_tree_model_get (model, &iter,
                            2, &key,
                            3, &more,
                            -1);

		if (!more) return;

		RPDDialog *dlg = rpd_dialog_new (GTK_WIDGET (window), key);
		gtk_dialog_run (GTK_DIALOG (dlg));
		gtk_widget_destroy (GTK_WIDGET (dlg));
	}
}

static gboolean
update_security_log (gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);

	system_security_log_update (window);

	return FALSE;
}

static void
show_log_search_period_error_dialog (GtkWindow *parent)
{
	GtkWidget *dlg = gtk_message_dialog_new (parent,
			GTK_DIALOG_MODAL,
			GTK_MESSAGE_ERROR,
			GTK_BUTTONS_CLOSE,
			NULL);

	const gchar *message =  _("Please make sure to check log search period.");
	gtk_message_dialog_format_secondary_markup (GTK_MESSAGE_DIALOG (dlg), "%s", message);

	gtk_window_set_title (GTK_WINDOW (dlg), _("Log Search Period Settings"));
	gtk_dialog_run (GTK_DIALOG (dlg));
	gtk_widget_destroy (dlg);
}

static void
last_vulnerable_update (guint vulnerable)
{
	gchar *pkexec = NULL, *cmd = NULL;

	pkexec = g_find_program_in_path ("pkexec");
	cmd = g_strdup_printf ("%s %s %u", pkexec, GOOROOM_SECURITY_STATUS_VULNERABLE_HELPER, vulnerable);

	g_spawn_command_line_sync (cmd, NULL, NULL, NULL, NULL);
}

static void
btn_search_clicked_cb (GtkButton *button, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	if (priv->search_from_utime > priv->search_to_utime) {
		show_log_search_period_error_dialog (GTK_WINDOW (window));
		return;
	}

	g_timeout_add (100, (GSourceFunc) update_security_log, data);
}

static void
btn_more_clicked_cb (GtkButton *button, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	treeview_row_activated_cb (GTK_TREE_VIEW (priv->trv_res_ctrl), NULL, NULL, data);

	send_taking_measure_signal_to_self ();
}

static void
on_safety_measure_button_clicked (GtkButton *button, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	gtk_widget_set_sensitive (priv->btn_safety_measure, FALSE);

	if (is_systemd_service_active (GOOROOM_AGENT_SERVICE_NAME)) {
		send_taking_measures_signal_to_agent ();
	} else {
		send_taking_measure_signal_to_self ();
	}

	last_vulnerable_update (0);
}

static void
on_calendar_popover_closed_cb (GtkPopover *popover, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	g_signal_handlers_block_by_func (priv->btn_calendar_from, btn_calendar_from_clicked_cb, window);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->btn_calendar_from), FALSE);
	g_signal_handlers_unblock_by_func (priv->btn_calendar_from, btn_calendar_from_clicked_cb, window);

	g_signal_handlers_block_by_func (priv->btn_calendar_to, btn_calendar_to_clicked_cb, window);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->btn_calendar_to), FALSE);
	g_signal_handlers_unblock_by_func (priv->btn_calendar_to, btn_calendar_to_clicked_cb, window);

	if (!priv->calendar_popover)
		return;

	gint new_y = DEFAULT_YEAR, new_m = DEFAULT_MONTH, new_d = DEFAULT_DAY;
	calendar_popover_get_date (priv->calendar_popover, &new_y, &new_m, &new_d);

	gtk_widget_destroy (GTK_WIDGET (priv->calendar_popover));
	priv->calendar_popover = NULL;

	GDateTime *dt = g_date_time_new_local (new_y, new_m, new_d, 0, 0, 0);
	gint64 new_utime = g_date_time_to_unix (dt);
	g_date_time_unref (dt);

	if (priv->log_date_from) {
		set_log_search_date (window, new_y, new_m, new_d, priv->log_date_from);
		if (new_utime > priv->search_to_utime)
			return;
	}

	if (priv->search_from_utime > new_utime) {
		show_log_search_period_error_dialog (GTK_WINDOW (window));
		return;
	}

	set_log_search_date (window, new_y, new_m, new_d, priv->log_date_from);

	g_timeout_add (100, (GSourceFunc) update_security_log, data);
}

static void
popover_calendar (GtkToggleButton *button, gpointer data)
{
	GtkWidget *calendar;
	gint y = DEFAULT_YEAR, m = DEFAULT_MONTH, d = DEFAULT_DAY;

	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	if (!gtk_toggle_button_get_active (button))
		return;

	priv->calendar_popover = calendar_popover_new ();

	gtk_popover_set_relative_to (GTK_POPOVER (priv->calendar_popover), GTK_WIDGET (button));
	gtk_popover_set_modal (GTK_POPOVER (priv->calendar_popover), TRUE);
	gtk_popover_set_position (GTK_POPOVER (priv->calendar_popover), GTK_POS_BOTTOM);

	get_log_search_date (window, &y, &m, &d, priv->log_date_from);

	calendar_popover_set_date (priv->calendar_popover, y, m, d);

	g_signal_connect (G_OBJECT (priv->calendar_popover), "closed",
                      G_CALLBACK (on_calendar_popover_closed_cb), window);

	gtk_popover_popup (GTK_POPOVER (priv->calendar_popover));
}

static void
logfilter_popover_closed_cb (GtkPopover *popover, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	g_signal_handlers_block_by_func (priv->btn_log_filter, log_filter_clicked_cb, window);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->btn_log_filter), FALSE);
	g_signal_handlers_unblock_by_func (priv->btn_log_filter, log_filter_clicked_cb, window);

	if (!priv->logfilter_popover)
		return;

	guint new_log_filter = logfilter_popover_get_logfilter (priv->logfilter_popover);

	gtk_widget_destroy (GTK_WIDGET (priv->logfilter_popover));
	priv->logfilter_popover = NULL;

	if (priv->settings)
		g_settings_set_uint (priv->settings, "log-filter", new_log_filter);

	if (priv->prev_log_filter != new_log_filter)
		g_timeout_add (100, (GSourceFunc) update_security_log, data);
}

static void
log_filter_clicked_cb (GtkToggleButton *button, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	if (!gtk_toggle_button_get_active (button))
		return;

	priv->logfilter_popover = logfilter_popover_new ();

	gtk_popover_set_relative_to (GTK_POPOVER (priv->logfilter_popover), GTK_WIDGET (button));
	gtk_popover_set_modal (GTK_POPOVER (priv->logfilter_popover), TRUE);
	gtk_popover_set_position (GTK_POPOVER (priv->logfilter_popover), GTK_POS_BOTTOM);

	guint cur_log_filter = 0;
	if (priv->settings)
		cur_log_filter = g_settings_get_uint (priv->settings, "log-filter");
	priv->prev_log_filter = cur_log_filter;

	logfilter_popover_set_logfilter (priv->logfilter_popover, cur_log_filter);

	g_signal_connect (G_OBJECT (priv->logfilter_popover), "closed",
                      G_CALLBACK (logfilter_popover_closed_cb), window);

	gtk_popover_popup (GTK_POPOVER (priv->logfilter_popover));
}

static void
btn_calendar_from_clicked_cb (GtkToggleButton *button, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);

	window->priv->log_date_from = TRUE;

	popover_calendar (button, data);
}

static void
btn_calendar_to_clicked_cb (GtkToggleButton *button, gpointer data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);

	window->priv->log_date_from = FALSE;

	popover_calendar (button, data);
}


static void
on_stack_visible_child_notify_cb (GObject    *object,
                                  GParamSpec *pspec,
                                  gpointer    data)
{
	const gchar *name = gtk_stack_get_visible_child_name (GTK_STACK (object));

	if (g_str_equal (name, "log-page"))
		g_timeout_add (100, (GSourceFunc) update_security_log, data);
}

static void
file_status_changed_cb (GFileMonitor      *monitor,
                        GFile             *file,
                        GFile             *other_file,
                        GFileMonitorEvent  event_type,
                        gpointer           data)
{
	SysinfoWindow *window = SYSINFO_WINDOW (data);
	SysinfoWindowPrivate *priv = window->priv;

	switch (event_type)
	{
		case G_FILE_MONITOR_EVENT_CHANGED:
		case G_FILE_MONITOR_EVENT_DELETED:
		case G_FILE_MONITOR_EVENT_CREATED:
		{
			g_timeout_add (100, (GSourceFunc) security_status_update_idle, window);
			break;
		}

		default:
			break;
	}
}

static void
sysinfo_window_init (SysinfoWindow *self)
{
	GError *error = NULL;
	gchar  *markup = NULL;
	GSettingsSchema *schema = NULL;
	GFile *file;
	GFileMonitor *monitor;

	SysinfoWindowPrivate *priv;

	priv = self->priv = sysinfo_window_get_instance_private (self);

	gtk_widget_init_template (GTK_WIDGET (self));

	priv->security_item_run = 0;
	priv->os_notify_level = 0;
	priv->exe_notify_level = 0;
	priv->boot_notify_level = 0;
	priv->media_notify_level = 0;
	priv->security_status = SECURITY_STATUS_UNKNOWN;
	priv->standalone_mode = TRUE;
	priv->agent_check_timeout_id = 0;
	priv->update_check_timeout_id = 0;
	priv->prev_log_filter = 0;
    priv->settings = NULL;

	schema = g_settings_schema_source_lookup (g_settings_schema_source_get_default (),
                                              "apps.gooroom-security-status-view", TRUE);
	if (schema) {
		priv->settings = g_settings_new_full (schema, NULL, NULL);
		g_settings_schema_unref (schema);
	}

	file = g_file_new_for_path (GOOROOM_SECURITY_STATUS_VULNERABLE);

	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, &error);
	if (error) {
		g_error_free (error);
	} else {
		g_signal_connect (monitor, "changed", G_CALLBACK (file_status_changed_cb), self);
	}
	g_object_unref (file);

	g_signal_connect (G_OBJECT (priv->btn_view_log), "clicked",
                      G_CALLBACK (on_view_log_button_clicked), self);
	g_signal_connect (G_OBJECT (priv->swt_push_update), "state-set",
                      G_CALLBACK (on_push_update_changed), self);

	priv->standalone_mode = is_standalone_mode ();
	if (priv->standalone_mode) {
		gtk_widget_hide (priv->box_device_id);
		gtk_widget_hide (priv->box_conn_status);
		gtk_widget_hide (priv->box_server_ip);
		gtk_widget_hide (priv->box_port_num);
		gtk_widget_show (priv->box_pkgs_change_blocking);

		gtk_widget_hide (priv->frm_push_update);
	}

	if (is_admin_group () && is_local_user ()) {
		gtk_widget_set_sensitive (priv->btn_safety_measure, FALSE);
		g_signal_connect (G_OBJECT (priv->btn_safety_measure), "clicked",
						G_CALLBACK (on_safety_measure_button_clicked), self);
	} else {
		gtk_widget_hide (priv->btn_safety_measure);
	}

	gtk_widget_set_sensitive (priv->btn_more, FALSE);

	/* set default date for searching log */
    gint year, month, day;
    GDateTime *dt = g_date_time_new_now_local ();
    g_date_time_get_ymd (dt, &year, &month, &day);
    g_date_time_unref (dt);

	set_log_search_date (self, year, month, day, TRUE);
	set_log_search_date (self, year, month, day, FALSE);

    accel_init (self);

	GtkTreeModel *model = gtk_tree_view_get_model (GTK_TREE_VIEW (priv->trv_security_log));
	gtk_tree_sortable_set_sort_column_id (GTK_TREE_SORTABLE (GTK_LIST_STORE (model)), 4, GTK_SORT_DESCENDING);

	g_signal_connect (G_OBJECT (priv->stack), "notify::visible-child", G_CALLBACK (on_stack_visible_child_notify_cb), self);

	g_signal_connect (G_OBJECT (priv->chk_os), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_exe), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_boot), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_media), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);

	g_signal_connect (G_OBJECT (priv->chk_log_debug), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_log_info), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_log_notice), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_log_warning), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_log_err), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_log_crit), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_log_alert), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);
	g_signal_connect (G_OBJECT (priv->chk_log_emerg), "toggled", G_CALLBACK (on_togglebutton_state_changed), self);

	g_signal_connect (G_OBJECT (priv->rdo_os), "toggled", G_CALLBACK (on_security_item_changed), self);
	g_signal_connect (G_OBJECT (priv->rdo_exe), "toggled", G_CALLBACK (on_security_item_changed), self);
	g_signal_connect (G_OBJECT (priv->rdo_boot), "toggled", G_CALLBACK (on_security_item_changed), self);
	g_signal_connect (G_OBJECT (priv->rdo_media), "toggled", G_CALLBACK (on_security_item_changed), self);

	g_signal_connect (G_OBJECT (priv->trv_res_ctrl), "row-activated", G_CALLBACK (treeview_row_activated_cb), self);
	g_signal_connect (G_OBJECT (priv->trv_res_ctrl), "cursor-changed", G_CALLBACK (treeview_cursor_changed_cb), self);
	g_signal_connect (G_OBJECT (priv->btn_more), "clicked", G_CALLBACK (btn_more_clicked_cb), self);
	g_signal_connect (G_OBJECT (priv->btn_calendar_from), "toggled", G_CALLBACK (btn_calendar_from_clicked_cb), self);
	g_signal_connect (G_OBJECT (priv->btn_calendar_to), "toggled", G_CALLBACK (btn_calendar_to_clicked_cb), self);
	g_signal_connect (G_OBJECT (priv->btn_search), "clicked", G_CALLBACK (btn_search_clicked_cb), self);
	g_signal_connect (G_OBJECT (priv->btn_log_filter), "toggled", G_CALLBACK (log_filter_clicked_cb), self);

	g_timeout_add (500, (GSourceFunc) update_ui, self);
}

static void
sysinfo_window_finalize (GObject *object)
{
	SysinfoWindow *window = SYSINFO_WINDOW (object);
	SysinfoWindowPrivate *priv = window->priv;

	if (priv->agent_check_timeout_id != 0) {
		g_source_remove (priv->agent_check_timeout_id);
		priv->agent_check_timeout_id = 0;
	}

	if (priv->update_check_timeout_id != 0) {
		g_source_remove (priv->update_check_timeout_id);
		priv->update_check_timeout_id = 0;
	}

	g_object_unref (priv->settings);

	G_OBJECT_CLASS (sysinfo_window_parent_class)->finalize (object);
}

static void
sysinfo_window_class_init (SysinfoWindowClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	object_class->finalize = sysinfo_window_finalize;

	gtk_widget_class_set_template_from_resource (GTK_WIDGET_CLASS (class),
			"/kr/gooroom/security/status/sysinfo/sysinfo-window.ui");

	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, stack);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_res_ctrl);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, box_res_ctrl);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, btn_more);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, btn_search);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, btn_calendar_from);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, btn_calendar_to);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, trv_res_ctrl);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_browser_urls);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, scl_browser_urls);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, trv_browser_urls);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_firewall4);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_firewall4_policy);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, scl_firewall4);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, trv_firewall4);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_firewall6);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_firewall6_policy);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, scl_firewall6);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, trv_firewall6);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, trv_security_log);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_sec_status);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_device_id);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_os);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_server_ip);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_machine_id);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_conn_status);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_op_mode);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_port_num);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_kernel_ver);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, box_change_pw_cycle);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_change_pw_cycle);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_screen_saver_time);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_pkgs_change_blocking);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, frm_push_update);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, rdo_os);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, rdo_exe);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, rdo_boot);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, rdo_media);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_os);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_exe);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_boot);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_media);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_log_debug);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_log_info);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_log_notice);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_log_warning);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_log_err);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_log_crit);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_log_alert);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, chk_log_emerg);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, btn_view_log);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, btn_safety_measure);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_update);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, swt_push_update);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, box_device_id);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, box_server_ip);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, box_conn_status);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, box_port_num);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, box_pkgs_change_blocking);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_search_date_from);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, lbl_search_date_to);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SysinfoWindow, btn_log_filter);
}

SysinfoWindow*
sysinfo_window_new (GtkApplication *application)
{
	g_return_val_if_fail (GTK_IS_APPLICATION (application), NULL);

	return g_object_new (SYSINFO_TYPE_WINDOW,
                         "application", application,
                         NULL);
}
