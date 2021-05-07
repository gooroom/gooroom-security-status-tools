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
#include "settings-window.h"

#include <stdlib.h>

#include <config.h>

#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <gio/gio.h>


struct _SettingsWindowPrivate
{
	GSettings *settings;

	GtkWidget *swt_service;
	GtkWidget *lbl_mgt_svr_url;
	GtkWidget *lbl_svr_crt;
	GtkWidget *lbl_client_id;
	GtkWidget *lbl_group;
	GtkWidget *lbl_client_crt;
	GtkWidget *btn_gms_settings;
	GtkWidget *chk_adn;
};


G_DEFINE_TYPE_WITH_PRIVATE (SettingsWindow, settings_window, GTK_TYPE_APPLICATION_WINDOW)



static gboolean on_service_state_changed (GtkSwitch *widget, gboolean state, gpointer data);


static void
child_watch_func (GPid     pid,
                  gint     status,
                  gpointer data)
{
	GtkWidget *dlg;
	gboolean service_active = FALSE, switch_active = FALSE;
	SettingsWindow *window = SETTINGS_WINDOW (data);
	SettingsWindowPrivate *priv = window->priv;

	g_spawn_close_pid (pid);

	if (!is_systemd_service_available (GOOROOM_AGENT_SERVICE_NAME)) {
		gtk_widget_set_sensitive (priv->swt_service, FALSE);
		gtk_switch_set_active (GTK_SWITCH (priv->swt_service), FALSE);
		return;
	}

	gtk_widget_set_sensitive (priv->swt_service, TRUE);

	service_active = is_systemd_service_active (GOOROOM_AGENT_SERVICE_NAME);
	switch_active = gtk_switch_get_active (GTK_SWITCH (priv->swt_service));

	g_signal_handlers_block_by_func (priv->swt_service, on_service_state_changed, window);
	gtk_switch_set_active (GTK_SWITCH (priv->swt_service), service_active);
	g_signal_handlers_unblock_by_func (priv->swt_service, on_service_state_changed, window);

	if (switch_active == service_active) {
		const gchar *message = (service_active) ? _("Service was started successfully") : _("Service was stopped successfully");

		dlg = gtk_message_dialog_new (GTK_WINDOW (window),
				GTK_DIALOG_MODAL,
				GTK_MESSAGE_INFO,
				GTK_BUTTONS_OK,
				NULL);

		gtk_message_dialog_format_secondary_markup (GTK_MESSAGE_DIALOG (dlg), "%s", message);

		gtk_window_set_title (GTK_WINDOW (dlg), _("Notifications"));
		gtk_dialog_run (GTK_DIALOG (dlg));
		gtk_widget_destroy (dlg);
	}
}

static gboolean
gooroom_agent_service_control (gpointer data)
{
	SettingsWindow *window = SETTINGS_WINDOW (data);
	SettingsWindowPrivate *priv = window->priv;

	GPid pid;
	gchar *cmd;
	gchar **argv;
	GError *error = NULL;

	gtk_widget_set_sensitive (GTK_WIDGET (priv->swt_service), FALSE);

	if (gtk_switch_get_active (GTK_SWITCH (priv->swt_service)))
		cmd = g_strdup_printf ("pkexec %s -s %s -a", GOOROOM_SYSTEMD_CONTROL_HELPER, GOOROOM_AGENT_SERVICE_NAME);
	else
		cmd = g_strdup_printf ("pkexec %s -s %s -d", GOOROOM_SYSTEMD_CONTROL_HELPER, GOOROOM_AGENT_SERVICE_NAME);

	g_shell_parse_argv (cmd, NULL, &argv, NULL);

	g_spawn_async_with_pipes (NULL, argv, NULL,
                              G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD, NULL,
                              NULL, &pid, NULL, NULL, NULL, &error);

	if (error)
		g_warning ("%s\n", error->message);

	g_free (cmd);
	g_strfreev (argv);

	g_child_watch_add (pid, child_watch_func, window);

	return FALSE;
}

static gboolean
on_service_state_changed (GtkSwitch *widget, gboolean state, gpointer data)
{
	SettingsWindow *window = SETTINGS_WINDOW (data);

	g_idle_add ((GSourceFunc) gooroom_agent_service_control, window);

	return FALSE;
}

static gboolean
gooroom_agent_service_status_update (gpointer data)
{
	SettingsWindow *window;
	SettingsWindowPrivate *priv;

	window = SETTINGS_WINDOW (data);
	priv = window->priv;

	if (!is_systemd_service_available (GOOROOM_AGENT_SERVICE_NAME)) {
		gtk_widget_set_sensitive (priv->swt_service, FALSE);
		return FALSE;
	}

	gtk_widget_set_sensitive (priv->swt_service, TRUE);

	g_signal_handlers_block_by_func (priv->swt_service, on_service_state_changed, window);

	gtk_switch_set_active (GTK_SWITCH (priv->swt_service), is_systemd_service_active (GOOROOM_AGENT_SERVICE_NAME));

	g_signal_handlers_unblock_by_func (priv->swt_service, on_service_state_changed, window);

	return FALSE;
}

static void
on_allow_duplicate_notification_toggled (GtkToggleButton *button,
                                         gpointer         data)
{
	SettingsWindow *window = SETTINGS_WINDOW (data);
	SettingsWindowPrivate *priv = window->priv;

	if (priv->settings) {
    	gboolean val = gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (button)) ? 1 : 0;
		g_settings_set_boolean (priv->settings, "allow-duplicate-notifications", val);
	}
}

static void
update_ui (SettingsWindow *window)
{
	SettingsWindowPrivate *priv = window->priv;

	gchar *svr_crt = NULL, *client_name = NULL, *group = NULL, *client_crt = NULL, *svr_mgt_url = NULL;
	GError *error = NULL;
	GKeyFile *keyfile = NULL;

	keyfile = g_key_file_new ();

	g_key_file_load_from_file (keyfile, GOOROOM_MANAGEMENT_SERVER_CONF, G_KEY_FILE_KEEP_COMMENTS, &error);

	if (error == NULL) {
		if (g_key_file_has_group (keyfile, "domain")) {
			svr_mgt_url = g_key_file_get_string (keyfile, "domain", "gkm", NULL);
		}

		if (g_key_file_has_group (keyfile, "certificate")) {
			svr_crt = g_key_file_get_string (keyfile, "certificate", "server_crt", NULL);
			client_name = g_key_file_get_string (keyfile, "certificate", "client_name", NULL);
			group = g_key_file_get_string (keyfile, "certificate", "organizational_unit", NULL);
			client_crt = g_key_file_get_string (keyfile, "certificate", "client_crt", NULL);
		}
	}

	if (!svr_mgt_url)
		svr_mgt_url = g_strdup (_("Unknown"));

	if (!svr_crt)
		svr_crt = g_strdup (_("Unknown"));

	if (!client_name)
		client_name = g_strdup (_("Unknown"));

	if (!group)
		group = g_strdup (_("Unknown"));

	if (!client_crt)
		client_crt = g_strdup (_("Unknown"));

	gtk_label_set_text (GTK_LABEL (priv->lbl_mgt_svr_url), svr_mgt_url);
	gtk_label_set_text (GTK_LABEL (priv->lbl_svr_crt), svr_crt);
	gtk_label_set_text (GTK_LABEL (priv->lbl_client_id), client_name);
	gtk_label_set_text (GTK_LABEL (priv->lbl_group), group);
	gtk_label_set_text (GTK_LABEL (priv->lbl_client_crt), client_crt);

	g_free (svr_mgt_url);
	g_free (svr_crt);
	g_free (client_name);
	g_free (group);
	g_free (client_crt);

	g_key_file_free (keyfile);
	g_clear_error (&error);

	gooroom_agent_service_status_update (window);

	gboolean adn = FALSE;
	if (priv->settings)
		adn = g_settings_get_boolean (priv->settings, "allow-duplicate-notifications");

	g_signal_handlers_block_by_func (priv->chk_adn, on_allow_duplicate_notification_toggled, window);
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_adn), adn);
	g_signal_handlers_unblock_by_func (priv->chk_adn, on_allow_duplicate_notification_toggled, window);
}

static void
open_help (GtkAccelGroup *accel, GObject *acceleratable,
           guint keyval, GdkModifierType modifier,
           gpointer user_data)
{
    gtk_show_uri_on_window (GTK_WINDOW(user_data), "help:gooroom-settings",
                            gtk_get_current_event_time(), NULL);
}

static void
accel_init (SettingsWindow *window)
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
client_server_register_done (GPid pid, gint status, gpointer data)
{
	SettingsWindow *window;
	SettingsWindowPrivate *priv;

	window = SETTINGS_WINDOW (data);
	priv = window->priv;

	g_spawn_close_pid (pid);

	update_ui (window);

	gtk_widget_set_sensitive (GTK_WIDGET (priv->btn_gms_settings), TRUE);
}

static gboolean
launch_client_server_register_async (SettingsWindow *window)
{
	GPid pid;
	gboolean ret = FALSE;
	gchar **argv = NULL;
	gchar *pkexec = NULL, *cmd = NULL, *cmdline = NULL;

	SettingsWindowPrivate *priv = window->priv;

	pkexec = g_find_program_in_path ("pkexec");
	cmd = g_find_program_in_path ("gooroom-client-server-register");

	if (!cmd) {
		GtkWidget *message;

		message = gtk_message_dialog_new (GTK_WINDOW (window),
				GTK_DIALOG_MODAL,
				GTK_MESSAGE_INFO,
				GTK_BUTTONS_CLOSE,
				_("Program is not installed"));

		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (message),
				_("Please install the gooroom-client-server-register."));

		gtk_dialog_run (GTK_DIALOG (message));
		gtk_widget_destroy (message);

		goto error;
	}

	cmdline = g_strdup_printf ("%s %s", pkexec, GCSR_WRAPPER);
	g_shell_parse_argv (cmdline, NULL, &argv, NULL);

	if (g_spawn_async (NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, NULL)) {
		g_child_watch_add (pid, (GChildWatchFunc) client_server_register_done, window);
		ret = TRUE;
	}

	g_free (cmdline);
	g_strfreev (argv);

error:
	g_free (cmd);
	g_free (pkexec);

	return ret;
}

static void
on_gms_settings_button_clicked (GtkButton *button, gpointer data)
{
	SettingsWindow *window = SETTINGS_WINDOW (data);

	gtk_widget_set_sensitive (GTK_WIDGET (button), FALSE);

	if (!launch_client_server_register_async (window))
		gtk_widget_set_sensitive (GTK_WIDGET (button), TRUE);
}

static void
settings_window_finalize (GObject *object)
{
	SettingsWindow *window = SETTINGS_WINDOW (object);
	SettingsWindowPrivate *priv = window->priv;

	if (priv->settings) {
		g_object_unref (priv->settings);
	}

	G_OBJECT_CLASS (settings_window_parent_class)->finalize (object);
}

static void
settings_window_init (SettingsWindow *self)
{
	GSettingsSchema *schema;
	SettingsWindowPrivate *priv;

	priv = self->priv = settings_window_get_instance_private (self);

	priv->settings = NULL;

	gtk_widget_init_template (GTK_WIDGET (self));

	schema = g_settings_schema_source_lookup (g_settings_schema_source_get_default (),
                                              "apps.gooroom-security-status", TRUE);
	if (schema) {
		priv->settings = g_settings_new_full (schema, NULL, NULL);
		g_settings_schema_unref (schema);
	}

	update_ui (self);
    accel_init (self);

	g_signal_connect (G_OBJECT (priv->swt_service), "state-set",
                      G_CALLBACK (on_service_state_changed), self);

	g_signal_connect (G_OBJECT (priv->btn_gms_settings), "clicked",
                      G_CALLBACK (on_gms_settings_button_clicked), self);

	gtk_widget_set_sensitive (GTK_WIDGET (priv->chk_adn), FALSE);
	if (priv->settings) {
		gtk_widget_set_sensitive (GTK_WIDGET (priv->chk_adn), TRUE);
		g_signal_connect (G_OBJECT (priv->chk_adn), "toggled",
                          G_CALLBACK (on_allow_duplicate_notification_toggled), self);
	}
}

static void
settings_window_class_init (SettingsWindowClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	object_class->finalize = settings_window_finalize;

	gtk_widget_class_set_template_from_resource (GTK_WIDGET_CLASS (class),
			"/kr/gooroom/security/status/settings/settings-window.ui");

	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SettingsWindow, swt_service);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SettingsWindow, lbl_mgt_svr_url);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SettingsWindow, lbl_svr_crt);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SettingsWindow, lbl_client_id);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SettingsWindow, lbl_group);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SettingsWindow, lbl_client_crt);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SettingsWindow, btn_gms_settings);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), SettingsWindow, chk_adn);
}

SettingsWindow*
settings_window_new (GtkApplication *application)
{
	g_return_val_if_fail (GTK_IS_APPLICATION (application), NULL);

	return g_object_new (SETTINGS_TYPE_WINDOW,
                         "application", application,
                         NULL);
}
