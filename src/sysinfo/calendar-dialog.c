/* 
 * Copyright (C) 2015-2019 Gooroom <gooroom@gooroom.kr>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#include "common.h"
#include "calendar-dialog.h"

#include <config.h>
#include <glib/gi18n.h>


struct _CalendarDialog {
	GtkDialog parent;
};

struct _CalendarDialogClass {
	GtkDialogClass parent_class;
};

typedef struct _CalendarDialogPrivate CalendarDialogPrivate;

struct _CalendarDialogPrivate {
	GtkWidget     *btn_ok;
	GtkWidget     *calendar;
};

G_DEFINE_TYPE_WITH_PRIVATE (CalendarDialog, calendar_dialog, GTK_TYPE_DIALOG)

static void
on_ok_button_clicked (GtkButton *widget, gpointer data)
{
	gint year = DEFAULT_YEAR;
	CalendarDialog *dialog;
	CalendarDialogPrivate *priv;

	dialog = CALENDAR_DIALOG (data);
	priv = calendar_dialog_get_instance_private (dialog);

	calendar_dialog_get_date (dialog, &year, NULL, NULL);

	if (year < DEFAULT_YEAR) {
		GtkWidget *message;

		message = gtk_message_dialog_new (GTK_WINDOW (dialog),
				GTK_DIALOG_MODAL,
				GTK_MESSAGE_INFO,
				GTK_BUTTONS_CLOSE,
				_("Invalid date"));

		gtk_message_dialog_format_secondary_text (GTK_MESSAGE_DIALOG (message),
						_("The date for searching log can only be set after January 1, %d."), DEFAULT_YEAR);
		gtk_dialog_run (GTK_DIALOG (message));
		gtk_widget_destroy (message);
		return;
	}

	gtk_dialog_response (GTK_DIALOG (dialog), GTK_RESPONSE_OK);
}

static void
calendar_dialog_init (CalendarDialog *dialog)
{
	GDateTime *dt;
	gint year, month, day;

	CalendarDialogPrivate *priv;
	priv = calendar_dialog_get_instance_private (dialog);

	gtk_widget_init_template (GTK_WIDGET (dialog));

	gtk_window_set_title (GTK_WINDOW (dialog), _("Date Selection"));

	dt = g_date_time_new_now_local ();
	g_date_time_get_ymd (dt, &year, &month, &day);

	calendar_dialog_set_date (dialog, year, month, day);

    if (dt) g_date_time_unref (dt);

	g_signal_connect (priv->btn_ok, "clicked", G_CALLBACK (on_ok_button_clicked), dialog);

}

static void
calendar_dialog_class_init (CalendarDialogClass *class)
{
	gtk_widget_class_set_template_from_resource (GTK_WIDGET_CLASS (class),
			"/kr/gooroom/security/status/sysinfo/calendar-dialog.ui");

	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), CalendarDialog, btn_ok);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), CalendarDialog, calendar);
}

CalendarDialog*
calendar_dialog_new (GtkWidget *parent)
{
	return g_object_new (CALENDAR_DIALOG_TYPE, "transient-for", parent, "use-header-bar", FALSE, NULL);
}

void
calendar_dialog_set_date (CalendarDialog *dialog, gint year, gint month, gint day)
{
	gint l_year, l_month, l_day;

	CalendarDialogPrivate *priv;
	priv = calendar_dialog_get_instance_private (dialog);

	l_year = (year < DEFAULT_YEAR || year > 9999) ? DEFAULT_YEAR : year;
	l_month = (month < 1 || month > 12) ? DEFAULT_MONTH : month;
	l_day = (day < 1 || day > 31) ? DEFAULT_DAY : day;

	gtk_calendar_select_month (GTK_CALENDAR (priv->calendar), l_month-1, l_year);
	gtk_calendar_select_day (GTK_CALENDAR (priv->calendar), l_day);
}

void
calendar_dialog_get_date (CalendarDialog *dialog, gint *year, gint *month, gint *day)
{
	guint l_year, l_month, l_day;

	CalendarDialogPrivate *priv;
	priv = calendar_dialog_get_instance_private (dialog);

	gtk_calendar_get_date (GTK_CALENDAR (priv->calendar), &l_year, &l_month, &l_day);

	if (year) *year = (gint)l_year;
	if (month)*month = (gint)l_month + 1;
	if (day)  *day = (gint)l_day;
}
