/* 
 * Copyright (C) 2018-2019 Gooroom <gooroom@gooroom.kr>
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
#include "calendar-popover.h"

#include <gtk/gtk.h>
#include <glib/gi18n.h>


struct _CalendarPopoverPrivate {
	GtkWidget  *calendar;
};


G_DEFINE_TYPE_WITH_PRIVATE (CalendarPopover, calendar_popover, GTK_TYPE_POPOVER)


static void
calendar_popover_init (CalendarPopover *self)
{
	GtkCssProvider *provider;
	GtkStyleContext *style_context;
	CalendarPopoverPrivate *priv;

	priv = self->priv = calendar_popover_get_instance_private (self);

	priv->calendar = gtk_calendar_new ();
	gtk_container_set_border_width (GTK_CONTAINER (self), 6);
	gtk_container_add (GTK_CONTAINER (self), priv->calendar);

	provider = gtk_css_provider_new ();
	gtk_css_provider_load_from_data (GTK_CSS_PROVIDER (provider),
                       "calendar {"
                       "  border: none;"
                       "  padding: 3px;"
                       "}" , -1, NULL);
	style_context = gtk_widget_get_style_context (priv->calendar);
	gtk_style_context_add_provider (style_context,
                                    GTK_STYLE_PROVIDER (provider),
                                    GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	g_object_unref (provider);

	gtk_widget_show (priv->calendar);
}

static void
calendar_popover_class_init (CalendarPopoverClass *class)
{
}

CalendarPopover *
calendar_popover_new (void)
{
	return g_object_new (CALENDAR_TYPE_POPOVER, NULL);
}

void
calendar_popover_set_date (CalendarPopover *popover, gint year, gint month, gint day)
{
	gint l_year, l_month, l_day;

	l_year = (year < DEFAULT_YEAR || year > 9999) ? DEFAULT_YEAR : year;
	l_month = (month < 1 || month > 12) ? DEFAULT_MONTH : month;
	l_day = (day < 1 || day > 31) ? DEFAULT_DAY : day;

	gtk_calendar_select_month (GTK_CALENDAR (popover->priv->calendar), l_month-1, l_year);
	gtk_calendar_select_day (GTK_CALENDAR (popover->priv->calendar), l_day);
}

void
calendar_popover_get_date (CalendarPopover *popover, gint *year, gint *month, gint *day)
{
	guint l_year, l_month, l_day;

	gtk_calendar_get_date (GTK_CALENDAR (popover->priv->calendar), &l_year, &l_month, &l_day);

	if (year) *year = (gint)l_year;
	if (month)*month = (gint)l_month + 1;
	if (day)  *day = (gint)l_day;
}
