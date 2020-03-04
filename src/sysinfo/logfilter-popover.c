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
#include "logfilter-popover.h"

#include <gtk/gtk.h>
#include <glib/gi18n.h>


struct _LogfilterPopoverPrivate {
	GtkWidget *chk_log_debug;
	GtkWidget *chk_log_info;
	GtkWidget *chk_log_notice;
	GtkWidget *chk_log_warning;
	GtkWidget *chk_log_err;
	GtkWidget *chk_log_crit;
	GtkWidget *chk_log_alert;
	GtkWidget *chk_log_emerg;

	guint filter;
};


G_DEFINE_TYPE_WITH_PRIVATE (LogfilterPopover, logfilter_popover, GTK_TYPE_POPOVER)


static void
logfilter_popover_init (LogfilterPopover *self)
{
	LogfilterPopoverPrivate *priv;

	priv = self->priv = logfilter_popover_get_instance_private (self);

	gtk_widget_init_template (GTK_WIDGET (self));
}

static void
logfilter_popover_class_init (LogfilterPopoverClass *class)
{
	gtk_widget_class_set_template_from_resource (GTK_WIDGET_CLASS (class),
			"/kr/gooroom/security/status/sysinfo/logfilter-popover.ui");

	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), LogfilterPopover, chk_log_debug);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), LogfilterPopover, chk_log_info);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), LogfilterPopover, chk_log_notice);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), LogfilterPopover, chk_log_warning);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), LogfilterPopover, chk_log_err);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), LogfilterPopover, chk_log_crit);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), LogfilterPopover, chk_log_alert);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), LogfilterPopover, chk_log_emerg);
}

LogfilterPopover *
logfilter_popover_new (void)
{
	return g_object_new (LOGFILTER_TYPE_POPOVER, NULL);
}

guint
logfilter_popover_get_logfilter (LogfilterPopover *popover)
{
	guint filter = 0;
	LogfilterPopoverPrivate *priv = popover->priv;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (priv->chk_log_debug)))
		filter |= LOG_LEVEL_DEBUG;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (priv->chk_log_info)))
		filter |= LOG_LEVEL_INFO;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (priv->chk_log_notice)))
		filter |= LOG_LEVEL_NOTICE;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (priv->chk_log_warning)))
		filter |= LOG_LEVEL_WARNING;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (priv->chk_log_err)))
		filter |= LOG_LEVEL_ERR;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (priv->chk_log_crit)))
		filter |= LOG_LEVEL_CRIT;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (priv->chk_log_alert)))
		filter |= LOG_LEVEL_ALERT;

	if (gtk_toggle_button_get_active (GTK_TOGGLE_BUTTON (priv->chk_log_emerg)))
		filter |= LOG_LEVEL_EMERG;

	return filter;
}

void
logfilter_popover_set_logfilter (LogfilterPopover *popover, guint logfilter)
{
	LogfilterPopoverPrivate *priv = popover->priv;

	priv->filter = logfilter;

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_log_debug),
                                 (priv->filter & LOG_LEVEL_DEBUG));

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_log_info),
                                 (priv->filter & LOG_LEVEL_INFO));

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_log_notice),
                                 (priv->filter & LOG_LEVEL_NOTICE));

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_log_warning),
                                 (priv->filter & LOG_LEVEL_WARNING));

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_log_err),
                                 (priv->filter & LOG_LEVEL_ERR));

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_log_crit),
                                 (priv->filter & LOG_LEVEL_CRIT));

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_log_alert),
                                 (priv->filter & LOG_LEVEL_ALERT));

	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (priv->chk_log_emerg),
                                 (priv->filter & LOG_LEVEL_EMERG));
}
