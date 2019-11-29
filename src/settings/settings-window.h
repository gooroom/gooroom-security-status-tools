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
 */


#ifndef _SETTINGS_WINDOW_H_
#define _SETTINGS_WINDOW_H_

#include <gtk/gtk.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define SETTINGS_TYPE_WINDOW            (settings_window_get_type ())
#define SETTINGS_WINDOW(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SETTINGS_TYPE_WINDOW, SettingsWindow))
#define SETTINGS_WINDOW_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  SETTINGS_TYPE_WINDOW, SettingsWindowClass))
#define SETTINGS_IS_WINDOW(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SETTINGS_TYPE_WINDOW))
#define SETTINGS_IS_WINDOW_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  SETTINGS_TYPE_WINDOW))
#define SETTINGS_WINDOW_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  SETTINGS_TYPE_WINDOW, SettingsWindowClass))

typedef struct _SettingsWindow SettingsWindow;
typedef struct _SettingsWindowClass SettingsWindowClass;
typedef struct _SettingsWindowPrivate SettingsWindowPrivate;


struct _SettingsWindow {
	GtkApplicationWindow __parent__;

	SettingsWindowPrivate *priv;
};

struct _SettingsWindowClass {
	GtkApplicationWindowClass __parent_class__;
};


GType            settings_window_get_type   (void) G_GNUC_CONST;

SettingsWindow  *settings_window_new        (GtkApplication *application);

G_END_DECLS

#endif /* _SETTINGS_WINDOW_H */
