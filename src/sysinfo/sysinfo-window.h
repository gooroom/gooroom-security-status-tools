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


#ifndef _SYSINFO_WINDOW_H_
#define _SYSINFO_WINDOW_H_

#include <gtk/gtk.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define SYSINFO_TYPE_WINDOW            (sysinfo_window_get_type ())
#define SYSINFO_WINDOW(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SYSINFO_TYPE_WINDOW, SysinfoWindow))
#define SYSINFO_WINDOW_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  SYSINFO_TYPE_WINDOW, SysinfoWindowClass))
#define SYSINFO_IS_WINDOW(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SYSINFO_TYPE_WINDOW))
#define SYSINFO_IS_WINDOW_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  SYSINFO_TYPE_WINDOW))
#define SYSINFO_WINDOW_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  SYSINFO_TYPE_WINDOW, SysinfoWindowClass))

typedef struct _SysinfoWindow SysinfoWindow;
typedef struct _SysinfoWindowClass SysinfoWindowClass;
typedef struct _SysinfoWindowPrivate SysinfoWindowPrivate;


struct _SysinfoWindow {
	GtkApplicationWindow __parent__;

	SysinfoWindowPrivate *priv;
};

struct _SysinfoWindowClass {
	GtkApplicationWindowClass __parent_class__;
};


GType           sysinfo_window_get_type   (void) G_GNUC_CONST;

SysinfoWindow  *sysinfo_window_new        (GtkApplication *application);


G_END_DECLS

#endif /* _SYSINFO_WINDOW_H */
