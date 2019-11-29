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

#ifndef _CALENDAR_DIALOG_H_
#define _CALENDAR_DIALOG_H_

#include <glib.h>
#include <gtk/gtk.h>

G_BEGIN_DECLS

#define CALENDAR_DIALOG_TYPE (calendar_dialog_get_type ())
#define CALENDAR_DIALOG(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), CALENDAR_DIALOG_TYPE, CalendarDialog))

typedef struct _CalendarDialog       CalendarDialog;
typedef struct _CalendarDialogClass  CalendarDialogClass;

GType            calendar_dialog_get_type      (void) G_GNUC_CONST;

CalendarDialog  *calendar_dialog_new           (GtkWidget *parent);

void             calendar_dialog_get_date      (CalendarDialog *dialog,
                                                gint *year,
                                                gint *month,
                                                gint *day);

void             calendar_dialog_set_date      (CalendarDialog *dialog,
                                                gint year,
                                                gint month,
                                                gint day);

G_END_DECLS

#endif /* _CALENDAR_DIALOG_H_ */
