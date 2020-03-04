/* 
 * Copyright (C) 2018-2020 Gooroom <gooroom@gooroom.kr>
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
 *
 */

#ifndef _CALENDAR_POPOVER_H_
#define _CALENDAR_POPOVER_H_

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define CALENDAR_TYPE_POPOVER            (calendar_popover_get_type ())
#define CALENDAR_POPOVER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), CALENDAR_TYPE_POPOVER, CalendarPopover))
#define CALENDAR_POPOVER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), CALENDAR_TYPE_POPOVER, CalendarPopoverClass))
#define CALENDAR_IS_POPOVER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CALENDAR_TYPE_POPOVER))
#define CALENDAR_IS_POPOVER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), CALENDAR_TYPE_POPOVER))
#define CALENDAR_POPOVER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), CALENDAR_TYPE_POPOVER, CalendarPopoverClass))

typedef struct _CalendarPopover        CalendarPopover;
typedef struct _CalendarPopoverClass   CalendarPopoverClass;
typedef struct _CalendarPopoverPrivate CalendarPopoverPrivate;


struct _CalendarPopover {
	GtkPopover __parent__;

	CalendarPopoverPrivate *priv;
};

struct _CalendarPopoverClass {
	GtkPopoverClass __parent_class__;
};


GType            calendar_popover_get_type  (void) G_GNUC_CONST;

CalendarPopover *calendar_popover_new       (void);

void             calendar_popover_set_date  (CalendarPopover *popover,
                                             gint             year,
                                             gint             month,
                                             gint             day);

void             calendar_popover_get_date  (CalendarPopover *popover,
                                             gint            *year,
                                             gint            *month,
                                             gint            *day);

G_END_DECLS

#endif /* _CALENDAR_POPOVER_H_ */
