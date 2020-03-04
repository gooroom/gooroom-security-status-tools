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

#ifndef _LOGFILTER_POPOVER_H_
#define _LOGFILTER_POPOVER_H_

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define LOGFILTER_TYPE_POPOVER            (logfilter_popover_get_type ())
#define LOGFILTER_POPOVER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), LOGFILTER_TYPE_POPOVER, LogfilterPopover))
#define LOGFILTER_POPOVER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), LOGFILTER_TYPE_POPOVER, LogfilterPopoverClass))
#define LOGFILTER_IS_POPOVER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), LOGFILTER_TYPE_POPOVER))
#define LOGFILTER_IS_POPOVER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LOGFILTER_TYPE_POPOVER))
#define LOGFILTER_POPOVER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), LOGFILTER_TYPE_POPOVER, LogfilterPopoverClass))

typedef struct _LogfilterPopover        LogfilterPopover;
typedef struct _LogfilterPopoverClass   LogfilterPopoverClass;
typedef struct _LogfilterPopoverPrivate LogfilterPopoverPrivate;


struct _LogfilterPopover {
	GtkPopover __parent__;

	LogfilterPopoverPrivate *priv;
};

struct _LogfilterPopoverClass {
	GtkPopoverClass __parent_class__;
};


GType             logfilter_popover_get_type  (void) G_GNUC_CONST;

LogfilterPopover *logfilter_popover_new       (void);

guint             logfilter_popover_get_logfilter (LogfilterPopover *popover);

void              logfilter_popover_set_logfilter (LogfilterPopover *popover,
                                                   guint             logfilter);

G_END_DECLS

#endif /* _LOGFILTER_POPOVER_H_ */
