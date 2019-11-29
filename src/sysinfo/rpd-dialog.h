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
 *
 */

#ifndef _RPD_DIALOG_H_
#define _RPD_DIALOG_H_

#include <gtk/gtk.h>

G_BEGIN_DECLS

#define RPD_DIALOG_TYPE (rpd_dialog_get_type ())
#define RPD_DIALOG(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), RPD_DIALOG_TYPE, RPDDialog))


typedef struct _RPDDialog          RPDDialog;
typedef struct _RPDDialogClass     RPDDialogClass;


GType         rpd_dialog_get_type  (void) G_GNUC_CONST;

RPDDialog    *rpd_dialog_new       (GtkWidget   *parent,
                                    const gchar *resource);

G_END_DECLS

#endif /* _RPD_DIALOG_H_ */
