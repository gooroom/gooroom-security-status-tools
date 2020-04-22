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
#include "rpd-dialog.h"

#include <gtk/gtk.h>
#include <glib/gi18n.h>

#include <json-c/json.h>


struct _RPDDialog {
	GtkDialog parent;
};

struct _RPDDialogClass {
	GtkDialogClass parent_class;
};

typedef struct _RPDDialogPrivate RPDDialogPrivate;

struct _RPDDialogPrivate {
	GtkWidget  *scl_resource;
	GtkWidget  *trv_resource;
	GtkWidget  *lbl_resource;

	gchar      *resource;
};

enum
{
	PROP_0,
	PROP_RESOURCE
};



G_DEFINE_TYPE_WITH_PRIVATE (RPDDialog, rpd_dialog, GTK_TYPE_DIALOG)


static void
treeview_columns_add (GtkTreeView *treeview, const gchar *type)
{
	gint idx;
	const gchar **p_str_columns;

	static const gchar *NET_COLUMNS[] =
	{
		N_("Status"),
		N_("Protocol"),
		N_("Direction"),
		N_("IP Address"),
		N_("Source Port"),
		N_("Destination Port"),
		NULL
	};

	static const gchar *USB_NET_COLUMNS[] =
	{
		N_("Status"),
		N_("Property"),
		N_("Value"),
		NULL
	};

	if (g_str_equal (type, "network")) {
		p_str_columns = NET_COLUMNS;
	} else if (g_str_equal (type, "usb_network")) {
		p_str_columns = USB_NET_COLUMNS;
	} else {
		return;
	}

	for (idx = 0; p_str_columns[idx] != NULL; idx++) {
		gint col_offset;
		GtkCellRenderer *renderer;
		GtkTreeViewColumn *column;

		renderer = gtk_cell_renderer_text_new ();
		g_object_set (renderer, "xalign", 0.5, NULL);

		col_offset = gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW (treeview),
                                                                  -1, _(p_str_columns[idx]),
                                                                  renderer, "text",
                                                                  idx,
                                                                  NULL);
		column = gtk_tree_view_get_column (GTK_TREE_VIEW (treeview), col_offset - 1);
		gtk_tree_view_column_set_clickable (GTK_TREE_VIEW_COLUMN (column), TRUE);
		gtk_tree_view_column_set_alignment (GTK_TREE_VIEW_COLUMN (column), 0.5);
		gtk_tree_view_column_set_expand (GTK_TREE_VIEW_COLUMN (column), TRUE);
	}
}

static void
build_ui (RPDDialog *dialog)
{
	RPDDialogPrivate *priv;
	priv = rpd_dialog_get_instance_private (dialog);

	gboolean ret = FALSE;
	gchar *grac_rules = NULL, *data = NULL, *output = NULL;
	GtkTreeModel *model;

	if (g_spawn_command_line_sync (GOOROOM_WHICH_GRAC_RULE, &output, NULL, NULL, NULL)) {
		gchar **lines = g_strsplit (output, "\n", -1);
		if (g_strv_length (lines) > 0)
			grac_rules = g_strdup (lines[0]);
		g_strfreev (lines);
	}

	if (grac_rules && g_file_test (grac_rules, G_FILE_TEST_EXISTS))
		g_file_get_contents (grac_rules, &data, NULL, NULL);

	g_free (output);
	g_free (grac_rules);

	if (!data) goto error;

	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (data, &jerr);
	if (jerr != json_tokener_success) {
		goto error;
	}

	if (g_str_equal (priv->resource, "network")) {
		json_object *net_obj = JSON_OBJECT_GET (root_obj, "network");
		if (net_obj) {
			json_object *rules_obj = JSON_OBJECT_GET (net_obj, "rules");
			if (rules_obj) {
				GtkTreeIter iter;
				GtkListStore *model;

				model = gtk_list_store_new (6, G_TYPE_STRING,
                                               G_TYPE_STRING,
                                               G_TYPE_STRING,
                                               G_TYPE_STRING,
                                               G_TYPE_STRING,
                                               G_TYPE_STRING);

				gint i = 0, len = 0;
				len = json_object_array_length (rules_obj);
				for (i = 0; i < len; i++) {
					GtkTreeIter iter;

					json_object *rule = json_object_array_get_idx (rules_obj, i);
					json_object *obj1 = JSON_OBJECT_GET (rule, "state");
					json_object *obj2 = JSON_OBJECT_GET (rule, "protocol");
					json_object *obj3 = JSON_OBJECT_GET (rule, "direction");
					json_object *obj4 = JSON_OBJECT_GET (rule, "ipaddress");
					json_object *obj5 = JSON_OBJECT_GET (rule, "src_ports");
					json_object *obj6 = JSON_OBJECT_GET (rule, "dst_ports");

					const gchar *str_state     = json_object_get_string (obj1);
					const gchar *str_protocol  = json_object_get_string (obj2);
					const gchar *str_direction = json_object_get_string (obj3);
					const gchar *str_ipaddress = json_object_get_string (obj4);
					const gchar *str_src_ports = json_object_get_string (obj5);
					const gchar *str_dst_ports = json_object_get_string (obj6);

					gtk_list_store_append (model, &iter);
					gtk_list_store_set (model, &iter,
                                        0, str_state,
                                        1, str_protocol,
                                        2, str_direction,
                                        3, str_ipaddress,
                                        4, str_src_ports,
                                        5, str_dst_ports,
                                        -1);

					gtk_tree_view_set_model (GTK_TREE_VIEW (priv->trv_resource), GTK_TREE_MODEL (model));

					treeview_columns_add (GTK_TREE_VIEW (priv->trv_resource), "network");

					g_object_unref (model);
				}
				ret = TRUE;
			}

		}
	} else if (g_str_equal (priv->resource, "usb_network")) {
		json_object *usb_net_obj = JSON_OBJECT_GET (root_obj, "usb_network");
		if (usb_net_obj) {
			json_object *wl_obj = JSON_OBJECT_GET (usb_net_obj, "whitelist");
			if (wl_obj) {
				GtkTreeIter iter;
				GtkListStore *model;

				model = gtk_list_store_new (3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

				json_object_object_foreach (wl_obj, key, val) {
					const char *str_val = json_object_get_string (val);
					if (key && str_val) {
						gtk_list_store_append (model, &iter);
						gtk_list_store_set (model, &iter,
                                            0, _("Allow"),
                                            1, key,
                                            2, str_val,
                                            -1);
					}
				}

				gtk_tree_view_set_model (GTK_TREE_VIEW (priv->trv_resource), GTK_TREE_MODEL (model));

				treeview_columns_add (GTK_TREE_VIEW (priv->trv_resource), "usb_network");

				g_object_unref (model);

				ret = TRUE;
			}
		}
	}

	json_object_put (root_obj);

	g_free (data);


error:
	if (!ret) {
		gtk_widget_show (priv->lbl_resource);
		gtk_widget_hide (priv->scl_resource);

		const gchar *msg = _("Could not find information.");
		gchar *markup = g_markup_printf_escaped ("<i>%s</i>", msg);
		gtk_label_set_markup (GTK_LABEL (priv->lbl_resource), markup);
		g_free (markup);
	}
}

static void
rpd_dialog_set_property (GObject       *object,
                         guint          prop_id,
                         const GValue  *value,
                         GParamSpec    *pspec)
{
	RPDDialog *dialog = RPD_DIALOG (object);
	RPDDialogPrivate *priv = rpd_dialog_get_instance_private (dialog);

	switch (prop_id) {
		case PROP_RESOURCE:
			g_free (priv->resource);
			priv->resource = g_strdup (g_value_get_string (value));
			g_object_notify (object, "resource");
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
rpd_dialog_get_property (GObject     *object,
                         guint        prop_id,
                         GValue      *value,
                         GParamSpec  *pspec)
{
	RPDDialog *dialog = RPD_DIALOG (object);
	RPDDialogPrivate *priv = rpd_dialog_get_instance_private (dialog);

	switch (prop_id) {
		case PROP_RESOURCE:
			g_value_set_string (value, priv->resource);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

static void
rpd_dialog_finalize (GObject *object)
{
	RPDDialog *dialog;
	RPDDialogPrivate *priv;

	dialog = RPD_DIALOG (object);
	priv = rpd_dialog_get_instance_private (dialog);

	g_free (priv->resource);
	priv->resource = NULL;

	G_OBJECT_CLASS (rpd_dialog_parent_class)->finalize (object);
}

static GObject *
rpd_dialog_constructor (GType                  type,
                        guint                  n_construct_properties,
                        GObjectConstructParam *construct_params)
{
	GObject   *object;
	RPDDialog *self; 
	RPDDialogPrivate *priv;

	object = G_OBJECT_CLASS (rpd_dialog_parent_class)->constructor (type, n_construct_properties, construct_params);

	self = RPD_DIALOG (object);
	priv = rpd_dialog_get_instance_private (self);

	gchar *title = g_strdup_printf ("%s (%s)", _("View more detail"), _(priv->resource));
	gtk_window_set_title (GTK_WINDOW (self), title);
	g_free (title);

	build_ui (self);

	gtk_tree_view_expand_all (GTK_TREE_VIEW (priv->trv_resource));

	return object;
}

static void
rpd_dialog_init (RPDDialog *dialog)
{
	RPDDialogPrivate *priv = rpd_dialog_get_instance_private (dialog);

	gtk_widget_init_template (GTK_WIDGET (dialog));

	priv->resource = NULL;
}

static void
rpd_dialog_class_init (RPDDialogClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);

	object_class->finalize     = rpd_dialog_finalize;
	object_class->constructor  = rpd_dialog_constructor;
	object_class->set_property = rpd_dialog_set_property;
	object_class->get_property = rpd_dialog_get_property;

	gtk_widget_class_set_template_from_resource (GTK_WIDGET_CLASS (class),
			"/kr/gooroom/security/status/sysinfo/rpd-dialog.ui");

	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), RPDDialog, scl_resource);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), RPDDialog, trv_resource);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), RPDDialog, lbl_resource);

	g_object_class_install_property (object_class,
									PROP_RESOURCE,
									g_param_spec_string ("resource",
									"",
									"",
									NULL,
									G_PARAM_READWRITE|G_PARAM_CONSTRUCT_ONLY));

}

RPDDialog *
rpd_dialog_new (GtkWidget *parent, const gchar *resource)
{
	return g_object_new (RPD_DIALOG_TYPE,
						"transient-for", parent,
						"use-header-bar", FALSE,
						"resource", resource,
						NULL);
}
