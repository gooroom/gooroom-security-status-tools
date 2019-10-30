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
	GtkWidget  *trv_col_1;
	GtkWidget  *trv_col_2;

	gchar      *resource;
};

enum
{
	PROP_0,
	PROP_RESOURCE
};



G_DEFINE_TYPE_WITH_PRIVATE (RPDDialog, rpd_dialog, GTK_TYPE_DIALOG)


static void
build_ui (RPDDialog *dialog)
{
	gchar *file = NULL;
	gchar *data = NULL;
	gboolean ret = FALSE;
	const gchar *files[] = {"/etc/gooroom/grac.d/user.rules", "/etc/gooroom/grac.d/default.rules", NULL};

	RPDDialogPrivate *priv;
	priv = rpd_dialog_get_instance_private (dialog);

	if (!g_str_equal (priv->resource, "network") && !g_str_equal (priv->resource, "bluetooth"))
		goto error;

	guint i = 0;
	for (i; i < G_N_ELEMENTS (files); i++) {
		if (g_file_test (files[i], G_FILE_TEST_EXISTS)) {
			file = g_strdup (files[i]);
			break;
		}
	}

	if (!file) goto error;

	g_file_get_contents (file, &data, NULL, NULL);

	g_free (file);

	if (!data) goto error;

	enum json_tokener_error jerr = json_tokener_success;
	json_object *root_obj = json_tokener_parse_verbose (data, &jerr);
	if (jerr != json_tokener_success) {
		goto error;
	}

	if (g_str_equal (priv->resource, "network")) {
		json_object *net_obj = JSON_OBJECT_GET (root_obj, "network");
		if (net_obj) {
			GtkTreeIter iter0;
			GtkTreeModel *model;
			model = gtk_tree_view_get_model (GTK_TREE_VIEW (priv->trv_resource));

			json_object *rules_obj = JSON_OBJECT_GET (net_obj, "rules");
			json_object *state_obj = JSON_OBJECT_GET (net_obj, "state");

			if (state_obj) {
				gchar *default_state = NULL;
				const char *str_state = json_object_get_string (state_obj);
				if (g_str_equal (str_state, "allow") || g_str_equal (str_state, "accept"))
					default_state = g_strdup (_("Allow"));
				else
					default_state = g_strdup (_("Block"));

				gtk_tree_store_append (GTK_TREE_STORE (model), &iter0, NULL);
				gtk_tree_store_set (GTK_TREE_STORE (model), &iter0,
						0, _("default_network"),
						1, default_state,
						-1);

				g_free (default_state);
			}

			if (rules_obj) {
				gtk_tree_store_append (GTK_TREE_STORE (model), &iter0, NULL);
				gtk_tree_store_set (GTK_TREE_STORE (model), &iter0,
						0, "rules",
						-1);

				int i = 0, len = 0;
				len = json_object_array_length (rules_obj);
				for (i = 0; i < len; i++) {
					GtkTreeIter iter1, iter2;

					gchar *str_rule = g_strdup_printf ("%s%d", _("rule"), i);

					gtk_tree_store_append (GTK_TREE_STORE (model), &iter1, &iter0);
					gtk_tree_store_set (GTK_TREE_STORE (model), &iter1,
							0, str_rule,
							-1);

					g_free (str_rule);

					json_object *rule = json_object_array_get_idx (rules_obj, i);
					json_object *obj1 = JSON_OBJECT_GET (rule, "ipaddress");
					json_object *obj2 = JSON_OBJECT_GET (rule, "state");
					json_object *obj3 = JSON_OBJECT_GET (rule, "ports");
					json_object *obj4 = JSON_OBJECT_GET (rule, "direction");

					if (obj1) {
						const char *str_ipaddress = json_object_get_string (obj1);
						gchar *ipaddress = g_strdup (str_ipaddress);

						gtk_tree_store_append (GTK_TREE_STORE (model), &iter2, &iter1);
						gtk_tree_store_set (GTK_TREE_STORE (model), &iter2,
								0, "ipaddress",
								1, ipaddress,
								-1);

						g_free (ipaddress);
					}


					if (obj2) {
						const char *state = json_object_get_string (obj2);
						gchar *str_state = g_strdup (state);

						gtk_tree_store_append (GTK_TREE_STORE (model), &iter2, &iter1);
						gtk_tree_store_set (GTK_TREE_STORE (model), &iter2,
								0, "state",
								1, str_state,
								-1);

						g_free (str_state);

					}

					if (obj3) {
						gtk_tree_store_append (GTK_TREE_STORE (model), &iter2, &iter1);
						gtk_tree_store_set (GTK_TREE_STORE (model), &iter2,
								0, "ports",
								-1);

						int i = 0, len = 0;
						len = json_object_array_length (obj3);
						for (i = 0; i < len; i++) {
							GtkTreeIter iter3, iter4;

							gchar *str_port = g_strdup_printf ("%s%d", _("ports"), i);

							gtk_tree_store_append (GTK_TREE_STORE (model), &iter3, &iter2);
							gtk_tree_store_set (GTK_TREE_STORE (model), &iter3,
									0, str_port,
									-1);

							g_free (str_port);

							json_object *ports_obj = json_object_array_get_idx (obj3, i);
							json_object *src_ports_obj = JSON_OBJECT_GET (ports_obj, "src_port");
							json_object *protocols_obj = JSON_OBJECT_GET (ports_obj, "protocol");
							json_object *dst_ports_obj = JSON_OBJECT_GET (ports_obj, "dst_port");
							if (src_ports_obj) {
								int j = 0;
								int j_len = json_object_array_length (src_ports_obj);
								GPtrArray *arr = g_ptr_array_new ();
								for (j = 0; j < j_len; j++) {
									json_object *src_port_obj = json_object_array_get_idx (src_ports_obj, j);
									const char *src_port = json_object_get_string (src_port_obj);
									g_ptr_array_add (arr, g_strdup (src_port));
								}
								g_ptr_array_add (arr, NULL);
								gchar **strings = (gchar **)g_ptr_array_free (arr, FALSE);

								gchar *str_src_ports = g_strjoinv (",", strings);

								g_free (strings);

								gtk_tree_store_append (GTK_TREE_STORE (model), &iter4, &iter3);
								gtk_tree_store_set (GTK_TREE_STORE (model), &iter4,
										0, "src_port",
										1, str_src_ports,
										-1);

								g_free (str_src_ports);
							}

							if (protocols_obj) {
								const char *protocols = json_object_get_string (protocols_obj);
								gchar *str_protocols = g_strdup (protocols);

								gtk_tree_store_append (GTK_TREE_STORE (model), &iter4, &iter3);
								gtk_tree_store_set (GTK_TREE_STORE (model), &iter4,
										0, "protocol",
										1, str_protocols,
										-1);

								g_free (str_protocols);
							}

							if (dst_ports_obj) {
								int j = 0;
								int j_len = json_object_array_length (dst_ports_obj);
								GPtrArray *arr = g_ptr_array_new ();
								for (j = 0; j < j_len; j++) {
									json_object *dst_port_obj = json_object_array_get_idx (dst_ports_obj, j);
									const char *dst_port = json_object_get_string (dst_port_obj);
								}
								g_ptr_array_add (arr, NULL);
								gchar **strings = (gchar **)g_ptr_array_free (arr, FALSE);

								gchar *str_dst_ports = g_strjoinv (",", strings);

								g_free (strings);

								gtk_tree_store_append (GTK_TREE_STORE (model), &iter4, &iter3);
								gtk_tree_store_set (GTK_TREE_STORE (model), &iter4,
										0, "dst_port",
										1, str_dst_ports,
										-1);

								g_free (str_dst_ports);
							}
						}
					}

					if (obj4) {
						const char *str_direction = json_object_get_string (obj4);
						gchar *direction = g_strdup (str_direction);

						gtk_tree_store_append (GTK_TREE_STORE (model), &iter2, &iter1);
						gtk_tree_store_set (GTK_TREE_STORE (model), &iter2,
								0, "direction",
								1, direction,
								-1);

						g_free (direction);
					}
				} // end of for
			}

			ret = TRUE;
		}
	} else if (g_str_equal (priv->resource, "bluetooth")) {
		json_object *bluetooth_obj = JSON_OBJECT_GET (root_obj, "bluetooth");
		if (bluetooth_obj) {
			GtkTreeIter iter;
			GtkTreeModel *model;
			model = gtk_tree_view_get_model (GTK_TREE_VIEW (priv->trv_resource));

			gtk_tree_view_column_set_title (GTK_TREE_VIEW_COLUMN (priv->trv_col_1), _("Mac Address"));
			gtk_tree_view_column_set_title (GTK_TREE_VIEW_COLUMN (priv->trv_col_2), _("Access Authority"));

			gchar *default_state = NULL;
			json_object *state_obj = JSON_OBJECT_GET (bluetooth_obj, "state");
			json_object *mac_addrs_obj = JSON_OBJECT_GET (bluetooth_obj, "mac_address");

			if (state_obj) {
				const char *str_state = json_object_get_string (state_obj);
				if (g_str_equal (str_state, "allow"))
					default_state = g_strdup (_("Allow"));
				else
					default_state = g_strdup (_("Disallow"));
			}

			gtk_tree_store_append (GTK_TREE_STORE (model), &iter, NULL);
			gtk_tree_store_set (GTK_TREE_STORE (model), &iter,
					0, _("default_bluetooth"),
					1, default_state,
					-1);

			if (mac_addrs_obj) {
				int i = 0, len = 0;
				len = json_object_array_length (mac_addrs_obj);
				for (i = 0; i < len; i++) {
					json_object *mac_addr_obj = json_object_array_get_idx (mac_addrs_obj, i);
					const char *mac_addr = json_object_get_string (mac_addr_obj);
					gtk_tree_store_append (GTK_TREE_STORE (model), &iter, NULL);
					gtk_tree_store_set (GTK_TREE_STORE (model), &iter,
							0, mac_addr,
							1, _("Allow"),
							-1);
				}
			}

			g_free (default_state);

			ret = TRUE;
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
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), RPDDialog, trv_col_1);
	gtk_widget_class_bind_template_child_private (GTK_WIDGET_CLASS (class), RPDDialog, trv_col_2);

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
