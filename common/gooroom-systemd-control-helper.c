/*
 * Copyright (C) 2013 Intel, Inc
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Author: Thomas Wood <thomas.wood@intel.com>
 *
 */

#include <gio/gio.h>


static char *opt_service       = NULL;
static gboolean opt_activate   = FALSE;
static gboolean opt_deactivate = FALSE;

static GOptionEntry options[] =
{
	{ "service",    's', 0, G_OPTION_ARG_STRING, &opt_service,    NULL, NULL },
	{ "activate",   'a', 0, G_OPTION_ARG_NONE,   &opt_activate,   NULL, NULL },
	{ "deactivate", 'd', 0, G_OPTION_ARG_NONE,   &opt_deactivate, NULL, NULL },
	{ NULL }
};


static gint
enable_service (const char *service)
{
  g_autoptr(GDBusConnection) connection = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) start_result = NULL;
  g_autoptr(GVariant) enable_result = NULL;

  connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
  if (!connection)
    {
      g_critical ("Error connecting to D-Bus system bus: %s", error->message);
      return 1;
    }

  const gchar *service_list[] = {service, NULL};

  enable_result = g_dbus_connection_call_sync (connection,
                                               "org.freedesktop.systemd1",
                                               "/org/freedesktop/systemd1",
                                               "org.freedesktop.systemd1.Manager",
                                               "EnableUnitFiles",
                                               g_variant_new ("(^asbb)", service_list, FALSE, FALSE),
                                               (GVariantType *) "(ba(sss))",
                                               G_DBUS_CALL_FLAGS_NONE,
                                               -1,
                                               NULL,
                                               &error);

  if (!enable_result)
    {
      g_critical ("Error enabling %s: %s", service, error->message);
      return 1;
    }

  start_result = g_dbus_connection_call_sync (connection,
                                              "org.freedesktop.systemd1",
                                              "/org/freedesktop/systemd1",
                                              "org.freedesktop.systemd1.Manager",
                                              "StartUnit",
                                              g_variant_new ("(ss)", service, "replace"),
                                              (GVariantType *) "(o)",
                                              G_DBUS_CALL_FLAGS_NONE,
                                              -1,
                                              NULL,
                                              &error);

  if (!start_result)
    {
      g_critical ("Error starting %s: %s", service, error->message);
      return 1;
    }

  return 0;
}

static gint
disable_service (const char *service)
{
  g_autoptr(GDBusConnection) connection = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) stop_result = NULL;
  g_autoptr(GVariant) disable_result = NULL;

  connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &error);
  if (!connection)
    {
      g_critical ("Error connecting to D-Bus system bus: %s", error->message);
      return 1;
    }

  stop_result = g_dbus_connection_call_sync (connection,
                                             "org.freedesktop.systemd1",
                                             "/org/freedesktop/systemd1",
                                             "org.freedesktop.systemd1.Manager",
                                             "StopUnit",
                                             g_variant_new ("(ss)", service, "replace"),
                                             (GVariantType *) "(o)",
                                             G_DBUS_CALL_FLAGS_NONE,
                                             -1,
                                             NULL,
                                             &error);
  if (!stop_result)
    {
      g_critical ("Error stopping %s: %s", service, error->message);
      return 1;
    }

  const gchar *service_list[] = {service, NULL};

  disable_result = g_dbus_connection_call_sync (connection,
                                                "org.freedesktop.systemd1",
                                                "/org/freedesktop/systemd1",
                                                "org.freedesktop.systemd1.Manager",
                                                "DisableUnitFiles",
                                                g_variant_new ("(^asb)", service_list, FALSE, FALSE),
                                                (GVariantType *) "(a(sss))",
                                                G_DBUS_CALL_FLAGS_NONE,
                                                -1,
                                                NULL,
                                                &error);

  if (!stop_result)
    {
      g_critical ("Error disabling %s: %s", service, error->message);
      return 1;
    }

  return 0;
}

int
main (int argc, char **argv)
{
	GOptionContext *context;

	context = g_option_context_new (NULL);
	g_option_context_add_main_entries (context, options, NULL);
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (opt_service) {
		if (opt_activate) {
			return enable_service (opt_service);
		}

		if (opt_deactivate) {
			return disable_service (opt_service);
		}
	}

	return 1;
}
