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


#ifndef _COMMON_H_
#define _COMMON_H_


#include <glib.h>
#include <gio/gio.h>

#include <json-c/json.h>


G_BEGIN_DECLS

#define GOOROOM_SECURITY_LOGPARSER_SEEKTIME    "/var/tmp/GOOROOM-SECURITY-LOGPARSER-SEEKTIME"
#define GOOROOM_MANAGEMENT_SERVER_CONF         "/etc/gooroom/gooroom-client-server-register/gcsr.conf"
#define GOOROOM_AGENT_SERVICE_NAME             "gooroom-agent.service"

#define	DEFAULT_YEAR                            1970 
#define	DEFAULT_MONTH                           1
#define	DEFAULT_DAY                             1

#define LOG_LEVEL_DEBUG    (1 << 0)
#define LOG_LEVEL_INFO     (1 << 1)
#define LOG_LEVEL_NOTICE   (1 << 2)
#define LOG_LEVEL_WARNING  (1 << 3)
#define LOG_LEVEL_ERR      (1 << 4)
#define LOG_LEVEL_CRIT     (1 << 5)
#define LOG_LEVEL_ALERT    (1 << 6)
#define LOG_LEVEL_EMERG    (1 << 7)

#define SECURITY_ITEM_OS_RUN     (1 << 0)
#define SECURITY_ITEM_EXE_RUN    (1 << 1)
#define SECURITY_ITEM_BOOT_RUN   (1 << 2)
#define SECURITY_ITEM_MEDIA_RUN  (1 << 3)

enum {
	SECURITY_STATUS_SAFETY,
	SECURITY_STATUS_VULNERABLE,
	SECURITY_STATUS_UNKNOWN
};

enum {
    ACCOUNT_TYPE_LOCAL = 0,
    ACCOUNT_TYPE_GOOROOM,
    ACCOUNT_TYPE_GOOGLE,
    ACCOUNT_TYPE_NAVER,
    ACCOUNT_TYPE_UNKNOWN
};


json_object *JSON_OBJECT_GET                      (json_object *obj,
                                                   const gchar *key);

gboolean     is_local_user                        (void);
gboolean     is_admin_group                       (void);
gboolean     is_standalone_mode                   (void);
int          get_account_type                     (const char *user);

gboolean     run_security_log_parser_async        (gchar    *seektime,
                                                   GIOFunc   callback_func,
                                                   gpointer  data);

gboolean     authenticate                         (const gchar *action_id);

gboolean     is_systemd_service_active            (const gchar *service_name);

gboolean     is_systemd_service_available         (const gchar *service_name);

void         send_taking_measures_signal_to_agent (void);
void         send_taking_measure_signal_to_self   (void);


G_END_DECLS


#endif /* _COMMON_H */
