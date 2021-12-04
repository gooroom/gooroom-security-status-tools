typedef struct _StackList StackList;

struct _StackList
{
    gchar *id;
    gchar *name;
    gchar *title;
    StackList *children;
};

StackList child0[] = {
    {"poicy-info", "page1", "Policy Info", NULL},
    {"resources-control", "page2", "Resources Control Policy", NULL},
    {"security", "page3", "Security", NULL},
    {"netwrok", "page4", "Network", NULL},
    {"notification", "page5", "Notification", NULL},
    {NULL}
};

StackList titles[] = {
    { "gpms", "page0", "Management Server", NULL },
    { NULL, NULL, "Policy", child0 },
    { "system-info", "page6", "System Info",NULL },
    { "log-info", "page7", "Log Info",NULL },
    { NULL }
};
