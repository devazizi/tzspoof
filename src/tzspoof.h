#ifndef TZSPOOF_H
#define TZSPOOF_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#define TZSPOOF_VERSION "1.0.0"
#define ZONEINFO_DIR    "/usr/share/zoneinfo"
#define LOCALTIME_FILE  "/etc/localtime"
#define TIMEZONE_FILE   "/etc/timezone"
#define HOSTNAME_FILE   "/etc/hostname"
#define HOSTS_FILE      "/etc/hosts"
#define NSSWITCH_FILE   "/etc/nsswitch.conf"
/* Distribution clock settings naming the zone (RHEL/SUSE, OpenRC). */
#define SYSCONFIG_CLOCK "/etc/sysconfig/clock"
#define CONFD_CLOCK     "/etc/conf.d/clock"
#define TZS_HOST_NAME_MAX 64

/* ANSI Colors */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[2m"
#define CLR_RED     "\033[31m"
#define CLR_GREEN   "\033[32m"
#define CLR_YELLOW  "\033[33m"
#define CLR_BLUE    "\033[34m"
#define CLR_MAGENTA "\033[35m"
#define CLR_CYAN    "\033[36m"
#define CLR_WHITE   "\033[37m"

typedef struct {
    char canonical[128];     /* e.g. "Asia/Tokyo" */
    char full_path[256];     /* e.g. "/usr/share/zoneinfo/Asia/Tokyo" */
    char tz_abbr[16];        /* e.g. "JST" */
    char utc_offset[16];     /* e.g. "+0900" */
    char formatted_time[64]; /* e.g. "Fri Nov 06 17:05:00 JST 2026" */
    bool valid;
} tz_info_t;

typedef struct {
    char target_zone[128];
    char hostname[TZS_HOST_NAME_MAX + 1]; /* empty: keep the real hostname */
    bool no_bus;                          /* do not fake org.freedesktop.timedate1 */
    bool hide_logs;                       /* mask /var/log and /run/log (hostname in every entry) */
    bool interactive_shell;
    bool quiet;
    bool env_only;
    bool force_preload;
    char **cmd_argv;
    int cmd_argc;
} tz_config_t;

#endif /* TZSPOOF_H */
