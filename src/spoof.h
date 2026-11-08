#ifndef SPOOF_H
#define SPOOF_H

#include "tzspoof.h"

/* Set up private user and mount namespaces, bind mount /etc/localtime and /etc/timezone */
bool spoof_setup_namespaces(const char *tz_canonical, const char *tz_path);

/* Configure environment variables ($TZ, $TZSPOOF_*, LD_PRELOAD) */
bool spoof_setup_environment(const char *tz_canonical, const char *tz_path, bool force_preload);

/* Execute either the interactive subshell or the specified command */
int spoof_execute(const tz_config_t *config, const tz_info_t *info, bool userns_active);

#endif /* SPOOF_H */
