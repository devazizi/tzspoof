#ifndef TZUTIL_H
#define TZUTIL_H

#include "tzspoof.h"

/* Resolve user input (alias, relative, or city) to canonical timezone info */
bool tz_resolve(const char *input, tz_info_t *info);

/* Populate time, abbreviation, and offset for an already identified canonical zone */
bool tz_populate_info(const char *canonical, const char *full_path, tz_info_t *info);

/* Collect all zone names (malloc'd); returns the count. */
size_t tz_collect(char ***out);
void tz_collect_free(char **zones, size_t n);

/* List available timezones with optional filter */
void tz_list(const char *filter);

/* Retrieve current system/session timezone */
bool tz_get_current(tz_info_t *info);

/* Render nice terminal banner */
void tz_print_banner(const tz_info_t *info, const char *hostname, const char *shell_path,
                     bool userns_active);

#endif /* TZUTIL_H */
