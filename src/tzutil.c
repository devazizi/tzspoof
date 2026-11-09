#include "tzutil.h"
#include <ftw.h>
#include <ctype.h>

struct tz_alias {
    const char *alias;
    const char *canonical;
};

static const struct tz_alias ALIASES[] = {
    {"utc",         "UTC"},
    {"gmt",         "GMT"},
    {"zulu",        "UTC"},
    {"tokyo",       "Asia/Tokyo"},
    {"japan",       "Asia/Tokyo"},
    {"london",      "Europe/London"},
    {"uk",          "Europe/London"},
    {"paris",       "Europe/Paris"},
    {"berlin",      "Europe/Berlin"},
    {"germany",     "Europe/Berlin"},
    {"amsterdam",   "Europe/Amsterdam"},
    {"rome",        "Europe/Rome"},
    {"madrid",      "Europe/Madrid"},
    {"zurich",      "Europe/Zurich"},
    {"stockholm",   "Europe/Stockholm"},
    {"oslo",        "Europe/Oslo"},
    {"helsinki",    "Europe/Helsinki"},
    {"warsaw",      "Europe/Warsaw"},
    {"prague",      "Europe/Prague"},
    {"vienna",      "Europe/Vienna"},
    {"brussels",    "Europe/Brussels"},
    {"athens",      "Europe/Athens"},
    {"istanbul",    "Europe/Istanbul"},
    {"moscow",      "Europe/Moscow"},
    {"ny",          "America/New_York"},
    {"nyc",         "America/New_York"},
    {"newyork",     "America/New_York"},
    {"new-york",    "America/New_York"},
    {"la",          "America/Los_Angeles"},
    {"losangeles",  "America/Los_Angeles"},
    {"los-angeles", "America/Los_Angeles"},
    {"chicago",     "America/Chicago"},
    {"denver",      "America/Denver"},
    {"phoenix",     "America/Phoenix"},
    {"toronto",     "America/Toronto"},
    {"vancouver",   "America/Vancouver"},
    {"montreal",    "America/Toronto"},
    {"saopaulo",    "America/Sao_Paulo"},
    {"sao-paulo",   "America/Sao_Paulo"},
    {"buenosaires", "America/Argentina/Buenos_Aires"},
    {"mexicocity",  "America/Mexico_City"},
    {"dubai",       "Asia/Dubai"},
    {"uae",         "Asia/Dubai"},
    {"tehran",      "Asia/Tehran"},
    {"iran",        "Asia/Tehran"},
    {"singapore",   "Asia/Singapore"},
    {"hongkong",    "Asia/Hong_Kong"},
    {"hong-kong",   "Asia/Hong_Kong"},
    {"seoul",       "Asia/Seoul"},
    {"korea",       "Asia/Seoul"},
    {"shanghai",    "Asia/Shanghai"},
    {"beijing",     "Asia/Shanghai"},
    {"china",       "Asia/Shanghai"},
    {"bangkok",     "Asia/Bangkok"},
    {"thailand",    "Asia/Bangkok"},
    {"jakarta",     "Asia/Jakarta"},
    {"kualalumpur", "Asia/Kuala_Lumpur"},
    {"delhi",       "Asia/Kolkata"},
    {"kolkata",     "Asia/Kolkata"},
    {"mumbai",      "Asia/Kolkata"},
    {"india",       "Asia/Kolkata"},
    {"sydney",      "Australia/Sydney"},
    {"melbourne",   "Australia/Melbourne"},
    {"brisbane",    "Australia/Brisbane"},
    {"perth",       "Australia/Perth"},
    {"auckland",    "Pacific/Auckland"},
    {"cairo",       "Africa/Cairo"},
    {"johannesburg","Africa/Johannesburg"},
    {NULL, NULL}
};

static bool is_valid_tzfile(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;

    /* Verify TZif magic header */
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;

    char magic[4];
    size_t n = fread(magic, 1, 4, fp);
    fclose(fp);

    return (n == 4 && memcmp(magic, "TZif", 4) == 0);
}

bool tz_populate_info(const char *canonical, const char *full_path, tz_info_t *info) {
    if (!canonical || !full_path || !info) return false;

    memset(info, 0, sizeof(*info));
    strncpy(info->canonical, canonical, sizeof(info->canonical) - 1);
    strncpy(info->full_path, full_path, sizeof(info->full_path) - 1);

    /* Save original TZ */
    const char *orig_tz = getenv("TZ");
    char orig_tz_backup[256] = {0};
    if (orig_tz) {
        strncpy(orig_tz_backup, orig_tz, sizeof(orig_tz_backup) - 1);
    }

    setenv("TZ", canonical, 1);
    tzset();

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);

    strftime(info->tz_abbr, sizeof(info->tz_abbr), "%Z", &tm_buf);
    strftime(info->utc_offset, sizeof(info->utc_offset), "%z", &tm_buf);
    strftime(info->formatted_time, sizeof(info->formatted_time), "%a %b %d %Y %H:%M:%S", &tm_buf);

    /* Restore original TZ */
    if (orig_tz) {
        setenv("TZ", orig_tz_backup, 1);
    } else {
        unsetenv("TZ");
    }
    tzset();

    info->valid = true;
    return true;
}

/* NFTW context for timezone search */
#define MAX_SEARCH_MATCHES 32
static char s_search_query[256];
static char s_found_canonical[MAX_SEARCH_MATCHES][128];
static char s_found_path[MAX_SEARCH_MATCHES][256];
static int  s_match_count = 0;

static int search_nftw_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;

    if (typeflag != FTW_F && typeflag != FTW_SL) return 0;

    const char *rel = fpath + strlen(ZONEINFO_DIR) + 1;
    if (strncmp(rel, "posix/", 6) == 0 ||
        strncmp(rel, "right/", 6) == 0 ||
        strncmp(rel, "SystemV/", 8) == 0 ||
        strstr(rel, ".tab") != NULL ||
        strstr(rel, ".list") != NULL ||
        strcmp(rel, "localtime") == 0) {
        return 0;
    }

    /* Check match against query */
    bool match = false;

    /* 1. Exact case-insensitive match */
    if (strcasecmp(rel, s_search_query) == 0) {
        match = true;
    } else {
        /* 2. Suffix match: e.g. "Tokyo" matches "Asia/Tokyo" */
        const char *slash = strrchr(rel, '/');
        const char *base = slash ? slash + 1 : rel;
        if (strcasecmp(base, s_search_query) == 0) {
            match = true;
        } else if (strcasestr(rel, s_search_query) != NULL) {
            match = true;
        }
    }

    if (match && is_valid_tzfile(fpath)) {
        if (s_match_count < MAX_SEARCH_MATCHES) {
            strncpy(s_found_canonical[s_match_count], rel, sizeof(s_found_canonical[0]) - 1);
            strncpy(s_found_path[s_match_count], fpath, sizeof(s_found_path[0]) - 1);
            s_match_count++;
        }
    }

    return 0;
}

bool tz_resolve(const char *input, tz_info_t *info) {
    if (!input || !*input || !info) return false;

    char cleaned[128] = {0};
    strncpy(cleaned, input, sizeof(cleaned) - 1);

    /* Remove leading/trailing spaces */
    char *start = cleaned;
    while (isspace((unsigned char)*start)) start++;
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    /* 1. Check alias table */
    for (int i = 0; ALIASES[i].alias != NULL; i++) {
        if (strcasecmp(start, ALIASES[i].alias) == 0) {
            char path[256];
            snprintf(path, sizeof(path), "%s/%s", ZONEINFO_DIR, ALIASES[i].canonical);
            if (is_valid_tzfile(path)) {
                return tz_populate_info(ALIASES[i].canonical, path, info);
            }
        }
    }

    /* 2. Check direct path under /usr/share/zoneinfo */
    char direct_path[256];
    if (start[0] == '/') {
        strncpy(direct_path, start, sizeof(direct_path) - 1);
    } else {
        snprintf(direct_path, sizeof(direct_path), "%s/%s", ZONEINFO_DIR, start);
    }

    if (is_valid_tzfile(direct_path)) {
        const char *canon = (strncmp(direct_path, ZONEINFO_DIR "/", strlen(ZONEINFO_DIR) + 1) == 0)
                            ? direct_path + strlen(ZONEINFO_DIR) + 1
                            : direct_path;
        return tz_populate_info(canon, direct_path, info);
    }

    /* 3. Search via NFTW */
    s_match_count = 0;
    strncpy(s_search_query, start, sizeof(s_search_query) - 1);
    nftw(ZONEINFO_DIR, search_nftw_cb, 20, FTW_PHYS);

    if (s_match_count == 1) {
        return tz_populate_info(s_found_canonical[0], s_found_path[0], info);
    } else if (s_match_count > 1) {
        /* Check for an exact basename match among the results */
        for (int i = 0; i < s_match_count; i++) {
            const char *slash = strrchr(s_found_canonical[i], '/');
            const char *base = slash ? slash + 1 : s_found_canonical[i];
            if (strcasecmp(base, start) == 0) {
                return tz_populate_info(s_found_canonical[i], s_found_path[i], info);
            }
        }

        fprintf(stderr, "%s[!] Ambiguous timezone '%s'. Multiple matches found:%s\n",
                CLR_YELLOW, start, CLR_RESET);
        for (int i = 0; i < s_match_count && i < 10; i++) {
            fprintf(stderr, "    - %s\n", s_found_canonical[i]);
        }
        if (s_match_count > 10) {
            fprintf(stderr, "    ... and %d more. Use 'tzspoof -l' to view all.\n", s_match_count - 10);
        }
        return false;
    }

    fprintf(stderr, "%s[-] Timezone '%s' not found.%s Use 'tzspoof -l' to search available zones.\n",
            CLR_RED, start, CLR_RESET);
    return false;
}

/* NFTW callback for listing */
static const char *s_list_filter = NULL;
static int s_list_total = 0;

static int list_nftw_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;

    if (typeflag != FTW_F && typeflag != FTW_SL) return 0;

    const char *rel = fpath + strlen(ZONEINFO_DIR) + 1;
    if (strncmp(rel, "posix/", 6) == 0 ||
        strncmp(rel, "right/", 6) == 0 ||
        strncmp(rel, "SystemV/", 8) == 0 ||
        strstr(rel, ".tab") != NULL ||
        strstr(rel, ".list") != NULL ||
        strcmp(rel, "localtime") == 0) {
        return 0;
    }

    if (s_list_filter && *s_list_filter) {
        if (strcasestr(rel, s_list_filter) == NULL) {
            return 0;
        }
    }

    if (is_valid_tzfile(fpath)) {
        printf("  %-38s", rel);
        s_list_total++;
        if (s_list_total % 2 == 0) {
            printf("\n");
        }
    }

    return 0;
}

void tz_list(const char *filter) {
    s_list_filter = filter;
    s_list_total = 0;

    printf("\n%s%sAvailable Timezones%s", CLR_BOLD, CLR_CYAN, CLR_RESET);
    if (filter && *filter) {
        printf(" (matching '%s%s%s')", CLR_YELLOW, filter, CLR_RESET);
    }
    printf(":\n%s────────────────────────────────────────────────────────────────────────────%s\n",
           CLR_DIM, CLR_RESET);

    nftw(ZONEINFO_DIR, list_nftw_cb, 20, FTW_PHYS);

    if (s_list_total % 2 != 0) {
        printf("\n");
    }

    printf("%s────────────────────────────────────────────────────────────────────────────%s\n",
           CLR_DIM, CLR_RESET);
    printf("Total matching zones: %s%d%s\n\n", CLR_GREEN, s_list_total, CLR_RESET);
}

bool tz_get_current(tz_info_t *info) {
    if (!info) return false;

    /* 1. Try reading $TZ */
    const char *env_tz = getenv("TZ");
    if (env_tz && *env_tz) {
        char direct[256];
        snprintf(direct, sizeof(direct), "%s/%s", ZONEINFO_DIR, env_tz);
        if (is_valid_tzfile(direct)) {
            return tz_populate_info(env_tz, direct, info);
        }
    }

    /* 2. Try reading /etc/localtime symlink */
    char link_dest[512] = {0};
    ssize_t len = readlink(LOCALTIME_FILE, link_dest, sizeof(link_dest) - 1);
    if (len > 0) {
        link_dest[len] = '\0';
        const char *zone_prefix = ZONEINFO_DIR "/";
        const char *found = strstr(link_dest, zone_prefix);
        if (found) {
            const char *canon = found + strlen(zone_prefix);
            char full[512];
            snprintf(full, sizeof(full), "%s/%s", ZONEINFO_DIR, canon);
            return tz_populate_info(canon, full, info);
        }
    }

    /* 3. Try reading /etc/timezone */
    FILE *fp = fopen(TIMEZONE_FILE, "r");
    if (fp) {
        char buf[128] = {0};
        if (fgets(buf, sizeof(buf), fp)) {
            char *nl = strchr(buf, '\n');
            if (nl) *nl = '\0';
            fclose(fp);
            char full[256];
            snprintf(full, sizeof(full), "%s/%s", ZONEINFO_DIR, buf);
            if (is_valid_tzfile(full)) {
                return tz_populate_info(buf, full, info);
            }
        } else {
            fclose(fp);
        }
    }

    /* 4. Fallback to generic localtime */
    return tz_populate_info("System Default", LOCALTIME_FILE, info);
}

/* Banner row with exact 72-column inner padding (a plain static function:
 * GCC nested functions do not compile with Clang). */
static void print_row(const char *label, const char *val, const char *color) {
    int vis_len = 2 + (int)strlen(label) + (int)strlen(val);
    if (strstr(label, "•")) vis_len -= 2; /* Adjust for 3-byte UTF-8 bullet occupying 1 column */
    int pad = 72 - vis_len;
    if (pad < 1) pad = 1;
    printf("%s│%s  %s%s%s%s", CLR_CYAN, CLR_RESET, label, color, val, CLR_RESET);
    for (int p = 0; p < pad; p++) putchar(' ');
    printf("%s│%s\n", CLR_CYAN, CLR_RESET);
}

void tz_print_banner(const tz_info_t *info, const char *shell_path, bool userns_active) {
    bool tty = isatty(STDOUT_FILENO);

    if (tty) {
        char line_time[128];
        snprintf(line_time, sizeof(line_time), "%s %s (UTC%s)",
                 info->formatted_time, info->tz_abbr, info->utc_offset);

        const char *iso_text = userns_active
            ? "Linux Mount & User Namespaces (/etc/localtime bind)"
            : "Environment & Preload Hook Only";

        printf("\n%s╭────────────────────────────────────────────────────────────────────────╮%s\n",
               CLR_CYAN, CLR_RESET);

        print_row("tzspoof v" TZSPOOF_VERSION " - Timezone Spoofing Active", "", CLR_BOLD CLR_GREEN);
        printf("%s├────────────────────────────────────────────────────────────────────────┤%s\n",
               CLR_CYAN, CLR_RESET);

        print_row("• Target Zone : ", info->canonical, CLR_BOLD);
        print_row("• Local Time  : ", line_time, CLR_YELLOW);
        print_row("• Isolation   : ", iso_text, CLR_BLUE);
        print_row("• Subshell    : ", shell_path, CLR_MAGENTA);

        printf("%s├────────────────────────────────────────────────────────────────────────┤%s\n",
               CLR_CYAN, CLR_RESET);
        print_row("Tip: Type 'exit' or press Ctrl+D to return to original shell.", "", CLR_DIM);
        printf("%s╰────────────────────────────────────────────────────────────────────────╯%s\n\n",
               CLR_CYAN, CLR_RESET);
    } else {
        fprintf(stderr, "[*] tzspoof: Target Zone: %s (%s, UTC%s)\n",
                info->canonical, info->tz_abbr, info->utc_offset);
    }
}
