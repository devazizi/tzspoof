#include "tzspoof.h"
#include "tzutil.h"
#include "spoof.h"
#include <getopt.h>

static void print_version(void) {
    printf("tzspoof version %s (Linux namespaces & environment spoofing engine)\n", TZSPOOF_VERSION);
}

static void print_help(const char *progname) {
    printf("%s%stzspoof v%s — High-Fidelity Timezone Spoofing Utility for Linux%s\n\n",
           CLR_BOLD, CLR_CYAN, TZSPOOF_VERSION, CLR_RESET);

    printf("%sUSAGE:%s\n", CLR_BOLD, CLR_RESET);
    printf("  %s [OPTIONS] <TIMEZONE> [--] [COMMAND [ARGS...]]\n", progname);
    printf("  %s -l, --list [FILTER]\n", progname);
    printf("  %s -c, --current\n", progname);
    printf("  %s -h, --help\n\n", progname);

    printf("%sDESCRIPTION:%s\n", CLR_BOLD, CLR_RESET);
    printf("  Spawns an interactive shell or executes commands within an isolated timezone\n"
           "  environment using unprivileged Linux User & Mount Namespaces (bind mounting\n"
           "  over /etc/localtime and /etc/timezone) without modifying the host system.\n\n");

    printf("%sARGUMENTS:%s\n", CLR_BOLD, CLR_RESET);
    printf("  %s<TIMEZONE>%s              Target timezone name or alias (e.g. UTC, Asia/Tokyo,\n"
           "                         Europe/London, tokyo, london, ny, berlin, tehran)\n",
           CLR_GREEN, CLR_RESET);
    printf("  %s[COMMAND [ARGS...]]%s     Optional command to execute. If omitted, drops into\n"
           "                         an interactive subshell ($SHELL or /bin/bash).\n\n",
           CLR_GREEN, CLR_RESET);

    printf("%sOPTIONS:%s\n", CLR_BOLD, CLR_RESET);
    printf("  %s-s, --shell%s             Explicitly spawn an interactive shell (default if no cmd)\n",
           CLR_GREEN, CLR_RESET);
    printf("  %s-l, --list [FILTER]%s     List available system timezones with optional filter\n",
           CLR_GREEN, CLR_RESET);
    printf("  %s-c, --current%s           Display current active timezone and local time\n",
           CLR_GREEN, CLR_RESET);
    printf("  %s-q, --quiet%s             Quiet mode (suppress banners and informational messages)\n",
           CLR_GREEN, CLR_RESET);
    printf("  %s-e, --env-only%s          Skip Linux namespaces; only use $TZ and LD_PRELOAD\n",
           CLR_GREEN, CLR_RESET);
    printf("  %s-p, --preload%s           Force loading of libtzspoof.so preload hook\n",
           CLR_GREEN, CLR_RESET);
    printf("  %s-v, --version%s           Show version information\n",
           CLR_GREEN, CLR_RESET);
    printf("  %s-h, --help%s              Show this help menu\n\n",
           CLR_GREEN, CLR_RESET);

    printf("%sPOPULAR ALIASES:%s\n", CLR_BOLD, CLR_RESET);
    printf("  utc, gmt, tokyo, japan, london, uk, paris, berlin, amsterdam, ny, newyork,\n"
           "  la, losangeles, chicago, toronto, vancouver, dubai, tehran, singapore,\n"
           "  hongkong, seoul, shanghai, sydney, melbourne, cairo\n\n");

    printf("%sEXAMPLES:%s\n", CLR_BOLD, CLR_RESET);
    printf("  # Spawn an interactive subshell in Tokyo timezone:\n");
    printf("  $ %s tokyo\n\n", progname);
    printf("  # Run a specific command in London timezone:\n");
    printf("  $ %s london date\n\n", progname);
    printf("  # Run a python script in New York timezone:\n");
    printf("  $ %s ny python3 -c \"import time; print(time.tzname)\"\n\n", progname);
    printf("  # Search available European timezones:\n");
    printf("  $ %s -l Europe\n\n", progname);
    printf("  # Check current active timezone:\n");
    printf("  $ %s -c\n\n", progname);
}

static void show_current(void) {
    tz_info_t info;
    if (!tz_get_current(&info)) {
        fprintf(stderr, "%s[-] Failed to determine current timezone.%s\n", CLR_RED, CLR_RESET);
        return;
    }

    const char *active = getenv("TZSPOOF_ACTIVE");
    printf("\n%s%sCurrent Timezone Status:%s\n", CLR_BOLD, CLR_CYAN, CLR_RESET);
    printf("  • Timezone    : %s%s%s\n", CLR_BOLD, info.canonical, CLR_RESET);
    printf("  • Local Time  : %s%s %s (UTC%s)%s\n",
           CLR_YELLOW, info.formatted_time, info.tz_abbr, info.utc_offset, CLR_RESET);
    printf("  • Source Path : %s%s%s\n", CLR_DIM, info.full_path, CLR_RESET);
    if (active && strcmp(active, "1") == 0) {
        const char *zone = getenv("TZSPOOF_ZONE");
        printf("  • Spoof State : %sACTIVE%s (Target: %s)\n", CLR_GREEN, CLR_RESET, zone ? zone : "unknown");
    } else {
        printf("  • Spoof State : %sINACTIVE%s (Native Host)\n", CLR_DIM, CLR_RESET);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    tz_config_t config;
    memset(&config, 0, sizeof(config));

    static struct option long_options[] = {
        {"help",       no_argument,       0, 'h'},
        {"version",    no_argument,       0, 'v'},
        {"list",       optional_argument, 0, 'l'},
        {"current",    no_argument,       0, 'c'},
        {"shell",      no_argument,       0, 's'},
        {"quiet",      no_argument,       0, 'q'},
        {"env-only",   no_argument,       0, 'e'},
        {"preload",    no_argument,       0, 'p'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "+hvcl::sqep", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            case 'l': {
                const char *filter = optarg;
                if (!filter && optind < argc && argv[optind][0] != '-') {
                    filter = argv[optind++];
                }
                tz_list(filter);
                return 0;
            }
            case 'c':
                show_current();
                return 0;
            case 's':
                config.interactive_shell = true;
                break;
            case 'q':
                config.quiet = true;
                break;
            case 'e':
                config.env_only = true;
                break;
            case 'p':
                config.force_preload = true;
                break;
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "%s[-] Error: Target timezone required.%s\n\n", CLR_RED, CLR_RESET);
        print_help(argv[0]);
        return 1;
    }

    const char *target_tz = argv[optind++];
    strncpy(config.target_zone, target_tz, sizeof(config.target_zone) - 1);

    /* Check if remaining arguments exist */
    if (optind < argc) {
        if (strcmp(argv[optind], "--") == 0) {
            optind++;
        }
        if (optind < argc) {
            config.cmd_argv = &argv[optind];
            config.cmd_argc = argc - optind;
        }
    }

    /* Resolve timezone */
    tz_info_t info;
    if (!tz_resolve(config.target_zone, &info)) {
        return 1;
    }

    /* Warn if nested spoofing */
    if (!config.quiet && getenv("TZSPOOF_ACTIVE") != NULL) {
        fprintf(stderr, "%s[!] Notice: You are already inside a tzspoof session. Nesting new timezone: %s%s\n",
                CLR_YELLOW, info.canonical, CLR_RESET);
    }

    /* Setup namespaces if not env-only */
    bool userns_active = false;
    if (!config.env_only) {
        if (spoof_setup_namespaces(info.canonical, info.full_path, config.quiet)) {
            userns_active = true;
        } else {
            if (!config.quiet) {
                fprintf(stderr, "%s[!] Warning: Linux namespace isolation unavailable (%s); falling back to environment mode.%s\n",
                        CLR_YELLOW, strerror(errno), CLR_RESET);
            }
        }
    }

    /* Setup environment variables and LD_PRELOAD */
    spoof_setup_environment(info.canonical, info.full_path, config.force_preload);

    /* Execute shell or command */
    return spoof_execute(&config, &info, userns_active);
}
