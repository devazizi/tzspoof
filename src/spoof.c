#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "spoof.h"
#include "tzutil.h"
#include <sched.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <pwd.h>
#include <libgen.h>

static bool write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return false;
    ssize_t len = (ssize_t)strlen(content);
    ssize_t written = write(fd, content, len);
    close(fd);
    return (written == len);
}

bool spoof_setup_namespaces(const char *tz_canonical, const char *tz_path) {
    uid_t uid = getuid();
    gid_t gid = getgid();

    /* Unshare user namespace and mount namespace */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == -1) {
        return false;
    }

    /* Disable setgroups for unprivileged gid_map write */
    write_file("/proc/self/setgroups", "deny");

    /* Map UID to same UID to preserve permissions and username */
    char map_buf[64];
    snprintf(map_buf, sizeof(map_buf), "%u %u 1\n", uid, uid);
    if (!write_file("/proc/self/uid_map", map_buf)) {
        return false;
    }

    /* Map GID to same GID */
    snprintf(map_buf, sizeof(map_buf), "%u %u 1\n", gid, gid);
    if (!write_file("/proc/self/gid_map", map_buf)) {
        return false;
    }

    /* Make root mount hierarchy private so our bind mounts do not leak */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        return false;
    }

    /* Bind mount the target timezone file over /etc/localtime */
    if (mount(tz_path, LOCALTIME_FILE, NULL, MS_BIND, NULL) == -1) {
        return false;
    }

    /* If /etc/timezone exists, bind mount a temporary file containing the canonical name */
    if (access(TIMEZONE_FILE, F_OK) == 0) {
        char tmppath[] = "/tmp/tzspoof_tz_XXXXXX";
        int tfd = mkstemp(tmppath);
        if (tfd >= 0) {
            dprintf(tfd, "%s\n", tz_canonical);
            close(tfd);
            mount(tmppath, TIMEZONE_FILE, NULL, MS_BIND, NULL);
            unlink(tmppath); /* Inode remains valid while mounted */
        }
    }

    return true;
}

static bool find_preload_lib(char *dest, size_t dest_size) {
    /* 1. Check relative to current binary */
    char exe_path[512] = {0};
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        char *dir = dirname(exe_path);
        snprintf(dest, dest_size, "%s/libtzspoof.so", dir);
        if (access(dest, R_OK) == 0) return true;

        /* Check ../lib/libtzspoof.so */
        snprintf(dest, dest_size, "%s/../lib/libtzspoof.so", dir);
        if (access(dest, R_OK) == 0) return true;
    }

    /* 2. Check standard system locations */
    const char *candidates[] = {
        "/usr/local/lib/libtzspoof.so",
        "/usr/lib/libtzspoof.so",
        "./libtzspoof.so",
        NULL
    };

    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], R_OK) == 0) {
            strncpy(dest, candidates[i], dest_size - 1);
            return true;
        }
    }

    return false;
}

bool spoof_setup_environment(const char *tz_canonical, const char *tz_path, bool force_preload) {
    setenv("TZ", tz_canonical, 1);
    setenv("TZSPOOF_ACTIVE", "1", 1);
    setenv("TZSPOOF_ZONE", tz_canonical, 1);
    setenv("TZSPOOF_TARGET_PATH", tz_path, 1);

    char lib_path[512] = {0};
    if (find_preload_lib(lib_path, sizeof(lib_path))) {
        const char *orig_preload = getenv("LD_PRELOAD");
        if (orig_preload && *orig_preload) {
            char new_preload[1024];
            snprintf(new_preload, sizeof(new_preload), "%s:%s", lib_path, orig_preload);
            setenv("LD_PRELOAD", new_preload, 1);
        } else {
            setenv("LD_PRELOAD", lib_path, 1);
        }
    } else if (force_preload) {
        fprintf(stderr, "%s[!] Warning: libtzspoof.so could not be found for LD_PRELOAD.%s\n",
                CLR_YELLOW, CLR_RESET);
    }

    return true;
}

int spoof_execute(const tz_config_t *config, const tz_info_t *info, bool userns_active) {
    if (config->interactive_shell || config->cmd_argc == 0) {
        /* Determine user shell */
        const char *shell = getenv("SHELL");
        if (!shell || !*shell) {
            struct passwd *pw = getpwuid(getuid());
            if (pw && pw->pw_shell && *pw->pw_shell) {
                shell = pw->pw_shell;
            } else {
                shell = "/bin/bash";
            }
        }

        if (!config->quiet) {
            tz_print_banner(info, shell, userns_active);
        }

        char *shell_args[] = { (char *)shell, NULL };
        execvp(shell, shell_args);

        perror("execvp (subshell)");
        return 1;
    }

    /* Execute custom command */
    execvp(config->cmd_argv[0], config->cmd_argv);

    perror("execvp (command)");
    return 1;
}
