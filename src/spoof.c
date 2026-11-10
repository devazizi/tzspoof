#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "spoof.h"
#include "tzutil.h"
#include "busproxy.h"
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

/*
 * New mount API (Linux >= 5.2). Raw syscalls keep the build working on
 * glibc < 2.36, which lacks the wrappers. The legacy mount(2) cannot be
 * used here: it always follows a symlink at the target, so bind mounting
 * over a symlinked /etc/localtime would overlay the host's real zone file
 * (e.g. /usr/share/zoneinfo/Asia/Tehran) for every process in the session.
 */
#include <sys/syscall.h>
#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_fsopen
#define SYS_fsopen 430
#endif
#ifndef SYS_fsconfig
#define SYS_fsconfig 431
#endif
#ifndef SYS_fsmount
#define SYS_fsmount 432
#endif
#define TZS_OPEN_TREE_CLONE        1
#define TZS_MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define TZS_FSOPEN_CLOEXEC         0x00000001
#define TZS_FSMOUNT_CLOEXEC        0x00000001
#define TZS_FSCONFIG_CMD_CREATE    6

static int sys_open_tree(int dfd, const char *path, unsigned int flags) {
    return (int)syscall(SYS_open_tree, dfd, path, flags);
}

/* Attach a detached mount fd at target without following a symlink there. */
static int attach_at(int src_fd, const char *target) {
    return (int)syscall(SYS_move_mount, src_fd, "", AT_FDCWD, target,
                        TZS_MOVE_MOUNT_F_EMPTY_PATH);
}

/* Clone path (relative to dfd) as a detached mount and attach it at target. */
static bool mount_over(int dfd, const char *path, unsigned int follow_flags, const char *target) {
    int src = sys_open_tree(dfd, path, TZS_OPEN_TREE_CLONE | O_CLOEXEC | follow_flags);
    if (src < 0) return false;
    int rc = attach_at(src, target);
    int saved = errno;
    close(src);
    errno = saved;
    return rc == 0;
}

#define MAX_ETC_FILE (1024 * 1024)

/* Read a small text file; returns a malloc'd NUL-terminated buffer or NULL. */
static char *read_small_file(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    char *buf = malloc(MAX_ETC_FILE + 1);
    size_t len = 0;
    ssize_t n = 0;
    while (buf && len < MAX_ETC_FILE && (n = read(fd, buf + len, MAX_ETC_FILE - len)) > 0) {
        len += (size_t)n;
    }
    close(fd);
    if (!buf || n < 0) { free(buf); return NULL; }
    buf[len] = '\0';
    return buf;
}

static bool write_scratch(int dir, const char *name, const char *content) {
    int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    size_t len = strlen(content);
    bool ok = write(fd, content, len) == (ssize_t)len;
    close(fd);
    return ok;
}

/*
 * /etc/hosts with "127.0.1.1 <name>" first, so forward and reverse
 * lookups of the spoofed name resolve locally (first match wins).
 */
static bool write_hosts(int dir, const char *hostname) {
    char *orig = read_small_file(HOSTS_FILE);
    if (!orig) return false;
    char *out = NULL;
    bool ok = asprintf(&out, "# tzspoof: spoofed hostname\n127.0.1.1\t%s\n%s", hostname, orig) >= 0 &&
              write_scratch(dir, "hosts", out);
    free(out);
    free(orig);
    return ok;
}

/*
 * nsswitch.conf with "files" moved to the front of the hosts: line.
 * Modules such as "resolve" (systemd-resolved) run outside the namespace
 * and would answer with the real hostname, or NOTFOUND-and-return for the
 * spoofed one, before /etc/hosts is ever consulted.
 */
static bool write_nsswitch(int dir) {
    char *orig = read_small_file(NSSWITCH_FILE);
    if (!orig) return false;
    size_t cap = strlen(orig) + 16;
    char *out = calloc(1, cap);
    if (!out) { free(orig); return false; }

    char *save = NULL;
    for (char *line = strtok_r(orig, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        const char *p = line + strspn(line, " \t");
        if (strncmp(p, "hosts:", 6) != 0) {
            strcat(out, line);
            strcat(out, "\n");
            continue;
        }
        strcat(out, "hosts: files");
        char *tsave = NULL;
        bool skip_action = false;
        for (char *tok = strtok_r((char *)p + 6, " \t", &tsave); tok; tok = strtok_r(NULL, " \t", &tsave)) {
            if (strcmp(tok, "files") == 0) { skip_action = true; continue; }
            if (skip_action && tok[0] == '[') continue; /* action bound to the old "files" */
            skip_action = false;
            strcat(out, " ");
            strcat(out, tok);
        }
        strcat(out, "\n");
    }
    bool ok = write_scratch(dir, "nsswitch.conf", out);
    free(out);
    free(orig);
    return ok;
}

/*
 * Private tmpfs that is never attached anywhere: it only holds the
 * replacement files. Nothing touches the host's /tmp, and files are never
 * unlinked (mounting over an unlinked file fails with ENOENT, which broke
 * nested sessions). Optional /etc files that do not exist are skipped.
 */
static int make_scratch_tmpfs(const char *tz_canonical, const char *tz_path, const char *hostname) {
    int fs = (int)syscall(SYS_fsopen, "tmpfs", TZS_FSOPEN_CLOEXEC);
    if (fs < 0) return -1;
    if (syscall(SYS_fsconfig, fs, TZS_FSCONFIG_CMD_CREATE, NULL, NULL, 0) != 0) {
        int saved = errno; close(fs); errno = saved;
        return -1;
    }
    int mnt = (int)syscall(SYS_fsmount, fs, TZS_FSMOUNT_CLOEXEC, 0);
    int saved = errno;
    close(fs);
    if (mnt < 0) { errno = saved; return -1; }

    if (symlinkat(tz_path, mnt, "localtime") != 0) goto fail;
    char line[256];
    snprintf(line, sizeof(line), "%s\n", tz_canonical);
    if (!write_scratch(mnt, "timezone", line)) goto fail;

    if (hostname) {
        snprintf(line, sizeof(line), "%s\n", hostname);
        if (!write_scratch(mnt, "hostname", line)) goto fail;
        /* Missing source files only mean there is nothing to replace. */
        if (!write_hosts(mnt, hostname) && errno != ENOENT) goto fail;
        if (!write_nsswitch(mnt) && errno != ENOENT) goto fail;
    }
    return mnt;

fail:
    saved = errno;
    close(mnt);
    errno = saved;
    return -1;
}

/* Replace target with scratch/name when both exist; warn (not fatal) on failure.
 * Returns true only if the replacement is in place. */
static bool replace_optional(int scratch, const char *name, const char *target, bool quiet) {
    if (faccessat(scratch, name, F_OK, AT_SYMLINK_NOFOLLOW) != 0 ||
        faccessat(AT_FDCWD, target, F_OK, AT_SYMLINK_NOFOLLOW) != 0) {
        return false;
    }
    if (!mount_over(scratch, name, 0, target)) {
        if (!quiet) {
            fprintf(stderr, "%s[!] Warning: could not replace %s (%s); it still shows the outer value.%s\n",
                    CLR_YELLOW, target, strerror(errno), CLR_RESET);
        }
        return false;
    }
    return true;
}

/*
 * Rewrite ZONE=/TIMEZONE= lines of a distribution clock config file
 * (/etc/sysconfig/clock, /etc/conf.d/clock) into scratch/name.
 * Returns false when the source does not exist or names no zone.
 */
static bool write_clock_config(int dir, const char *name, const char *src, const char *zone) {
    char *orig = read_small_file(src);
    if (!orig) return false;
    size_t cap = strlen(orig) + 64 + 2 * strlen(zone);
    char *out = calloc(1, cap);
    bool found = false;
    if (out) {
        char *save = NULL;
        for (char *line = strtok_r(orig, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
            const char *p = line + strspn(line, " \t");
            const char *keys[] = {"ZONE=", "TIMEZONE=", NULL};
            bool replaced = false;
            for (int k = 0; keys[k]; k++) {
                if (strncmp(p, keys[k], strlen(keys[k])) == 0) {
                    snprintf(out + strlen(out), cap - strlen(out), "%s\"%s\"\n", keys[k], zone);
                    replaced = found = true;
                    break;
                }
            }
            if (!replaced) snprintf(out + strlen(out), cap - strlen(out), "%s\n", line);
        }
    }
    bool ok = out && found && write_scratch(dir, name, out);
    free(out);
    free(orig);
    return ok;
}

bool spoof_setup_namespaces(const char *tz_canonical, const char *tz_path, const char *hostname,
                            bool fake_bus, bool quiet) {
    uid_t uid = getuid();
    gid_t gid = getgid();

    /* Unshare user and mount namespaces (plus UTS when spoofing the hostname) */
    int flags = CLONE_NEWUSER | CLONE_NEWNS | (hostname ? CLONE_NEWUTS : 0);
    if (unshare(flags) == -1) {
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

    /* The kernel hostname: uname(2), gethostname(), /proc/sys/kernel/hostname */
    if (hostname && sethostname(hostname, strlen(hostname)) != 0) {
        return false;
    }

    /* Make root mount hierarchy private so our bind mounts do not leak */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        return false;
    }

    int scratch = make_scratch_tmpfs(tz_canonical, tz_path, hostname);
    if (scratch < 0) return false;

    /*
     * Inspect /etc/localtime itself (no follow). Using an O_PATH fd from
     * open_tree() also bypasses an inherited libtzspoof.so stat hook.
     */
    struct stat st;
    int lt = sys_open_tree(AT_FDCWD, LOCALTIME_FILE, O_CLOEXEC | AT_SYMLINK_NOFOLLOW);
    if (lt < 0 || fstatat(lt, "", &st, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0) {
        int saved = errno;
        if (lt >= 0) close(lt);
        close(scratch);
        errno = saved;
        return false;
    }
    close(lt);

    /* Keep the host's file type: symlink stays a symlink, file stays a file. */
    bool ok = S_ISLNK(st.st_mode)
        ? mount_over(scratch, "localtime", AT_SYMLINK_NOFOLLOW, LOCALTIME_FILE)
        : mount_over(AT_FDCWD, tz_path, 0, LOCALTIME_FILE);
    if (!ok) {
        int saved = errno;
        close(scratch);
        errno = saved;
        return false;
    }

    /* Optional files; /etc/timezone exists mainly on Debian-family hosts. */
    replace_optional(scratch, "timezone", TIMEZONE_FILE, quiet);
    if (write_clock_config(scratch, "sysconfig-clock", SYSCONFIG_CLOCK, tz_canonical)) {
        replace_optional(scratch, "sysconfig-clock", SYSCONFIG_CLOCK, quiet);
    }
    if (write_clock_config(scratch, "confd-clock", CONFD_CLOCK, tz_canonical)) {
        replace_optional(scratch, "confd-clock", CONFD_CLOCK, quiet);
    }
    /* timedatectl & co. ask systemd-timedated over the system bus. */
    if (fake_bus && busproxy_prepare(scratch) &&
        !replace_optional(scratch, BUSPROXY_SOCKET_NAME, SYSTEM_BUS_SOCKET, quiet)) {
        busproxy_cancel();
    }
    if (hostname) {
        replace_optional(scratch, "hostname", HOSTNAME_FILE, quiet);
        replace_optional(scratch, "hosts", HOSTS_FILE, quiet);
        replace_optional(scratch, "nsswitch.conf", NSSWITCH_FILE, quiet);
    }

    close(scratch);
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

bool spoof_setup_environment(const char *tz_canonical, const char *tz_path, const char *hostname,
                             bool force_preload) {
    setenv("TZ", tz_canonical, 1);
    setenv("TZSPOOF_ACTIVE", "1", 1);
    setenv("TZSPOOF_ZONE", tz_canonical, 1);
    setenv("TZSPOOF_TARGET_PATH", tz_path, 1);
    if (hostname) {
        setenv("TZSPOOF_HOSTNAME", hostname, 1);
        /* Shells export HOSTNAME/HOST; refresh inherited copies. */
        setenv("HOSTNAME", hostname, 1);
        setenv("HOST", hostname, 1);
    }

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
            tz_print_banner(info, config->hostname[0] ? config->hostname : NULL, shell, userns_active);
        }

        char *shell_args[] = { (char *)shell, NULL };
        busproxy_start(info->canonical);
        execvp(shell, shell_args);

        perror("execvp (subshell)");
        return 1;
    }

    /* Execute custom command */
    busproxy_start(info->canonical);
    execvp(config->cmd_argv[0], config->cmd_argv);

    perror("execvp (command)");
    return 1;
}
