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

/*
 * Private tmpfs that is never attached anywhere: it only holds the
 * replacement symlink and /etc/timezone content. Nothing touches the
 * host's /tmp, and files are never unlinked (mounting over an unlinked
 * file fails with ENOENT, which broke nested sessions).
 */
static int make_scratch_tmpfs(const char *tz_canonical, const char *tz_path) {
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
    int fd = openat(mnt, "timezone", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) goto fail;
    dprintf(fd, "%s\n", tz_canonical);
    close(fd);
    return mnt;

fail:
    saved = errno;
    close(mnt);
    errno = saved;
    return -1;
}

bool spoof_setup_namespaces(const char *tz_canonical, const char *tz_path, bool quiet) {
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

    int scratch = make_scratch_tmpfs(tz_canonical, tz_path);
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

    /* /etc/timezone is optional (Debian-family); only replace it if present. */
    if (faccessat(AT_FDCWD, TIMEZONE_FILE, F_OK, AT_SYMLINK_NOFOLLOW) == 0 &&
        !mount_over(scratch, "timezone", 0, TIMEZONE_FILE) && !quiet) {
        fprintf(stderr, "%s[!] Warning: could not replace %s (%s); it still shows the outer zone.%s\n",
                CLR_YELLOW, TIMEZONE_FILE, strerror(errno), CLR_RESET);
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
