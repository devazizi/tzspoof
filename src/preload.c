#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* glibc declares path arguments nonnull; the NULL guards are kept anyway. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wpointer-bool-conversion"
#else
#pragma GCC diagnostic ignored "-Wnonnull-compare"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

/* Forward declarations for legacy glibc stat functions if headers omit them */
int __xstat(int ver, const char *path, struct stat *statbuf);
int __xstat64(int ver, const char *path, struct stat64 *statbuf);
int __lxstat(int ver, const char *path, struct stat *statbuf);
int __lxstat64(int ver, const char *path, struct stat64 *statbuf);
int __fxstat(int ver, int fd, struct stat *statbuf);
int __fxstat64(int ver, int fd, struct stat64 *statbuf);
int __fxstatat(int ver, int dirfd, const char *path, struct stat *statbuf, int flags);
int __fxstatat64(int ver, int dirfd, const char *path, struct stat64 *statbuf, int flags);

static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
static ssize_t (*real_readlink_chk)(const char *, char *, size_t, size_t) = NULL;
static ssize_t (*real_readlinkat)(int, const char *, char *, size_t) = NULL;
static ssize_t (*real_readlinkat_chk)(int, const char *, char *, size_t, size_t) = NULL;

static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static int (*real_openat64)(int, const char *, int, ...) = NULL;

static int (*real_stat)(const char *, struct stat *) = NULL;
static int (*real_stat64)(const char *, struct stat64 *) = NULL;
static int (*real_lstat)(const char *, struct stat *) = NULL;
static int (*real_lstat64)(const char *, struct stat64 *) = NULL;
static int (*real_fstat)(int, struct stat *) = NULL;
static int (*real_fstat64)(int, struct stat64 *) = NULL;
static int (*real_fstatat)(int, const char *, struct stat *, int) = NULL;
static int (*real_fstatat64)(int, const char *, struct stat64 *, int) = NULL;

static int (*real_xstat)(int, const char *, struct stat *) = NULL;
static int (*real_xstat64)(int, const char *, struct stat64 *) = NULL;
static int (*real_lxstat)(int, const char *, struct stat *) = NULL;
static int (*real_lxstat64)(int, const char *, struct stat64 *) = NULL;
static int (*real_fxstat)(int, int, struct stat *) = NULL;
static int (*real_fxstat64)(int, int, struct stat64 *) = NULL;
static int (*real_fxstatat)(int, int, const char *, struct stat *, int) = NULL;
static int (*real_fxstatat64)(int, int, const char *, struct stat64 *, int) = NULL;

static int (*real_statx)(int, const char *, int, unsigned int, struct statx *) = NULL;

/*
 * Inside an unprivileged user namespace, host root (and every other
 * unmapped ID) shows up as the overflow ID 65534. Tools such as ssh
 * reject root-owned config files that appear owned by "nobody", so the
 * hooks report 65534 as 0 there. Outside a user namespace (e.g. -e mode)
 * a 65534 owner is genuine and is passed through unchanged.
 */
static int in_userns = 0;

static void detect_userns(void) {
    /* The initial namespace maps the full range: "0 0 4294967295". */
    int fd = real_open ? real_open("/proc/self/uid_map", O_RDONLY | O_CLOEXEC) : -1;
    if (fd < 0) return;
    char buf[128] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    /*
     * Compare tokens as strings: sscanf/strtoul resolve to the
     * __isoc23_* symbols (GLIBC_2.38) on new toolchains, which breaks
     * programs that bundle an older libc (e.g. staticx binaries).
     */
    static const char *const init_map[] = {"0", "0", "4294967295"};
    char *p = buf;
    for (int i = 0; i < 3; i++) {
        p += strspn(p, " \t");
        size_t len = strcspn(p, " \t\n");
        if (len != strlen(init_map[i]) || strncmp(p, init_map[i], len) != 0) {
            in_userns = 1;
            return;
        }
        p += len;
    }
}

static void init_hooks(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;

    if (!real_readlink)       real_readlink       = dlsym(RTLD_NEXT, "readlink");
    if (!real_readlink_chk)   real_readlink_chk   = dlsym(RTLD_NEXT, "__readlink_chk");
    if (!real_readlinkat)     real_readlinkat     = dlsym(RTLD_NEXT, "readlinkat");
    if (!real_readlinkat_chk) real_readlinkat_chk = dlsym(RTLD_NEXT, "__readlinkat_chk");

    if (!real_open)           real_open           = dlsym(RTLD_NEXT, "open");
    if (!real_open64)         real_open64         = dlsym(RTLD_NEXT, "open64");
    if (!real_openat)         real_openat         = dlsym(RTLD_NEXT, "openat");
    if (!real_openat64)       real_openat64       = dlsym(RTLD_NEXT, "openat64");

    if (!real_stat)           real_stat           = dlsym(RTLD_NEXT, "stat");
    if (!real_stat64)         real_stat64         = dlsym(RTLD_NEXT, "stat64");
    if (!real_lstat)          real_lstat          = dlsym(RTLD_NEXT, "lstat");
    if (!real_lstat64)        real_lstat64        = dlsym(RTLD_NEXT, "lstat64");
    if (!real_fstat)          real_fstat          = dlsym(RTLD_NEXT, "fstat");
    if (!real_fstat64)        real_fstat64        = dlsym(RTLD_NEXT, "fstat64");
    if (!real_fstatat)        real_fstatat        = dlsym(RTLD_NEXT, "fstatat");
    if (!real_fstatat64)      real_fstatat64      = dlsym(RTLD_NEXT, "fstatat64");

    if (!real_xstat)          real_xstat          = dlsym(RTLD_NEXT, "__xstat");
    if (!real_xstat64)        real_xstat64        = dlsym(RTLD_NEXT, "__xstat64");
    if (!real_lxstat)         real_lxstat         = dlsym(RTLD_NEXT, "__lxstat");
    if (!real_lxstat64)       real_lxstat64       = dlsym(RTLD_NEXT, "__lxstat64");
    if (!real_fxstat)         real_fxstat         = dlsym(RTLD_NEXT, "__fxstat");
    if (!real_fxstat64)       real_fxstat64       = dlsym(RTLD_NEXT, "__fxstat64");
    if (!real_fxstatat)       real_fxstatat       = dlsym(RTLD_NEXT, "__fxstatat");
    if (!real_fxstatat64)     real_fxstatat64     = dlsym(RTLD_NEXT, "__fxstatat64");

    if (!real_statx)          real_statx          = dlsym(RTLD_NEXT, "statx");

    detect_userns();
}

static inline void fix_stat_buf(struct stat *buf) {
    if (buf && in_userns) {
        if (buf->st_uid == 65534) buf->st_uid = 0;
        if (buf->st_gid == 65534) buf->st_gid = 0;
    }
}

static inline void fix_stat64_buf(struct stat64 *buf) {
    if (buf && in_userns) {
        if (buf->st_uid == 65534) buf->st_uid = 0;
        if (buf->st_gid == 65534) buf->st_gid = 0;
    }
}

static inline void fix_statx_buf(struct statx *buf) {
    if (buf && in_userns) {
        if (buf->stx_uid == 65534) buf->stx_uid = 0;
        if (buf->stx_gid == 65534) buf->stx_gid = 0;
    }
}

/*
 * Helper to spoof readlink buffer. Callers use it only after the real
 * readlink succeeded, so a regular-file /etc/localtime keeps returning
 * EINVAL and stays consistent with lstat().
 */
static ssize_t do_spoof_readlink(char *buf, size_t bufsiz) {
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (!target || !*target) return -1;

    size_t len = strlen(target);
    if (len >= bufsiz) len = bufsiz;
    memcpy(buf, target, len);
    return (ssize_t)len;
}

ssize_t readlink(const char *pathname, char *buf, size_t bufsiz) {
    init_hooks();
    ssize_t res = real_readlink ? real_readlink(pathname, buf, bufsiz) : -1;
    if (res >= 0 && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        ssize_t spoofed = do_spoof_readlink(buf, bufsiz);
        if (spoofed >= 0) return spoofed;
    }
    return res;
}

ssize_t __readlink_chk(const char *pathname, char *buf, size_t bufsiz, size_t buflen) {
    init_hooks();
    ssize_t res = real_readlink_chk ? real_readlink_chk(pathname, buf, bufsiz, buflen) : -1;
    if (res >= 0 && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        ssize_t spoofed = do_spoof_readlink(buf, bufsiz);
        if (spoofed >= 0) return spoofed;
    }
    return res;
}

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    init_hooks();
    ssize_t res = real_readlinkat ? real_readlinkat(dirfd, pathname, buf, bufsiz) : -1;
    if (res >= 0 && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        ssize_t spoofed = do_spoof_readlink(buf, bufsiz);
        if (spoofed >= 0) return spoofed;
    }
    return res;
}

ssize_t __readlinkat_chk(int dirfd, const char *pathname, char *buf, size_t bufsiz, size_t buflen) {
    init_hooks();
    ssize_t res = real_readlinkat_chk ? real_readlinkat_chk(dirfd, pathname, buf, bufsiz, buflen) : -1;
    if (res >= 0 && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        ssize_t spoofed = do_spoof_readlink(buf, bufsiz);
        if (spoofed >= 0) return spoofed;
    }
    return res;
}

/* Open hooks fallback for environments without namespaces */
int open(const char *pathname, int flags, ...) {
    init_hooks();
    mode_t mode = 0;
    /* O_TMPFILE includes O_DIRECTORY, so test the whole mask. */
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & O_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
    }

    return real_open ? real_open(pathname, flags, mode) : -1;
}

int open64(const char *pathname, int flags, ...) {
    init_hooks();
    mode_t mode = 0;
    /* O_TMPFILE includes O_DIRECTORY, so test the whole mask. */
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & O_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
    }

    return real_open64 ? real_open64(pathname, flags, mode) : -1;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    init_hooks();
    mode_t mode = 0;
    /* O_TMPFILE includes O_DIRECTORY, so test the whole mask. */
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & O_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }

    return real_openat ? real_openat(dirfd, pathname, flags, mode) : -1;
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    init_hooks();
    mode_t mode = 0;
    /* O_TMPFILE includes O_DIRECTORY, so test the whole mask. */
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & O_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }

    return real_openat64 ? real_openat64(dirfd, pathname, flags, mode) : -1;
}

/* Stat hooks to redirect /etc/localtime and fix UID/GID in user namespaces */
int stat(const char *pathname, struct stat *buf) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
    }
    int res = real_stat ? real_stat(pathname, buf) : -1;
    if (res == 0) fix_stat_buf(buf);
    return res;
}

int stat64(const char *pathname, struct stat64 *buf) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
    }
    int res = real_stat64 ? real_stat64(pathname, buf) : -1;
    if (res == 0) fix_stat64_buf(buf);
    return res;
}

int lstat(const char *pathname, struct stat *buf) {
    init_hooks();
    int res = real_lstat ? real_lstat(pathname, buf) : -1;
    if (res == 0) fix_stat_buf(buf);
    return res;
}

int lstat64(const char *pathname, struct stat64 *buf) {
    init_hooks();
    int res = real_lstat64 ? real_lstat64(pathname, buf) : -1;
    if (res == 0) fix_stat64_buf(buf);
    return res;
}

int fstat(int fd, struct stat *buf) {
    init_hooks();
    int res = real_fstat ? real_fstat(fd, buf) : -1;
    if (res == 0) fix_stat_buf(buf);
    return res;
}

int fstat64(int fd, struct stat64 *buf) {
    init_hooks();
    int res = real_fstat64 ? real_fstat64(fd, buf) : -1;
    if (res == 0) fix_stat64_buf(buf);
    return res;
}

int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & AT_SYMLINK_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }
    int res = real_fstatat ? real_fstatat(dirfd, pathname, buf, flags) : -1;
    if (res == 0) fix_stat_buf(buf);
    return res;
}

int fstatat64(int dirfd, const char *pathname, struct stat64 *buf, int flags) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & AT_SYMLINK_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }
    int res = real_fstatat64 ? real_fstatat64(dirfd, pathname, buf, flags) : -1;
    if (res == 0) fix_stat64_buf(buf);
    return res;
}

int __xstat(int ver, const char *pathname, struct stat *buf) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
    }
    int res = real_xstat ? real_xstat(ver, pathname, buf) : -1;
    if (res == 0) fix_stat_buf(buf);
    return res;
}

int __xstat64(int ver, const char *pathname, struct stat64 *buf) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
    }
    int res = real_xstat64 ? real_xstat64(ver, pathname, buf) : -1;
    if (res == 0) fix_stat64_buf(buf);
    return res;
}

int __lxstat(int ver, const char *pathname, struct stat *buf) {
    init_hooks();
    int res = real_lxstat ? real_lxstat(ver, pathname, buf) : -1;
    if (res == 0) fix_stat_buf(buf);
    return res;
}

int __lxstat64(int ver, const char *pathname, struct stat64 *buf) {
    init_hooks();
    int res = real_lxstat64 ? real_lxstat64(ver, pathname, buf) : -1;
    if (res == 0) fix_stat64_buf(buf);
    return res;
}

int __fxstat(int ver, int fd, struct stat *buf) {
    init_hooks();
    int res = real_fxstat ? real_fxstat(ver, fd, buf) : -1;
    if (res == 0) fix_stat_buf(buf);
    return res;
}

int __fxstat64(int ver, int fd, struct stat64 *buf) {
    init_hooks();
    int res = real_fxstat64 ? real_fxstat64(ver, fd, buf) : -1;
    if (res == 0) fix_stat64_buf(buf);
    return res;
}

int __fxstatat(int ver, int dirfd, const char *pathname, struct stat *buf, int flags) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & AT_SYMLINK_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }
    int res = real_fxstatat ? real_fxstatat(ver, dirfd, pathname, buf, flags) : -1;
    if (res == 0) fix_stat_buf(buf);
    return res;
}

int __fxstatat64(int ver, int dirfd, const char *pathname, struct stat64 *buf, int flags) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & AT_SYMLINK_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }
    int res = real_fxstatat64 ? real_fxstatat64(ver, dirfd, pathname, buf, flags) : -1;
    if (res == 0) fix_stat64_buf(buf);
    return res;
}

/*
 * gettimeofday(tv, tz): the tz argument returns the kernel's sys_tz, which
 * systemd sets to the host's UTC offset when the RTC keeps local time
 * (/etc/adjtime: LOCAL). On UTC-RTC hosts it is 0 for every zone, so 0 is
 * passed through unchanged; a non-zero value is replaced with the spoofed
 * zone's current offset (minutes west of UTC, as the kernel reports it).
 */
struct tzspoof_timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

static int (*real_gettimeofday)(void *, void *) = NULL;

int gettimeofday(void *restrict tv, void *restrict tzp) {
    if (!real_gettimeofday) real_gettimeofday = (int (*)(void *, void *))dlsym(RTLD_NEXT, "gettimeofday");
    if (!real_gettimeofday) return -1;
    int res = real_gettimeofday(tv, tzp);
    struct tzspoof_timezone *tz = tzp;
    if (res == 0 && tz && tz->tz_minuteswest != 0 && getenv("TZSPOOF_TARGET_PATH")) {
        time_t now = time(NULL);
        struct tm tm;
        if (localtime_r(&now, &tm)) {
            tz->tz_minuteswest = (int)(-tm.tm_gmtoff / 60);
            tz->tz_dsttime = 0;
        }
    }
    return res;
}

int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *buf) {
    init_hooks();
    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && !(flags & AT_SYMLINK_NOFOLLOW) && pathname && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }
    int res = real_statx ? real_statx(dirfd, pathname, flags, mask, buf) : -1;
    if (res == 0) fix_statx_buf(buf);
    return res;
}
