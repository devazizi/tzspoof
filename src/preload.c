#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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

static ssize_t (*real_readlink)(const char *, char *, size_t) = NULL;
static ssize_t (*real_readlink_chk)(const char *, char *, size_t, size_t) = NULL;
static ssize_t (*real_readlinkat)(int, const char *, char *, size_t) = NULL;
static ssize_t (*real_readlinkat_chk)(int, const char *, char *, size_t, size_t) = NULL;

static int (*real_open)(const char *, int, ...) = NULL;
static int (*real_open64)(const char *, int, ...) = NULL;
static int (*real_openat)(int, const char *, int, ...) = NULL;
static int (*real_openat64)(int, const char *, int, ...) = NULL;

static void init_hooks(void) {
    if (!real_readlink)     real_readlink     = dlsym(RTLD_NEXT, "readlink");
    if (!real_readlink_chk) real_readlink_chk = dlsym(RTLD_NEXT, "__readlink_chk");
    if (!real_readlinkat)   real_readlinkat   = dlsym(RTLD_NEXT, "readlinkat");
    if (!real_readlinkat_chk) real_readlinkat_chk = dlsym(RTLD_NEXT, "__readlinkat_chk");

    if (!real_open)         real_open         = dlsym(RTLD_NEXT, "open");
    if (!real_open64)       real_open64       = dlsym(RTLD_NEXT, "open64");
    if (!real_openat)       real_openat       = dlsym(RTLD_NEXT, "openat");
    if (!real_openat64)     real_openat64     = dlsym(RTLD_NEXT, "openat64");
}

/* Helper to spoof readlink buffer */
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
    if (strcmp(pathname, "/etc/localtime") == 0) {
        ssize_t res = do_spoof_readlink(buf, bufsiz);
        if (res >= 0) return res;
    }
    return real_readlink ? real_readlink(pathname, buf, bufsiz) : -1;
}

ssize_t __readlink_chk(const char *pathname, char *buf, size_t bufsiz, size_t buflen) {
    init_hooks();
    if (strcmp(pathname, "/etc/localtime") == 0) {
        ssize_t res = do_spoof_readlink(buf, bufsiz);
        if (res >= 0) return res;
    }
    return real_readlink_chk ? real_readlink_chk(pathname, buf, bufsiz, buflen) : -1;
}

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    init_hooks();
    if (strcmp(pathname, "/etc/localtime") == 0) {
        ssize_t res = do_spoof_readlink(buf, bufsiz);
        if (res >= 0) return res;
    }
    return real_readlinkat ? real_readlinkat(dirfd, pathname, buf, bufsiz) : -1;
}

ssize_t __readlinkat_chk(int dirfd, const char *pathname, char *buf, size_t bufsiz, size_t buflen) {
    init_hooks();
    if (strcmp(pathname, "/etc/localtime") == 0) {
        ssize_t res = do_spoof_readlink(buf, bufsiz);
        if (res >= 0) return res;
    }
    return real_readlinkat_chk ? real_readlinkat_chk(dirfd, pathname, buf, bufsiz, buflen) : -1;
}

/* Open hooks fallback for environments without namespaces */
int open(const char *pathname, int flags, ...) {
    init_hooks();
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
    }

    return real_open ? real_open(pathname, flags, mode) : -1;
}

int open64(const char *pathname, int flags, ...) {
    init_hooks();
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
    }

    return real_open64 ? real_open64(pathname, flags, mode) : -1;
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    init_hooks();
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }

    return real_openat ? real_openat(dirfd, pathname, flags, mode) : -1;
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    init_hooks();
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char *target = getenv("TZSPOOF_TARGET_PATH");
    if (target && strcmp(pathname, "/etc/localtime") == 0) {
        pathname = target;
        dirfd = AT_FDCWD;
    }

    return real_openat64 ? real_openat64(dirfd, pathname, flags, mode) : -1;
}
