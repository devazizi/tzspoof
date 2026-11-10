#ifndef BUSPROXY_H
#define BUSPROXY_H

#include "tzspoof.h"

#define SYSTEM_BUS_SOCKET "/run/dbus/system_bus_socket"
#define BUSPROXY_SOCKET_NAME "system_bus_socket"

/*
 * System D-Bus filtering proxy.
 *
 * timedatectl and other D-Bus clients ask systemd-timedated, which runs
 * outside the namespace and reports the host's real zone. The proxy sits
 * on the session's /run/dbus/system_bus_socket, answers
 * org.freedesktop.timedate1 itself with the spoofed zone, and forwards all
 * other traffic (including fd passing) unchanged to the real bus.
 */

/*
 * Create the proxy's listening socket as scratch_dir_fd/BUSPROXY_SOCKET_NAME
 * and open the real bus socket by O_PATH (it stays reachable after the
 * mount hides its path). Returns false if the host has no system bus.
 */
bool busproxy_prepare(int scratch_dir_fd);

/* Drop a prepared proxy (e.g. the mount over the bus socket failed). */
void busproxy_cancel(void);

/*
 * Fork the proxy helper if prepared. It lives until the calling process
 * (which then execs the command) exits. Call right before exec.
 */
void busproxy_start(const char *tz_canonical);

/* Run the proxy loop in the current process (used by busproxy_start). */
void busproxy_serve(int listen_fd, int upstream_path_fd, const char *tz_canonical);

#endif /* BUSPROXY_H */
