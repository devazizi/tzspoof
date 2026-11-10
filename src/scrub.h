#ifndef SCRUB_H
#define SCRUB_H

#include "tzspoof.h"

/*
 * Real hostnames to hide when --hostname is used. Collected before the UTS
 * namespace changes: gethostname(), /etc/hostname, and what
 * systemd-hostnamed reports (which, inside nested sessions, is the true host
 * name that neither of the others shows).
 */

/* Record the spoofed name; names equal to it are never scrubbed. */
void scrub_set_spoof(const char *spoof);

/* Add a real name (trimmed; empty and duplicate names are ignored). */
void scrub_add_name(const char *name);

int scrub_count(void);

/* True if any real name occurs in d (case-insensitive). */
bool scrub_contains(const void *d, size_t len);

/*
 * Replace whole-word, case-insensitive occurrences of real names in s
 * (word characters: letters, digits, '-' and '_'; so "alipc.lan" becomes
 * "<spoof>.lan"). Returns a malloc'd NUL-terminated string and its length,
 * or NULL if nothing changed.
 */
char *scrub_text(const char *s, size_t len, size_t *out_len);

#endif /* SCRUB_H */
