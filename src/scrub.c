#include "scrub.h"
#include <ctype.h>

#define MAX_NAMES 16

static char *s_names[MAX_NAMES];
static int s_count;
static const char *s_spoof = "";

void scrub_set_spoof(const char *spoof) { s_spoof = spoof ? spoof : ""; }

int scrub_count(void) { return s_count; }

void scrub_add_name(const char *name) {
    if (!name) return;
    while (isspace((unsigned char)*name)) name++;
    size_t len = strlen(name);
    while (len > 0 && isspace((unsigned char)name[len - 1])) len--;
    if (len == 0 || s_count == MAX_NAMES) return;
    if (strlen(s_spoof) == len && strncasecmp(name, s_spoof, len) == 0) return;
    for (int i = 0; i < s_count; i++) {
        if (strlen(s_names[i]) == len && strncasecmp(s_names[i], name, len) == 0) return;
    }
    char *copy = strndup(name, len);
    if (copy) s_names[s_count++] = copy;
}

static bool is_word(unsigned char c) { return isalnum(c) || c == '-' || c == '_'; }

bool scrub_contains(const void *d, size_t len) {
    const char *p = d;
    for (int i = 0; i < s_count; i++) {
        size_t n = strlen(s_names[i]);
        for (size_t off = 0; n && off + n <= len; off++) {
            if (strncasecmp(p + off, s_names[i], n) == 0) return true;
        }
    }
    return false;
}

/* Index of the real name matching at s[off] on word boundaries, or -1. */
static int match_at(const char *s, size_t len, size_t off) {
    if (off > 0 && is_word((unsigned char)s[off - 1])) return -1;
    for (int i = 0; i < s_count; i++) {
        size_t n = strlen(s_names[i]);
        if (off + n > len || strncasecmp(s + off, s_names[i], n) != 0) continue;
        if (off + n < len && is_word((unsigned char)s[off + n])) continue;
        return i;
    }
    return -1;
}

char *scrub_text(const char *s, size_t len, size_t *out_len) {
    if (s_count == 0 || !scrub_contains(s, len)) return NULL;
    size_t spoof_len = strlen(s_spoof);
    size_t cap = len + 1, used = 0;
    for (int i = 0; i < s_count; i++) {
        if (spoof_len > strlen(s_names[i])) cap += (spoof_len - strlen(s_names[i])) * (len / strlen(s_names[i]) + 1);
    }
    char *out = malloc(cap);
    if (!out) return NULL;
    bool changed = false;
    for (size_t off = 0; off < len;) {
        int m = match_at(s, len, off);
        if (m >= 0) {
            memcpy(out + used, s_spoof, spoof_len);
            used += spoof_len;
            off += strlen(s_names[m]);
            changed = true;
        } else {
            out[used++] = s[off++];
        }
    }
    out[used] = '\0';
    if (!changed) {
        free(out);
        return NULL;
    }
    if (out_len) *out_len = used;
    return out;
}
