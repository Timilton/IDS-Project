#include "anomaly.h"
#include "alerts.h"
#include "uthash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
 * Ring buffer size per source IP. Must be at least as big as any threshold
 * you'd reasonably configure.
 */
#define MAX_TIMESTAMPS 500

/*
 * Generic sliding window tracker. Used for both SYN flood and SSH brute
 * force by instantiating two separate hash maps of these.
 */
typedef struct {
    uint32_t       src_ip;
    time_t         timestamps[MAX_TIMESTAMPS];
    int            count;
    int            head;
    time_t         last_alert;
    UT_hash_handle hh;
} tracker_t;

/* Two independent tracker hash maps. */
static tracker_t *syn_trackers = NULL;
static tracker_t *ssh_trackers = NULL;

/* Per-detector configuration. */
static int cfg_syn_threshold = 100;
static int cfg_syn_window    = 5;
static int cfg_ssh_threshold = 10;
static int cfg_ssh_window    = 30;

void anomaly_init(int syn_threshold, int syn_window,
                  int ssh_threshold, int ssh_window) {
    cfg_syn_threshold = syn_threshold;
    cfg_syn_window    = syn_window;
    cfg_ssh_threshold = ssh_threshold;
    cfg_ssh_window    = ssh_window;
}

/*
 * Generic "record an event for this source IP and alert if threshold crossed".
 * The record/prune/count logic is the same for SYN flood and SSH brute force,
 * so factor it out and let each detector pass its own tracker table and config.
 */
static void record_event(tracker_t **table, const parsed_packet_t *pkt,
                         int threshold, int window,
                         const char *alert_id, const char *severity) {
    time_t now = time(NULL);
    uint32_t key = pkt->src_ip_raw;
    tracker_t *t;

    HASH_FIND_INT(*table, &key, t);
    if (!t) {
        t = calloc(1, sizeof(tracker_t));
        t->src_ip = key;
        HASH_ADD_INT(*table, src_ip, t);
    }

    /* Append to ring buffer. */
    t->timestamps[t->head] = now;
    t->head = (t->head + 1) % MAX_TIMESTAMPS;
    if (t->count < MAX_TIMESTAMPS) t->count++;

    /* Sliding window log: count timestamps within [now - window, now]. */
    int recent = 0;
    for (int i = 0; i < t->count; i++) {
        if (now - t->timestamps[i] <= window) recent++;
    }

    /* Alert if over threshold. Suppress if we recently alerted for this IP
     * to avoid spamming (once per window is enough). */
    if (recent > threshold && now - t->last_alert >= window) {
        char details[256];
        snprintf(details, sizeof(details),
            "%d events in %ds window (threshold %d)",
            recent, window, threshold);
        alerts_write(alert_id, severity, pkt, details);
        t->last_alert = now;
    }
}

void anomaly_check_syn(const parsed_packet_t *pkt) {
    /* Only SYN-only TCP (not SYN-ACK, which is the server's reply). */
    if (strcmp(pkt->protocol, "TCP") != 0) return;
    if (!(pkt->tcp_flags & TCP_SYN))       return;
    if (pkt->tcp_flags & TCP_ACK)          return;

    record_event(&syn_trackers, pkt,
                 cfg_syn_threshold, cfg_syn_window,
                 "SYN_FLOOD", "high");
}

void anomaly_check_ssh(const parsed_packet_t *pkt) {
    /* SSH connection attempts: SYN to port 22. */
    if (strcmp(pkt->protocol, "TCP") != 0) return;
    if (pkt->dst_port != 22)               return;
    if (!(pkt->tcp_flags & TCP_SYN))       return;
    if (pkt->tcp_flags & TCP_ACK)          return;

    record_event(&ssh_trackers, pkt,
                 cfg_ssh_threshold, cfg_ssh_window,
                 "SSH_BRUTE_FORCE", "high");
}

static void free_table(tracker_t **table) {
    tracker_t *t, *tmp;
    HASH_ITER(hh, *table, t, tmp) {
        HASH_DEL(*table, t);
        free(t);
    }
}

void anomaly_free(void) {
    free_table(&syn_trackers);
    free_table(&ssh_trackers);
}
