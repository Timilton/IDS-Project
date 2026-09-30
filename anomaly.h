#ifndef ANOMALY_H
#define ANOMALY_H

#include "parser.h"

/*
 * Set thresholds and windows for the two anomaly detectors.
 * Call once at startup.
 */
void anomaly_init(int syn_threshold, int syn_window,
                  int ssh_threshold, int ssh_window);

/*
 * Called for every parsed packet. Internally filters for SYN-only TCP
 * packets and updates the per-source-IP sliding window. Fires SYN_FLOOD alerts.
 */
void anomaly_check_syn(const parsed_packet_t *pkt);

/*
 * Called for every parsed packet. Internally filters for SYN packets to
 * dst_port 22 and updates a separate per-source-IP sliding window.
 * Fires SSH_BRUTE_FORCE alerts.
 */
void anomaly_check_ssh(const parsed_packet_t *pkt);

/*
 * Free all tracker state. Call at shutdown.
 */
void anomaly_free(void);

#endif
