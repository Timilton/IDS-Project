#include "alerts.h"

#include <stdio.h>
#include <time.h>

/*
 * Module-private state. Nobody outside this file can touch these directly;
 * they only see the functions in alerts.h.
 */
static FILE *alert_file = NULL;
static long  alert_counter = 0;

int alerts_init(const char *path) {
    alert_file = fopen(path, "w");
    if (!alert_file) {
        perror("fopen alerts");
        return -1;
    }
    return 0;
}

void alerts_write(const char *alert_id, const char *severity,
                  const parsed_packet_t *pkt, const char *details) {
    if (!alert_file) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    fprintf(alert_file,
        "{\"timestamp\":\"%s\",\"alert_id\":\"%s\",\"severity\":\"%s\","
        "\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":\"%s\","
        "\"src_port\":%u,\"dst_port\":%u,\"details\":\"%s\"}\n",
        timestamp, alert_id, severity ? severity : "medium",
        pkt->src_ip, pkt->dst_ip, pkt->protocol,
        pkt->src_port, pkt->dst_port, details);
    fflush(alert_file);
    alert_counter++;

    printf("[ALERT] %s %s from %s:%u to %s:%u  %s\n",
        severity ? severity : "medium", alert_id,
        pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port, details);
}

long alerts_count(void) {
    return alert_counter;
}

void alerts_close(void) {
    if (alert_file) {
        fclose(alert_file);
        alert_file = NULL;
    }
}
