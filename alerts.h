#ifndef ALERTS_H
#define ALERTS_H

#include "parser.h"

/*
 * Open the alert log file (JSON Lines format). Returns 0 on success.
 */
int alerts_init(const char *path);

/*
 * Write one alert record. Also prints to stdout so the user sees alerts live.
 */
void alerts_write(const char *alert_id, const char *severity,
                  const parsed_packet_t *pkt, const char *details);

/*
 * How many alerts have fired since alerts_init(). Used by main for the shutdown summary.
 */
long alerts_count(void);

/*
 * Close the alert log.
 */
void alerts_close(void);

#endif
