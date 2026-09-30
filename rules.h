#ifndef RULES_H
#define RULES_H

#include "parser.h"

/*
 * Load rules from a JSON file into the module's internal rule array.
 * Returns 0 on success, -1 on parse error or missing file.
 */
int rules_load(const char *path);

/*
 * Check a parsed packet against every loaded rule. Fires alerts for matches.
 */
void rules_check(const parsed_packet_t *pkt);

/*
 * If the rules file on disk has been modified since the last load, reload it.
 * Call periodically from the main loop (say, every N packets).
 */
void rules_reload_if_changed(const char *path);

/*
 * How many rules are currently loaded. For the startup banner.
 */
int rules_get_count(void);

/*
 * Free all loaded rules. Call at shutdown.
 */
void rules_free(void);

#endif
