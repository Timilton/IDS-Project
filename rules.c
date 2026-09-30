#include "rules.h"
#include "alerts.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

/*
 * A signature rule. NULL fields and 0 ports mean "any" (match anything).
 */
typedef struct {
    char *id;
    char *protocol;
    int   dst_port;
    int   src_port;
    char *payload_contains;
    char *severity;
} rule_t;

/* Module-private state. */
static rule_t *rules = NULL;
static int     rule_count = 0;
static time_t  rules_mtime = 0;

int rules_get_count(void) { return rule_count; }

void rules_free(void) {
    for (int i = 0; i < rule_count; i++) {
        free(rules[i].id);
        free(rules[i].protocol);
        free(rules[i].payload_contains);
        free(rules[i].severity);
    }
    free(rules);
    rules = NULL;
    rule_count = 0;
}

int rules_load(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open rules file: %s\n", path);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *json_text = malloc(size + 1);
    fread(json_text, 1, size, fp);
    json_text[size] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(json_text);
    free(json_text);
    if (!root || !cJSON_IsArray(root)) {
        fprintf(stderr, "Rules file must be a JSON array\n");
        if (root) cJSON_Delete(root);
        return -1;
    }

    rules_free();

    int n = cJSON_GetArraySize(root);
    rules = calloc(n, sizeof(rule_t));
    rule_count = 0;

    for (int i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(root, i);
        if (!cJSON_IsObject(item)) continue;

        rule_t *r = &rules[rule_count];
        cJSON *id      = cJSON_GetObjectItem(item, "id");
        cJSON *proto   = cJSON_GetObjectItem(item, "protocol");
        cJSON *dport   = cJSON_GetObjectItem(item, "dst_port");
        cJSON *sport   = cJSON_GetObjectItem(item, "src_port");
        cJSON *payload = cJSON_GetObjectItem(item, "payload_contains");
        cJSON *sev     = cJSON_GetObjectItem(item, "severity");

        r->id       = (id    && cJSON_IsString(id))    ? strdup(id->valuestring)    : strdup("UNNAMED");
        r->protocol = (proto && cJSON_IsString(proto)) ? strdup(proto->valuestring) : NULL;
        r->dst_port = (dport && cJSON_IsNumber(dport)) ? dport->valueint : 0;
        r->src_port = (sport && cJSON_IsNumber(sport)) ? sport->valueint : 0;
        r->payload_contains = (payload && cJSON_IsString(payload)) ? strdup(payload->valuestring) : NULL;
        r->severity = (sev   && cJSON_IsString(sev))   ? strdup(sev->valuestring)   : NULL;
        rule_count++;
    }

    cJSON_Delete(root);

    struct stat st;
    if (stat(path, &st) == 0) rules_mtime = st.st_mtime;

    printf("Loaded %d rules from %s\n", rule_count, path);
    return 0;
}

static int proto_matches(const char *rule_proto, const char *pkt_proto) {
    if (!rule_proto) return 1;
    return strcasecmp(rule_proto, pkt_proto) == 0;
}

void rules_check(const parsed_packet_t *pkt) {
    for (int i = 0; i < rule_count; i++) {
        rule_t *r = &rules[i];

        if (!proto_matches(r->protocol, pkt->protocol)) continue;
        if (r->dst_port && r->dst_port != pkt->dst_port) continue;
        if (r->src_port && r->src_port != pkt->src_port) continue;

        if (r->payload_contains) {
            int needle_len = strlen(r->payload_contains);
            int found = 0;
            if (pkt->payload_len >= needle_len) {
                for (int j = 0; j <= pkt->payload_len - needle_len; j++) {
                    if (memcmp(pkt->payload + j, r->payload_contains, needle_len) == 0) {
                        found = 1;
                        break;
                    }
                }
            }
            if (!found) continue;
        }

        char details[256];
        snprintf(details, sizeof(details), "matched rule %s", r->id);
        alerts_write(r->id, r->severity, pkt, details);
    }
}

void rules_reload_if_changed(const char *path) {
    if (!path) return;
    struct stat st;
    if (stat(path, &st) != 0) return;
    if (st.st_mtime != rules_mtime) {
        printf("Rules file changed, reloading...\n");
        rules_load(path);
    }
}
