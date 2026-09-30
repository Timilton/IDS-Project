/*
 * Mini Network IDS - M2: Main Program
 *
 * Split into modules after the initial single-file M2:
 *   parser  - raw byte parsing to parsed_packet_t
 *   rules   - signature matching + hot-reload
 *   anomaly - SYN flood and SSH brute force detection
 *   alerts  - alert log writer
 *
 * Build with the Makefile:
 *   make          (produces ./sniffer)
 *   make clean    (removes build products)
 *
 * Run:
 *   sudo ./sniffer --rules rules.json --alerts alerts.jsonl
 *   sudo ./sniffer --help
 */

#include "parser.h"
#include "rules.h"
#include "anomaly.h"
#include "alerts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>

#define ETH_P_ALL_CUSTOM 0x0003

/* Config for the main program, populated from CLI args. */
typedef struct {
    char *interface;
    char *rules_path;
    char *alerts_path;
    int   syn_threshold;
    int   syn_window;
    int   ssh_threshold;
    int   ssh_window;
} config_t;

static volatile int keep_running = 1;
static long packet_count = 0;
static long tcp_count = 0, udp_count = 0, icmp_count = 0;
static config_t cfg;

static void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: sudo %s [options]\n\n"
        "Options:\n"
        "  --interface <name>       Bind to one interface (e.g. wlan0)\n"
        "  --rules <path>           JSON rules file for signature detection\n"
        "  --alerts <path>          Alert log output (default: alerts.jsonl)\n"
        "  --syn-threshold <n>      SYN count in window before alert (default: 100)\n"
        "  --syn-window <sec>       SYN window in seconds (default: 5)\n"
        "  --ssh-threshold <n>      SSH connect attempts before alert (default: 10)\n"
        "  --ssh-window <sec>       SSH window in seconds (default: 30)\n"
        "  --help                   Show this message\n",
        prog);
}

static int parse_args(int argc, char **argv, config_t *c) {
    c->interface = NULL;
    c->rules_path = NULL;
    c->alerts_path = "alerts.jsonl";
    c->syn_threshold = 100;
    c->syn_window = 5;
    c->ssh_threshold = 10;
    c->ssh_window = 30;

    static struct option opts[] = {
        {"interface",     required_argument, 0, 'i'},
        {"rules",         required_argument, 0, 'r'},
        {"alerts",        required_argument, 0, 'a'},
        {"syn-threshold", required_argument, 0, 't'},
        {"syn-window",    required_argument, 0, 'w'},
        {"ssh-threshold", required_argument, 0, 'T'},
        {"ssh-window",    required_argument, 0, 'W'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:r:a:t:w:T:W:h", opts, NULL)) != -1) {
        switch (opt) {
            case 'i': c->interface = optarg; break;
            case 'r': c->rules_path = optarg; break;
            case 'a': c->alerts_path = optarg; break;
            case 't': c->syn_threshold = atoi(optarg); break;
            case 'w': c->syn_window = atoi(optarg); break;
            case 'T': c->ssh_threshold = atoi(optarg); break;
            case 'W': c->ssh_window = atoi(optarg); break;
            case 'h': print_usage(argv[0]); exit(EXIT_SUCCESS);
            default:  print_usage(argv[0]); return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (parse_args(argc, argv, &cfg) < 0) exit(EXIT_FAILURE);

    signal(SIGINT, handle_sigint);

    /* Initialize each module. */
    if (alerts_init(cfg.alerts_path) < 0) exit(EXIT_FAILURE);
    if (cfg.rules_path && rules_load(cfg.rules_path) < 0) exit(EXIT_FAILURE);
    anomaly_init(cfg.syn_threshold, cfg.syn_window,
                 cfg.ssh_threshold, cfg.ssh_window);

    /* Create raw socket. */
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL_CUSTOM));
    if (sockfd < 0) { perror("socket (root needed)"); exit(EXIT_FAILURE); }

    if (cfg.interface) {
        int idx = if_nametoindex(cfg.interface);
        if (idx == 0) {
            fprintf(stderr, "Unknown interface: %s\n", cfg.interface);
            exit(EXIT_FAILURE);
        }
        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL_CUSTOM);
        sll.sll_ifindex = idx;
        if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind");
            exit(EXIT_FAILURE);
        }
    }

    printf("IDS running.\n");
    printf("  Alerts:        %s\n", cfg.alerts_path);
    if (cfg.rules_path) printf("  Rules:         %s (%d loaded)\n",
                                cfg.rules_path, rules_get_count());
    if (cfg.interface)  printf("  Interface:     %s\n", cfg.interface);
    printf("  SYN threshold: %d in %ds\n", cfg.syn_threshold, cfg.syn_window);
    printf("  SSH threshold: %d in %ds\n", cfg.ssh_threshold, cfg.ssh_window);
    printf("Press Ctrl+C to stop.\n\n");

    unsigned char buffer[65536];
    parsed_packet_t pkt;

    while (keep_running) {
        ssize_t n = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (n < 0) {
            if (keep_running == 0) break;
            perror("recvfrom");
            continue;
        }
        packet_count++;

        if (parse_packet(buffer, n, &pkt) < 0) continue;

        if      (strcmp(pkt.protocol, "TCP")  == 0) tcp_count++;
        else if (strcmp(pkt.protocol, "UDP")  == 0) udp_count++;
        else if (strcmp(pkt.protocol, "ICMP") == 0) icmp_count++;

        /* Detection layer: run every detector against this packet. */
        if (cfg.rules_path) rules_check(&pkt);
        anomaly_check_syn(&pkt);
        anomaly_check_ssh(&pkt);

        /* Poll for rules file changes every 500 packets. */
        if (packet_count % 500 == 0) rules_reload_if_changed(cfg.rules_path);
    }

    printf("\nStopped.\n");
    printf("  Packets seen: %ld  (TCP: %ld, UDP: %ld, ICMP: %ld)\n",
        packet_count, tcp_count, udp_count, icmp_count);
    printf("  Alerts fired: %ld\n", alerts_count());

    rules_free();
    anomaly_free();
    alerts_close();
    close(sockfd);
    return 0;
}
