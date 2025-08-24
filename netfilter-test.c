#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static char *block_host = NULL;

char* extract_host(const char* data, int len) {
    const char* p = data;
    const char* end = data + len;

    while (p < end && *p != '\n') p++;
    if (p >= end) return NULL;
    p++;

    while (p < end) {
        if (*p == '\r' || *p == '\n') break;

        if (p + 5 < end && strncasecmp(p, "Host:", 5) == 0) {
            p += 5;
            while (p < end && (*p == ' ' || *p == '\t')) p++;

            const char* start = p;
            while (p < end && *p != '\r' && *p != '\n') p++;

            int host_len = p - start;
            if (host_len > 0) {
                char* host = malloc(host_len + 1);
                strncpy(host, start, host_len);
                host[host_len] = '\0';
                return host;
            }
        }

        while (p < end && *p != '\n') p++;
        if (p < end) p++;
    }

    return NULL;
}

int should_drop(unsigned char *data, int len) {
    if (len < sizeof(struct iphdr)) return 0;

    struct iphdr *ip = (struct iphdr *)data;
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) return 0;

    int ip_len = ip->ihl * 4;
    if (len < ip_len + sizeof(struct tcphdr)) return 0;

    struct tcphdr *tcp = (struct tcphdr *)(data + ip_len);
    if (ntohs(tcp->dest) != 80) return 0;

    int tcp_len = tcp->doff * 4;
    int total_hdr = ip_len + tcp_len;
    if (len <= total_hdr) return 0;

    unsigned char *http = data + total_hdr;
    int http_len = len - total_hdr;

    if (http_len < 4) return 0;
    if (strncmp((char*)http, "GET ", 4) != 0 &&
        strncmp((char*)http, "POST ", 5) != 0 &&
        strncmp((char*)http, "HEAD ", 5) != 0) return 0;

    char *host = extract_host((char*)http, http_len);
    if (host) {
        int block = (strcasecmp(host, block_host) == 0);
        if (block) printf("BLOCKED: %s\n", host);
        free(host);
        return block;
    }

    return 0;
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                   struct nfq_data *nfa, void *data) {
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *pkt;
    int ret;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    ret = nfq_get_payload(nfa, &pkt);
    if (ret >= 0 && should_drop(pkt, ret)) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        fprintf(stderr, "usage: %s <host>\n", argv[0]);
        exit(1);
    }

    block_host = argv[1];
    printf("target: %s\n", block_host);

    h = nfq_open();
    if (!h) exit(1);

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) exit(1);

    qh = nfq_create_queue(h, 0, &callback, NULL);
    if (!qh) exit(1);

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) exit(1);

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
