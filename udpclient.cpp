#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

#define MAX_MSGS 10000

typedef unsigned char u8;
typedef unsigned int  u32;

static void trim_line(char* s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\r' || s[len - 1] == '\n' || s[len - 1] == ' '))
        s[--len] = 0;
}

static int build_datagram(const char* line, int index, unsigned char** out, size_t* outlen) {
    int h1, m1, s1, h2, m2, s2;
    unsigned long bbb;
    char* msgptr = NULL;
    char* p = (char*)line;

    if (sscanf(p, "%2d:%2d:%2d", &h1, &m1, &s1) != 3) return 0;
    p = strchr(p, ' '); if (!p) return 0; p++;
    if (sscanf(p, "%2d:%2d:%2d", &h2, &m2, &s2) != 3) return 0;
    p = strchr(p, ' '); if (!p) return 0; p++;
    if (sscanf(p, "%lu", &bbb) != 1) return 0;
    p = strchr(p, ' '); if (!p) return 0; p++;
    msgptr = p;

    size_t msglen = strlen(msgptr);
    *outlen = 4 + 6 + 4 + msglen + 1;
    *out = (unsigned char*)malloc(*outlen);
    if (!*out) return 0;

    u32 idx_net = htonl(index);
    u32 bbb_net = htonl((u32)bbb);

    memcpy(*out, &idx_net, 4);
    (*out)[4] = (u8)h1; (*out)[5] = (u8)m1; (*out)[6] = (u8)s1;
    (*out)[7] = (u8)h2; (*out)[8] = (u8)m2; (*out)[9] = (u8)s2;
    memcpy(*out + 10, &bbb_net, 4);
    memcpy(*out + 14, msgptr, msglen);
    (*out)[14 + msglen] = 0;
    return 1;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: udpclient IP:PORT file.txt\n");
        return 1;
    }

    char ip[64];
    int port = 0;
    if (sscanf(argv[1], "%63[^:]:%d", ip, &port) != 2) {
        fprintf(stderr, "Invalid address format. Expected IP:PORT\n");
        return 1;
    }

    FILE* f = fopen(argv[2], "r");
    if (!f) {
        perror("File open failed");
        return 1;
    }

    char* lines[MAX_MSGS];
    int total_msgs = 0;
    char buf[8192];

    while (fgets(buf, sizeof(buf), f) && total_msgs < MAX_MSGS) {
        trim_line(buf);
        if (strlen(buf) == 0) continue;
        lines[total_msgs] = strdup(buf);
        total_msgs++;
    }
    fclose(f);
    if (total_msgs == 0) {
        printf("No messages to send.\n");
        return 0;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address\n");
        close(s);
        return 1;
    }

    printf("Sending %d messages to %s:%d...\n", total_msgs, ip, port);

    int acked[MAX_MSGS] = { 0 };
    int sent_count = 0, acked_count = 0;

    struct timeval tv;
    fd_set rfds;
    time_t start_time = time(NULL);

    int idle_rounds = 0;
    const int max_idle_rounds = 100; // ~30s total

    while (acked_count < total_msgs) {
        int new_acks_received = 0;

        /* Send all unsent/unacknowledged messages */
        for (int i = 0; i < total_msgs; ++i) {
            if (acked[i]) continue;

            unsigned char* packet = NULL;
            size_t plen = 0;
            if (!build_datagram(lines[i], i, &packet, &plen)) continue;

            ssize_t wn = sendto(s, packet, plen, 0, (struct sockaddr*)&sa, sizeof(sa));
            if (wn < 0) {
                perror("sendto");
                free(packet);
                continue;
            }
            free(packet);
            sent_count++;
        }

        /* Wait up to 300ms for response(s) */
        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 300000;
        int r = select(s + 1, &rfds, NULL, NULL, &tv);

        if (r > 0 && FD_ISSET(s, &rfds)) {
            unsigned char recvbuf[4096];
            struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
            ssize_t rn = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&from, &fromlen);
            if (rn > 0 && (rn % 4 == 0)) {
                int count = rn / 4;
                for (int i = 0; i < count; ++i) {
                    u32 msg_idx_net;
                    memcpy(&msg_idx_net, recvbuf + i * 4, 4);
                    u32 msg_idx = ntohl(msg_idx_net);
                    if (msg_idx < (u32)total_msgs && !acked[msg_idx]) {
                        acked[msg_idx] = 1;
                        acked_count++;
                        new_acks_received = 1;
                    }
                }
            }
        }

        if (!new_acks_received) {
            idle_rounds++;
            if (idle_rounds > max_idle_rounds) {
                printf("No new acknowledgements for 30s, stopping.\n");
                break;
            }
        }
        else {
            idle_rounds = 0;
        }
    }

    printf("Finished: Sent %d datagrams, got %d ACKs.\n", sent_count, acked_count);

    for (int i = 0; i < total_msgs; ++i)
        free(lines[i]);
    close(s);
    return 0;
}
