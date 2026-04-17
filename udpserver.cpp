// udpserver
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "Ws2_32.lib")

typedef unsigned int  u32;
typedef unsigned short u16;
typedef unsigned long long u64;
typedef unsigned char u8;


/* =================== 64-bit hash set for dedup =================== */
typedef struct { u64* keys; size_t cap; size_t sz; } u64set;

static int set_init(u64set* s) {
    s->cap = 4096; s->sz = 0;
    s->keys = (u64*)malloc(s->cap * sizeof(u64));
    if (!s->keys) return 0;
    for (size_t i = 0; i < s->cap; ++i)
        s->keys[i] = 0xFFFFFFFFFFFFFFFFull;
    return 1;
}
static void set_free(u64set* s) { free(s->keys); s->keys = NULL; s->cap = s->sz = 0; }
static size_t set_probe(u64 k, size_t cap) {
    return (size_t)((k * 11400714819323198485ull) & (cap - 1));
}
static int set_has(u64set* s, u64 k) {
    size_t i = set_probe(k, s->cap);
    while (1) {
        u64 v = s->keys[i];
        if (v == k) return 1;
        if (v == 0xFFFFFFFFFFFFFFFFull) return 0;
        i = (i + 1) & (s->cap - 1);
    }
}
static int set_put(u64set* s, u64 k) {
    if (s->sz * 2 >= s->cap) {
        size_t ncap = s->cap * 2;
        u64* nkeys = (u64*)malloc(ncap * sizeof(u64));
        if (!nkeys) return 0;
        for (size_t i = 0; i < ncap; ++i) nkeys[i] = 0xFFFFFFFFFFFFFFFFull;
        for (size_t i = 0; i < s->cap; ++i) {
            u64 v = s->keys[i];
            if (v == 0xFFFFFFFFFFFFFFFFull) continue;
            size_t j = set_probe(v, ncap);
            while (nkeys[j] != 0xFFFFFFFFFFFFFFFFull)
                j = (j + 1) & (ncap - 1);
            nkeys[j] = v;
        }
        free(s->keys);
        s->keys = nkeys;
        s->cap = ncap;
    }
    size_t i = set_probe(k, s->cap);
    while (s->keys[i] != 0xFFFFFFFFFFFFFFFFull) {
        if (s->keys[i] == k) return 1;
        i = (i + 1) & (s->cap - 1);
    }
    s->keys[i] = k; s->sz++;
    return 1;
}

/* =================== Client tracking =================== */
#define MAX_CLIENTS 1024
struct client_info {
    u32 addr;
    u16 port;
    time_t last_seen;
};
static struct client_info clients[MAX_CLIENTS];
static int nclients = 0;

static void update_client(const struct sockaddr_in* ca) {
    time_t now = time(NULL);
    for (int i = 0; i < nclients; ++i) {
        if (clients[i].addr == ca->sin_addr.s_addr && clients[i].port == ca->sin_port) {
            clients[i].last_seen = now;
            return;
        }
    }
    if (nclients < MAX_CLIENTS) {
        clients[nclients].addr = ca->sin_addr.s_addr;
        clients[nclients].port = ca->sin_port;
        clients[nclients].last_seen = now;
        nclients++;
    }
}

/* periodic cleanup */
static void cleanup_clients(void) {
    time_t now = time(NULL);
    for (int i = 0; i < nclients; ) {
        if (now - clients[i].last_seen > 30) {
            struct in_addr ia; ia.s_addr = clients[i].addr;
            printf("Removing inactive client %s:%d\n",
                inet_ntoa(ia), ntohs(clients[i].port));
            clients[i] = clients[nclients - 1];
            nclients--;
            continue;
        }
        i++;
    }
}

/* =================== Append message to file =================== */
static void append_msg(const char* ipport, u8 h1, u8 m1, u8 s1,
    u8 h2, u8 m2, u8 s2, u32 bbb, const char* msg) {
    FILE* f = fopen("msg.txt", "a");
    if (!f) return;
    fprintf(f, "%s %02u:%02u:%02u %02u:%02u:%02u %u %s\n",
        ipport, h1, m1, s1, h2, m2, s2, bbb, msg);
    fclose(f);
}

/* =================== Main =================== */
int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s FIRST_PORT LAST_PORT\n", argv[0]);
        return 1;
    }

    int p1 = atoi(argv[1]), p2 = atoi(argv[2]);
    if (p1 <= 0 || p2 < p1 || p2 > 65535) {
        printf("Invalid port range.\n");
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    int count = p2 - p1 + 1;
    SOCKET* socks = (SOCKET*)malloc(count * sizeof(SOCKET));
    WSAEVENT* evs = (WSAEVENT*)malloc(count * sizeof(WSAEVENT));
    if (!socks || !evs) return 1;

    for (int i = 0; i < count; ++i) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (socks[i] == INVALID_SOCKET) {
            printf("Socket creation failed on port %d\n", p1 + i);
            return 1;
        }
        u_long nb = 1;
        ioctlsocket(socks[i], FIONBIO, &nb);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)(p1 + i));
        sa.sin_addr.s_addr = INADDR_ANY;
        if (bind(socks[i], (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
            printf("Bind failed on %d\n", p1 + i);
            return 1;
        }
        evs[i] = WSACreateEvent();
        WSAEventSelect(socks[i], evs[i], FD_READ | FD_CLOSE);
    }

    /* clear msg.txt at start */
    FILE* f = fopen("msg.txt", "w");
    if (f) fclose(f);

    u64set dedup;
    if (!set_init(&dedup)) return 1;

    printf("Listening UDP ports %d..%d\n", p1, p2);
    int stop = 0;
    time_t last_gc = time(NULL);

    while (!stop) {
        DWORD w = WSAWaitForMultipleEvents(count, evs, FALSE, 500, FALSE);
        if (w == WSA_WAIT_TIMEOUT) {
            if (time(NULL) - last_gc >= 5) {
                cleanup_clients();
                last_gc = time(NULL);
            }
            continue;
        }
        if (w == WSA_WAIT_FAILED) break;

        int idx = (int)(w - WSA_WAIT_EVENT_0);
        if (idx < 0 || idx >= count) continue;

        WSANETWORKEVENTS ne;
        if (WSAEnumNetworkEvents(socks[idx], evs[idx], &ne) == SOCKET_ERROR)
            continue;

        if (ne.lNetworkEvents & FD_READ) {
            for (;;) {
                char buf[65536];
                struct sockaddr_in ca;
                int clen = sizeof(ca);
                int rn = recvfrom(socks[idx], buf, sizeof(buf), 0,
                    (struct sockaddr*)&ca, &clen);
                if (rn == SOCKET_ERROR) {
                    int e = WSAGetLastError();
                    if (e == WSAEWOULDBLOCK) break;
                    break;
                }
                if (rn < 15) continue;

                update_client(&ca);

                const char* ipstr = inet_ntoa(ca.sin_addr);
                int port = ntohs(ca.sin_port);
                char ipport[64];
                _snprintf(ipport, sizeof(ipport), "%s:%d", ipstr, port);

                u32 idx_net; memcpy(&idx_net, buf, 4);
                u32 msg_idx = ntohl(idx_net);
                u8 h1 = buf[4], m1 = buf[5], s1 = buf[6];
                u8 h2 = buf[7], m2 = buf[8], s2 = buf[9];
                u32 bbb_net; memcpy(&bbb_net, buf + 10, 4);
                u32 bbb = ntohl(bbb_net);

                int pos = 14, end = -1;
                for (int i = pos; i < rn; ++i)
                    if (buf[i] == 0) { end = i; break; }
                if (end < 0) continue;
                int mlen = end - pos;
                char msg[4096];
                if (mlen > (int)sizeof(msg) - 1) mlen = sizeof(msg) - 1;
                memcpy(msg, buf + pos, mlen);
                msg[mlen] = 0;

                u64 key = ((u64)ca.sin_addr.s_addr << 32) ^
                    ((u64)ca.sin_port << 16) ^ msg_idx;

                if (!set_has(&dedup, key)) {
                    set_put(&dedup, key);
                    append_msg(ipport, h1, m1, s1, h2, m2, s2, bbb, msg);
                }

                /* send ack */
                u32 ack = htonl(msg_idx);
                sendto(socks[idx], (const char*)&ack, 4, 0,
                    (struct sockaddr*)&ca, sizeof(ca));

                if (strcmp(msg, "stop") == 0) {
                    printf("Received stop from %s\n", ipport);
                    stop = 1;
                    break;
                }
            }
        }
    }

    for (int i = 0; i < count; ++i) {
        closesocket(socks[i]);
        WSACloseEvent(evs[i]);
    }
    free(socks);
    free(evs);
    set_free(&dedup);
    WSACleanup();
    printf("UDP server stopped.\n");
    return 0;
}
