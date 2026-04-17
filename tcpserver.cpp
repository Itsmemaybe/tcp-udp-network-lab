// tcpserver.c — 

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_CLIENTS 128

typedef enum { MODE_UNDEF = 0, MODE_PUT = 1, MODE_GET = 2 } Mode;

typedef struct {
    int   sock;
    char  ip[64];
    int   port;

    /* input buffer (grows as needed) */
    unsigned char* inbuf;
    size_t inlen;
    size_t incap;

    /* output buffer for pending data (acks for PUT, payload for GET) */
    unsigned char* outbuf;
    size_t outlen;
    size_t outcap;

    /* command mode */
    Mode mode;

    /* GET state: have we queued all data from msg.txt? If yes, close after flush */
    int get_done;
} Client;

static int set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int ensure_cap(unsigned char** buf, size_t* cap, size_t need) {
    if (*cap >= need) return 1;
    size_t ncap = (*cap == 0 ? 4096 : *cap);
    while (ncap < need) {
        if (ncap > (1u << 27)) return 0; /* safety cap ~128MB */
        ncap <<= 1u;
    }
    unsigned char* p = (unsigned char*)realloc(*buf, ncap);
    if (!p) return 0;
    *buf = p;
    *cap = ncap;
    return 1;
}

static int queue_bytes(Client* c, const void* data, size_t len) {
    if (!ensure_cap(&c->outbuf, &c->outcap, c->outlen + len)) return 0;
    memcpy(c->outbuf + c->outlen, data, len);
    c->outlen += len;
    return 1;
}

static void client_reset(Client* c) {
    if (c->sock > 0) close(c->sock);
    c->sock = -1;
    c->ip[0] = '\0';
    c->port = 0;

    free(c->inbuf);  c->inbuf = NULL; c->inlen = 0; c->incap = 0;
    free(c->outbuf); c->outbuf = NULL; c->outlen = 0; c->outcap = 0;

    c->mode = MODE_UNDEF;
    c->get_done = 0;
}

static void client_init(Client* c) {
    memset(c, 0, sizeof(*c));
    c->sock = -1;
}

/* parse & pop one complete PUT-message from c->inbuf; write to file; queue "ok".
   returns: 0 = need more data; 1 = parsed; 2 = parsed & msg == "stop" */
static int parse_one_put(Client* c, FILE* fout) {
    /* minimal header: 4 (index) + 3 + 3 + 4 = 14, plus at least 1 byte of '\0' => 15 */
    if (c->inlen < 15) return 0;

    size_t pos = 0;
    /* index */
    if (c->inlen - pos < 4) return 0;
    uint32_t idx_net; memcpy(&idx_net, c->inbuf + pos, 4); pos += 4;

    /* times */
    if (c->inlen - pos < 6) return 0;
    unsigned h1 = c->inbuf[pos++], m1 = c->inbuf[pos++], s1 = c->inbuf[pos++];
    unsigned h2 = c->inbuf[pos++], m2 = c->inbuf[pos++], s2 = c->inbuf[pos++];

    /* BBB */
    if (c->inlen - pos < 4) return 0;
    uint32_t bbb_net; memcpy(&bbb_net, c->inbuf + pos, 4); pos += 4;

    /* message: until first '\0' */
    size_t msg_start = pos, found = msg_start;
    int have_nul = 0;
    for (; found < c->inlen; ++found) {
        if (c->inbuf[found] == 0) { have_nul = 1; break; }
    }
    if (!have_nul) return 0;

    size_t msg_len = found - msg_start;
    /* copy message into temporary C-string */
    char* msg = (char*)malloc(msg_len + 1);
    if (!msg) return 0;
    if (msg_len) memcpy(msg, c->inbuf + msg_start, msg_len);
    msg[msg_len] = '\0';

    /* consume from input buffer (including trailing '\0') */
    size_t consumed = found + 1;
    if (consumed < c->inlen) memmove(c->inbuf, c->inbuf + consumed, c->inlen - consumed);
    c->inlen -= consumed;

    uint32_t idx = ntohl(idx_net);
    uint32_t bbb = ntohl(bbb_net);

    /* write to msg.txt: "IP:PORT hh:mm:ss hh:mm:ss BBB Message" */
    fprintf(fout, "%s:%d %02u:%02u:%02u %02u:%02u:%02u %u %s\n",
        c->ip, c->port, h1, m1, s1, h2, m2, s2, bbb, msg);
    fflush(fout);

    /* queue "ok" */
    (void)queue_bytes(c, "ok", 2);

    int is_stop = (strcmp(msg, "stop") == 0);
    free(msg);
    return is_stop ? 2 : 1;
}

/* parse one line from msg.txt ("IP:PORT hh:mm:ss hh:mm:ss BBB Message") into protocol frame
   with given sequential index, and queue it into client's outbuf. returns 1 on success else 0 */
static int queue_get_frame_from_line(Client* c, const char* line, uint32_t seq_idx) {
    /* we'll parse with sscanf the fixed parts, then the rest is message (may contain spaces) */
    int ip1, ip2, ip3, ip4, port;
    unsigned h1, m1, s1, h2, m2, s2;
    unsigned long bbb_ul;
    const char* p = line;

    /* find first space after "IP:PORT " and keep pointer to message start */
    /* We don't strictly need the IP here; the spec says "IP and port that preceded the message in msg.txt are ignored" for GET,
       so we only need to parse and skip them, not validate. We'll just scan until first space. */
    const char* sp = strchr(p, ' ');
    if (!sp) return 0;
    /* after this space there must be "hh:mm:ss ..." */
    /* parse times + BBB using sscanf starting at sp+1 */
    int n = sscanf(sp + 1, "%2u:%2u:%2u %2u:%2u:%2u %lu", &h1, &m1, &s1, &h2, &m2, &s2, &bbb_ul);
    if (n != 7) return 0;

    /* move pointer after BBB to get message */
    /* find third space after sp+1: (time1) (time2) (BBB) (message...) */
    const char* p_after_t1 = strchr(sp + 1, ' ');
    if (!p_after_t1) return 0;
    const char* p_after_t2 = strchr(p_after_t1 + 1, ' ');
    if (!p_after_t2) return 0;
    const char* p_after_bbb = strchr(p_after_t2 + 1, ' ');
    if (!p_after_bbb) {
        /* empty message allowed */
        p_after_bbb = sp + strlen(sp); /* points to '\0' */
    }

    const char* msg = (*p_after_bbb == ' ') ? (p_after_bbb + 1) : p_after_bbb;
    size_t msg_len = strlen(msg);
    /* trim trailing \r\n */
    while (msg_len && (msg[msg_len - 1] == '\n' || msg[msg_len - 1] == '\r')) msg_len--;

    if (h1 > 23 || m1 > 59 || s1 > 59 || h2 > 23 || m2 > 59 || s2 > 59) return 0;
    if (bbb_ul > 0xFFFFFFFFu) return 0;
    uint32_t bbb = (uint32_t)bbb_ul;

    /* build frame: 4B idx + 3 + 3 + 4 + msg + '\0' */
    uint32_t idx_net = htonl(seq_idx);
    uint32_t bbb_net = htonl(bbb);

    size_t need = 4 + 3 + 3 + 4 + msg_len + 1;
    unsigned char* frame = (unsigned char*)malloc(need);
    if (!frame) return 0;

    size_t off = 0;
    memcpy(frame + off, &idx_net, 4); off += 4;
    frame[off++] = (unsigned char)h1; frame[off++] = (unsigned char)m1; frame[off++] = (unsigned char)s1;
    frame[off++] = (unsigned char)h2; frame[off++] = (unsigned char)m2; frame[off++] = (unsigned char)s2;
    memcpy(frame + off, &bbb_net, 4); off += 4;
    if (msg_len) memcpy(frame + off, msg, msg_len);
    off += msg_len;
    frame[off++] = 0;

    int ok = queue_bytes(c, frame, need);
    free(frame);
    return ok;
}

/* fill outgoing buffer for GET client from msg.txt once */
static void build_get_payload(Client* c) {
    if (c->get_done) return;
    FILE* fin = fopen("msg.txt", "rb");
    uint32_t seq = 0;
    if (fin) {
        char* line = NULL;
        size_t cap = 0;
        ssize_t r;
        /* getline is POSIX; for old compilers we'll roll our own: */
        while (1) {
            int ch; size_t len = 0;
            if (!ensure_cap((unsigned char**)&line, &cap, 1024)) break;
            line[0] = '\0';
            while ((ch = fgetc(fin)) != EOF) {
                if (!ensure_cap((unsigned char**)&line, &cap, len + 2)) break;
                line[len++] = (char)ch;
                if (ch == '\n') break;
            }
            if (len == 0) break;
            line[len] = '\0';
            /* queue one frame */
            if (!queue_get_frame_from_line(c, line, seq)) {
                /* skip malformed line silently */
            }
            else {
                seq++;
            }
        }
        if (line) free(line);
        fclose(fin);
    }
    c->get_done = 1; /* even if empty */
}

/* try to send pending outbuf */
static int flush_out(Client* c) {
    while (c->outlen > 0) {
        ssize_t n = send(c->sock, c->outbuf, c->outlen, 0);
        if (n > 0) {
            if ((size_t)n < c->outlen) {
                memmove(c->outbuf, c->outbuf + n, c->outlen - n);
            }
            c->outlen -= (size_t)n;
        }
        else {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return 1; /* try later */
            }
            return 0; /* fatal */
        }
    }
    return 1;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s PORT\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Bad port\n");
        return 1;
    }

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons((uint16_t)port);

    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); close(ls); return 1; }
    if (listen(ls, 64) < 0) { perror("listen"); close(ls); return 1; }
    if (set_nonblock(ls) < 0) { perror("nonblock"); close(ls); return 1; }

    /* truncate msg.txt on start (как в тестах) */
    FILE* fout = fopen("msg.txt", "w");
    if (!fout) { perror("msg.txt"); close(ls); return 1; }

    Client clients[MAX_CLIENTS];
    for (int i = 0; i < MAX_CLIENTS; ++i) client_init(&clients[i]);

    int stop_all = 0;

    while (!stop_all) {
        fd_set rfds, wfds;
        FD_ZERO(&rfds); FD_ZERO(&wfds);
        int maxfd = ls;
        FD_SET(ls, &rfds);

        for (int i = 0; i < MAX_CLIENTS; ++i) {
            if (clients[i].sock > 0) {
                FD_SET(clients[i].sock, &rfds);
                if (clients[i].outlen > 0) FD_SET(clients[i].sock, &wfds);
                if (clients[i].sock > maxfd) maxfd = clients[i].sock;
            }
        }

        struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
        int r = select(maxfd + 1, &rfds, &wfds, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }

        /* accept */
        if (FD_ISSET(ls, &rfds)) {
            struct sockaddr_in ca; socklen_t cl = sizeof(ca);
            int cs = accept(ls, (struct sockaddr*)&ca, &cl);
            if (cs >= 0) {
                set_nonblock(cs);
                int slot = -1;
                for (int i = 0; i < MAX_CLIENTS; ++i) if (clients[i].sock <= 0) { slot = i; break; }
                if (slot >= 0) {
                    Client* c = &clients[slot];
                    client_reset(c);
                    c->sock = cs;
                    snprintf(c->ip, sizeof(c->ip), "%s", inet_ntoa(ca.sin_addr));
                    c->port = ntohs(ca.sin_port);
                    /* ready */
                }
                else {
                    close(cs);
                }
            }
        }

        /* IO */
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            Client* c = &clients[i];
            if (c->sock <= 0) continue;

            /* write first (to avoid outbuf growth) */
            if (c->outlen > 0 && FD_ISSET(c->sock, &wfds)) {
                if (!flush_out(c)) { client_reset(c); continue; }
                if (c->mode == MODE_GET && c->get_done && c->outlen == 0) {
                    /* finished sending: close client */
                    client_reset(c);
                    continue;
                }
            }

            if (!FD_ISSET(c->sock, &rfds)) continue;

            unsigned char tmp[8192];
            ssize_t n = recv(c->sock, tmp, sizeof(tmp), 0);
            if (n == 0) {
                /* client closed — никакого «дочитывания после FIN» */
                client_reset(c);
                continue;
            }
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                client_reset(c);
                continue;
            }
            if (!ensure_cap(&c->inbuf, &c->incap, c->inlen + (size_t)n)) { client_reset(c); continue; }
            memcpy(c->inbuf + c->inlen, tmp, (size_t)n);
            c->inlen += (size_t)n;

            /* detect mode once we have >=3 bytes */
            if (c->mode == MODE_UNDEF && c->inlen >= 3) {
                if (c->inbuf[0] == 'p' && c->inbuf[1] == 'u' && c->inbuf[2] == 't') {
                    /* drop "put" */
                    memmove(c->inbuf, c->inbuf + 3, c->inlen - 3);
                    c->inlen -= 3;
                    c->mode = MODE_PUT;
                }
                else if (c->inbuf[0] == 'g' && c->inbuf[1] == 'e' && c->inbuf[2] == 't') {
                    /* drop "get" */
                    memmove(c->inbuf, c->inbuf + 3, c->inlen - 3);
                    c->inlen -= 3;
                    c->mode = MODE_GET;
                    /* build and queue payload once */
                    build_get_payload(c);
                    /* try to send right away */
                    if (!flush_out(c)) { client_reset(c); continue; }
                    if (c->get_done && c->outlen == 0) {
                        /* if nothing to send — just close immediately */
                        client_reset(c);
                        continue;
                    }
                }
                else {
                    /* unknown command */
                    client_reset(c);
                    continue;
                }
            }

            if (c->mode == MODE_PUT) {
                while (1) {
                    int pr = parse_one_put(c, fout);
                    if (pr == 0) break;
                    if (pr == 2) {
                        /* got "stop": send ok already queued; flush now, then stop_all */
                        /* попытаться выслать накопленное; если не выйдет — закроем позже по циклу */
                        flush_out(c);
                        stop_all = 1;
                        break;
                    }
                }
            }
        } /* for clients */
    } /* while !stop_all */

    /* shutdown: close all clients and sockets */
    for (int i = 0; i < MAX_CLIENTS; ++i) if (clients[i].sock > 0) client_reset(&clients[i]);
    fclose(fout);
    close(ls);
    return 0;
}
