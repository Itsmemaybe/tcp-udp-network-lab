// tcpclient2.cpp — Windows (MSVC 2010), C, blocking sockets, English messages only
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

typedef unsigned int   uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char  uint8_t;

/* send all bytes */
static int send_all(SOCKET s, const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, len - sent, 0);
        if (n <= 0) return 0;
        sent += n;
    }
    return 1;
}

/* receive exactly len bytes */
static int recv_all(SOCKET s, unsigned char* buf, int len) {
    int got = 0;
    while (got < len) {
        int r = recv(s, (char*)buf + got, len - got, 0);
        if (r <= 0) return r; /* 0 = closed, <0 = error */
        got += r;
    }
    return got;
}

/* receive message until null byte, dynamically allocated */
static int recv_msg_cstring(SOCKET s, char** out_buf, size_t* out_len) {
    const size_t SAFETY_CAP = 64 * 1024 * 1024; /* 64 MB */
    char* buf = NULL;
    size_t cap = 0, len = 0;

    for (;;) {
        char ch;
        int r = recv(s, &ch, 1, 0);
        if (r <= 0) { free(buf); return 0; } /* closed/error */

        if (ch == '\0') {
            *out_buf = buf;
            *out_len = len;
            return 1;
        }

        if (len + 1 > cap) {
            size_t ncap = cap ? cap : 1024;
            while (ncap < len + 1) {
                if (ncap > SAFETY_CAP) { free(buf); return 0; }
                ncap <<= 1;
            }
            char* p = (char*)realloc(buf, ncap);
            if (!p) { free(buf); return 0; }
            buf = p; cap = ncap;
        }
        buf[len++] = ch;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s IP:PORT get FILENAME\n", argv[0]);
        return 1;
    }

    /* parse IP:PORT */
    char addrbuf[256];
    strncpy(addrbuf, argv[1], sizeof(addrbuf) - 1);
    addrbuf[sizeof(addrbuf) - 1] = '\0';
    char* colon = strchr(addrbuf, ':');
    if (!colon) { printf("Invalid IP:PORT format\n"); return 1; }
    *colon = '\0';
    const char* ip = addrbuf;
    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) { printf("Invalid port number\n"); return 1; }

    if (strcmp(argv[2], "get") != 0) {
        printf("Second argument must be 'get'\n");
        return 1;
    }
    const char* outname = argv[3];

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n"); return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed\n"); WSACleanup(); return 1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (InetPtonA(AF_INET, ip, &sa.sin_addr) != 1) {
        printf("Invalid IP address\n"); closesocket(sock); WSACleanup(); return 1;
    }

    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        printf("Connection failed to %s:%d\n", ip, port);
        closesocket(sock); WSACleanup(); return 1;
    }

    /* send 'get' command */
    if (!send_all(sock, "get", 3)) {
        printf("Failed to send 'get' command\n");
        closesocket(sock); WSACleanup(); return 1;
    }

    FILE* fout = fopen(outname, "w");
    if (!fout) {
        printf("Failed to open output file: %s\n", outname);
        closesocket(sock); WSACleanup(); return 1;
    }

    printf("Connected to server %s:%d, waiting for data...\n", ip, port);

    /* read messages until server closes connection */
    for (;;) {
        unsigned char idx_buf[4];
        int r = recv_all(sock, idx_buf, 4);
        if (r == 0) break;      /* server closed connection */
        if (r < 0) { printf("Receive error (index)\n"); goto done; }

        unsigned char times[6];
        r = recv_all(sock, times, 6);
        if (r <= 0) { printf("Receive error (times)\n"); goto done; }

        unsigned char bbb_buf[4];
        r = recv_all(sock, bbb_buf, 4);
        if (r <= 0) { printf("Receive error (BBB)\n"); goto done; }

        /* receive message until '\0' */
        char* msg = NULL;
        size_t mlen = 0;
        if (!recv_msg_cstring(sock, &msg, &mlen)) {
            printf("Receive error (message)\n");
            if (msg) free(msg);
            goto done;
        }

        /* unpack fields */
        unsigned int h1 = times[0], m1 = times[1], s1 = times[2];
        unsigned int h2 = times[3], m2 = times[4], s2 = times[5];
        uint32_t bbb_net;
        memcpy(&bbb_net, bbb_buf, 4);
        uint32_t bbb = ntohl(bbb_net);

        /* write to output file */
        fprintf(fout, "%s:%d %02u:%02u:%02u %02u:%02u:%02u %u ",
            ip, port, h1, m1, s1, h2, m2, s2, bbb);
        if (mlen > 0) fwrite(msg, 1, mlen, fout);
        fputc('\n', fout);
        fflush(fout);

        free(msg);
    }

    printf("All messages received. Closing connection.\n");

done:
    fclose(fout);
    closesocket(sock);
    WSACleanup();
    printf("tcpclient2 finished successfully.\n");
    return 0;
}
