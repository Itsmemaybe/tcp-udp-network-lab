#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;

/* --- Safe send: ensures all bytes are sent --- */
static int send_all(SOCKET s, const char* data, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, len - sent, 0);
        if (n == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) { Sleep(5); continue; }
            if (err == WSAECONNRESET || err == WSAECONNABORTED || err == WSAENETRESET)
                return 0;
            printf("Send error %d after %d bytes\n", err, sent);
            return 0;
        }
        if (n == 0) return 0;
        sent += n;
    }
    return 1;
}

/* --- Non-blocking drain of "ok" responses --- */
static void drain_ok_nonblocking(SOCKET s, unsigned int* got) {
    u_long avail = 0;
    if (ioctlsocket(s, FIONREAD, &avail) == SOCKET_ERROR) return;
    while (avail > 0) {
        char buf[256];
        int toread = (avail > sizeof(buf)) ? (int)sizeof(buf) : (int)avail;
        int n = recv(s, buf, toread, 0);
        if (n <= 0) break;
        *got += (unsigned int)n;
        avail -= n;
    }
}

/* --- Trim trailing spaces/newlines --- */
static void trim_line(char* s) {
    int len = (int)strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' '))
        s[--len] = 0;
}

/* --- Main --- */
int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: tcpclient IP:PORT file.txt\n");
        return 1;
    }

    /* Parse IP and port */
    char ip[64];
    int port = 0;
    if (sscanf(argv[1], "%63[^:]:%d", ip, &port) != 2) {
        printf("Invalid address format (expected IP:PORT)\n");
        return 1;
    }

    /* Initialize WinSock */
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    /* Connect to server */
    SOCKET sock;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u16)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) <= 0) {
        printf("Invalid IP address\n");
        WSACleanup();
        return 1;
    }

    int connected = 0;
    for (int i = 0; i < 10; ++i) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            printf("Socket creation failed\n");
            WSACleanup();
            return 1;
        }
        if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
            connected = 1;
            break;
        }
        closesocket(sock);
        Sleep(100);
    }
    if (!connected) {
        printf("Unable to connect to server\n");
        WSACleanup();
        return 1;
    }

    printf("Connected to %s:%d\n", ip, port);

    /* Send "put" command */
    if (send(sock, "put", 3, 0) != 3) {
        printf("Failed to send 'put' command\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    /* Open input file */
    FILE* f = fopen(argv[2], "r");
    if (!f) {
        printf("Cannot open input file: %s\n", argv[2]);
        closesocket(sock);
        WSACleanup();
        return 1;
    }

#define INITIAL_LINE_BUF 8192
    char* linebuf = (char*)malloc(INITIAL_LINE_BUF);
    size_t bufsize = INITIAL_LINE_BUF;
    size_t linelen = 0;
    int ch;

    unsigned int msg_index = 0;
    unsigned int sent_messages = 0;
    unsigned int ok_bytes_got = 0;
    int keep_sending = 1;

    while (keep_sending && (ch = fgetc(f)) != EOF) {
        if (linelen + 1 >= bufsize) {
            bufsize *= 2;
            linebuf = (char*)realloc(linebuf, bufsize);
            if (!linebuf) {
                printf("Memory allocation failed while reading line\n");
                fclose(f);
                closesocket(sock);
                WSACleanup();
                return 1;
            }
        }

        if (ch == '\n' || ch == '\r') {
            if (linelen == 0) continue;
            linebuf[linelen] = '\0';
            trim_line(linebuf);

        process_line:
            {
                int h1, m1, s1, h2, m2, s2;
                unsigned long bbb;
                char* msgptr = NULL;
                char* p = linebuf;
                if (sscanf(p, "%2d:%2d:%2d", &h1, &m1, &s1) != 3) { linelen = 0; continue; }
                p = strchr(p, ' '); if (!p) { linelen = 0; continue; } p++;
                if (sscanf(p, "%2d:%2d:%2d", &h2, &m2, &s2) != 3) { linelen = 0; continue; }
                p = strchr(p, ' '); if (!p) { linelen = 0; continue; } p++;
                if (sscanf(p, "%lu", &bbb) != 1) { linelen = 0; continue; }
                p = strchr(p, ' '); if (!p) { linelen = 0; continue; } p++;
                msgptr = p;

                size_t msglen = strlen(msgptr);
                size_t frame_len = 4 + 6 + 4 + msglen + 1;
                char* frame = (char*)malloc(frame_len);
                if (!frame) { linelen = 0; continue; }

                u32 idx_net = htonl(msg_index);
                memcpy(frame, &idx_net, 4);
                frame[4] = (u8)h1; frame[5] = (u8)m1; frame[6] = (u8)s1;
                frame[7] = (u8)h2; frame[8] = (u8)m2; frame[9] = (u8)s2;
                u32 bbb_net = htonl(bbb);
                memcpy(frame + 10, &bbb_net, 4);
                memcpy(frame + 14, msgptr, msglen);
                frame[14 + msglen] = 0;

                if (!send_all(sock, frame, (int)frame_len)) {
                    printf("Connection closed by server while sending message #%u\n", msg_index);
                    free(frame);
                    keep_sending = 0;
                    break;
                }

                free(frame);
                sent_messages++;
                msg_index++;
                linelen = 0;
                drain_ok_nonblocking(sock, &ok_bytes_got);
            }
        }
        else {
            linebuf[linelen++] = (char)ch;
        }
    }

    /* Process last line if file has no newline at the end (e.g., "stop") */
    if (linelen > 0 && keep_sending) {
        linebuf[linelen] = '\0';
        trim_line(linebuf);
        goto process_line;
    }

    free(linebuf);
    fclose(f);

    /* Wait for remaining "ok" */
    unsigned int need_ok = sent_messages * 2;
    char okbuf[256];
    while (ok_bytes_got < need_ok) {
        int n = recv(sock, okbuf, sizeof(okbuf), 0);
        if (n <= 0) break;
        ok_bytes_got += (unsigned int)n;
    }

    closesocket(sock);
    WSACleanup();

    printf("Client finished. Sent %u messages. Got %u/%u ack bytes.\n",
        sent_messages, ok_bytes_got, sent_messages * 2);

    return 0;
}
