/*
 * uoamhub
 * $Id$
 *
 * (c) 2004 Max Kellermann (max@duempel.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#define MAX_DOMAINS 8
#define MAX_CLIENTS 64
static int verbose = 9;
static int should_exit = 0;

struct client {
    int sockfd;
    int handshake:1;
};

struct domain {
    struct client clients[MAX_CLIENTS];
    unsigned num_clients;
};

struct packet_header {
    /* WARNING: big endian */
    unsigned char five, zero1, type, three, ten;
    char reserved[3];
    uint32_t length, counter;
};

static unsigned char packet_handshake_response[] = {
    0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xd0, 0x16, 0xd0, 0x16, 0x94, 0x96, 0x8f, 0x0a,
    0x05, 0x00, 0x32, 0x30, 0x30, 0x30, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00,
};

static unsigned char packet_ack[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

static unsigned char packet_ack2[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x2c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

static unsigned char packet_poll[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x4d, 0x69, 0x6e, 0x6b,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x66, 0xd3, 0x00, 0x00, 0x00,
    0x70, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

static unsigned char packet_response2[] = {
    0x05, 0x00, 0x0f, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x38, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0xd0, 0x16, 0xd0, 0x16, 0x94, 0x96, 0x8f, 0x0a,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
    0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
    0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
};

static void exit_signal_handler(int sig) {
    (void)sig;

    should_exit++;
}

static int getaddrinfo_helper(const char *host_and_port, int default_port,
                              const struct addrinfo *hints,
                              struct addrinfo **aip) {
    const char *colon, *host, *port;
    char buffer[256];

    colon = strchr(host_and_port, ':');
    if (colon == NULL) {
        snprintf(buffer, sizeof(buffer), "%d", default_port);

        host = host_and_port;
        port = buffer;
    } else {
        size_t len = colon - host_and_port;

        if (len >= sizeof(buffer)) {
            errno = ENAMETOOLONG;
            return EAI_SYSTEM;
        }

        memcpy(buffer, host_and_port, len);
        buffer[len] = 0;

        host = buffer;
        port = colon + 1;
    }

    if (strcmp(host, "*") == 0)
        host = "0.0.0.0";

    return getaddrinfo(host, port, hints, aip);
}

static void kill_client(struct domain *domain, unsigned n) {
    assert(domain != NULL);
    assert(domain->num_clients < MAX_CLIENTS);
    assert(domain->num_clients > 0);
    assert(n < domain->num_clients);

    printf("kill_client num=%u\n", domain->num_clients);

    close(domain->clients[n].sockfd);

    domain->num_clients--;

    if (n < domain->num_clients)
        memmove(domain->clients + n, domain->clients + n + 1,
                (domain->num_clients - n) * sizeof(*domain->clients));
}

static void respond(struct client *client, unsigned char *request,
                    unsigned char *response, size_t response_length) {
    size_t i;

    assert(response_length >= 16);

    memcpy(response + 12, request + 12, 4);

    send(client->sockfd, response, response_length, 0);

    printf("response: len=%lu\n", (unsigned long)response_length);
    for (i = 0; i < response_length; i++) {
        printf("%02x ", response[i] & 0xff);
        if (i % 16 == 15)
            printf("\n");
    }
    printf("\n\n");
}

int main(int argc, char **argv) {
    struct addrinfo hints, *bind_address;
    int ret, sockfd, max_fd;
    struct domain domains[MAX_DOMAINS];
    unsigned num_domains = 1, z, w;
    struct sigaction sa;
    fd_set rfds;

    (void)argc;
    (void)argv;

    /* create domain 0 */
    memset(domains, 0, sizeof(domains[0]));

    /* server socket stuff */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo_helper("172.30.3.1", 2000, &hints, &bind_address);
    if (ret < 0) {
        fprintf(stderr, "getaddrinfo_helper failed: %s\n",
                strerror(errno));
        exit(1);
    }

    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "failed to create socket: %s\n",
                strerror(errno));
        exit(1);
    }

    ret = bind(sockfd, bind_address->ai_addr,
               bind_address->ai_addrlen);
    if (ret < 0) {
        fprintf(stderr, "failed to bind: %s\n",
                strerror(errno));
        exit(1);
    }

    ret = listen(sockfd, 4);
    if (ret < 0) {
        fprintf(stderr, "listen failed: %s\n",
                strerror(errno));
        exit(1);
    }

    /* signals */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = exit_signal_handler;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    /* main loop */
    do {
        if (verbose > 0)
            printf("select()\n");

        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        max_fd = sockfd;
        for (z = 0; z < num_domains; z++) {
            for (w = 0; w < domains[z].num_clients; w++) {
                FD_SET(domains[z].clients[w].sockfd, &rfds);
                if (domains[z].clients[w].sockfd > max_fd)
                    max_fd = domains[z].clients[w].sockfd;
            }
        }

        ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0 && errno != EINTR) {
            fprintf(stderr, "select failed: %s\n", strerror(errno));
            exit(1);
        }

        if (verbose > 0)
            printf("after select() = %d\n", ret);

        if (ret > 0) {
            if (FD_ISSET(sockfd, &rfds)) {
                struct sockaddr addr;
                socklen_t addrlen = sizeof(addr);

                ret = accept(sockfd, &addr, &addrlen);
                if (ret < 0) {
                    fprintf(stderr, "accept failed: %s\n", strerror(errno));
                    exit(1);
                }

                if (domains[0].num_clients < MAX_CLIENTS) {
                    struct client *client = &domains[0].clients[domains[0].num_clients++];

                    printf("client connected\n");

                    memset(client, 0, sizeof(*client));
                    client->sockfd = ret;
                } else {
                    /* sorry, domain 0 is full */
                    close(sockfd);
                }
            }

            for (z = 0; z < num_domains; z++) {
                struct client *client = domains[z].clients;

                for (w = 0; w < domains[z].num_clients; w++, client++) {
                    if (FD_ISSET(client->sockfd, &rfds)) {
                        unsigned char buffer[4096];
                        ssize_t nbytes, i;
                        struct packet_header *header = (struct packet_header*)buffer;

                        nbytes = recv(client->sockfd, buffer, sizeof(buffer), 0);
                        printf("packet: client=%u/%u len=%ld\n", z, w, (long)nbytes);
                        for (i = 0; i < nbytes; i++) {
                            printf("%02x ", buffer[i] & 0xff);
                            if (i % 16 == 15)
                                printf("\n");
                        }
                        printf("\n\n");

                        if (nbytes == 0) {
                            printf("client disconnected\n");
                            kill_client(&domains[z], w--);
                            client--;
                            continue;
                        }

                        if (nbytes < 16)
                            continue;

                        if (header->five != 0x05 || header->zero1 != 0x00 ||
                            header->three != 0x03 || header->ten != 0x10) {
                            printf("wrong packet, killing client\n");
                            kill_client(&domains[z], w--);
                            client--;
                            continue;
                        }

                        switch (header->type) {
                        case 0x0b:
                            client->handshake = 1;
                            respond(client, buffer,
                                    packet_handshake_response,
                                    sizeof(packet_handshake_response));
                            break;

                        case 0x00:
                            if (buffer[22] == 0x02)
                                respond(client, buffer,
                                        packet_poll,
                                        sizeof(packet_poll));
                            else if (buffer[20] == 0x01)
                                respond(client, buffer,
                                        packet_ack2,
                                        sizeof(packet_ack2));
                            else
                                respond(client, buffer,
                                        packet_ack,
                                        sizeof(packet_ack));
                            break;

                        case 0x0e:
                            respond(client, buffer,
                                    packet_response2,
                                    sizeof(packet_response2));
                            break;
                        }
                    }
                }
            }
        }
    } while (!should_exit);

    /* cleanup */
    close(sockfd);

    for (z = 0; z < num_domains; z++) {
        struct client *client = domains[z].clients;

        for (w = 0; w < domains[z].num_clients; w++, client++) {
            close(client->sockfd);
        }
    }
}
