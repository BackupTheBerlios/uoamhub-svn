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
#define MAX_CHATS 8

static int verbose = 9;
static int should_exit = 0;

struct noip_player_info {
    char name[64];
    unsigned char reserved[12];
    unsigned char position[16];
};

struct player_info {
    unsigned char ip[4];
    struct noip_player_info noip;
};

struct chat {
    size_t size;
    char data[1];
};

struct client {
    int sockfd;
    int handshake:1;
    struct player_info info;
    struct chat *chats[MAX_CHATS];
    unsigned num_chats;
};

struct domain {
    struct client clients[MAX_CLIENTS];
    unsigned num_clients;
};

struct packet_header {
    /* WARNING: big endian */
    unsigned char five, zero1, type, three, ten;
    unsigned char reserved[3];
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

static unsigned char packet_chat[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xa8, 0x5f, 0x6a, 0x00,
};

static unsigned char packet_poll[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
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
    unsigned z;
    struct client *client = &domain->clients[n];

    assert(domain != NULL);
    assert(domain->num_clients < MAX_CLIENTS);
    assert(domain->num_clients > 0);
    assert(n < domain->num_clients);

    printf("kill_client num=%u\n", domain->num_clients);

    close(domain->clients[n].sockfd);

    for (z = 0; z < client->num_chats; z++) {
        free(client->chats[z]);
    }

    domain->num_clients--;

    if (n < domain->num_clients)
        memmove(domain->clients + n, domain->clients + n + 1,
                (domain->num_clients - n) * sizeof(*domain->clients));
}

static void enqueue_chat(struct domain *domain,
                         const void *data, size_t size) {
    struct client *client;
    struct chat *chat;
    unsigned z;

    printf("entering enqueue_chat\n");
    for (z = 0, client = domain->clients; z < domain->num_clients;
         z++, client++) {
        /*if (client->info.noip.name[0] == 0)
          continue;*/

        if (client->num_chats >= MAX_CHATS)
            continue;

        chat = malloc(sizeof(*chat) - sizeof(chat->data) + size);
        if (chat == NULL)
            break;

        printf("  chat_add to %s num=%u\n", client->info.noip.name, client->num_chats);

        chat->size = size;
        memcpy(chat->data, data, size);

        client->chats[client->num_chats++] = chat;
    }
    printf("leaving enqueue_chat\n");
}

static void respond(struct client *client, unsigned char *request,
                    unsigned char *response, size_t response_length) {
    size_t i;

    assert(response_length >= 16);

    memcpy(response + 12, request + 12, 4);

    send(client->sockfd, response, response_length, 0);

    printf("response: len=%lu\n", (unsigned long)response_length);
    for (i = 0; i < response_length; i++) {
        printf("%02x ", response[i]);
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
                        unsigned char buffer[4096], buffer2[4096];
                        ssize_t nbytes, i;
                        struct packet_header *header = (struct packet_header*)buffer;

                        nbytes = recv(client->sockfd, buffer, sizeof(buffer), 0);
                        printf("packet: client=%u/%u len=%ld\n", z, w, (long)nbytes);
                        for (i = 0; i < nbytes; i++) {
                            printf("%02x ", buffer[i]);
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
                            if (buffer[22] == 0x02) {
                                /* 00 00 02 00: client polls */
                                size_t pos;
                                unsigned f, num = 0;

                                memcpy(buffer2, packet_poll, sizeof(packet_poll));
                                pos = sizeof(packet_poll);

                                printf("making poll packet pos=%u: %u\n", pos, domains[z].num_clients);
                                for (f = 0; f < domains[z].num_clients; f++) {
                                    if (domains[z].clients[f].info.noip.name[0] == 0)
                                        continue;
                                    printf("adding client info %s\n", domains[z].clients[f].info.noip.name);
                                    memcpy(buffer2 + pos, &domains[z].clients[f].info.noip,
                                           sizeof(domains[z].clients[f].info.noip));
                                    num++;
                                    pos += sizeof(client->info.noip);
                                }
                                printf("after client loop pos=%u\n", pos);

                                buffer2[24] = (unsigned char)num;
                                buffer2[32] = (unsigned char)num;

                                memset(buffer2 + pos, 0, 4);
                                pos += 4;

                                buffer2[8] = pos & 0xff;
                                buffer2[9] = (pos >> 8) & 0xff;
                                buffer2[10] = 0;
                                buffer2[11] = 0;
                                buffer2[16] = (pos - 24) & 0xff;
                                buffer2[17] = ((pos - 24) >> 8) & 0xff;
                                buffer2[18] = 0;
                                buffer2[19] = 0;

                                respond(client, buffer, buffer2, pos);
                            } else if (buffer[20] == 0x01 && buffer[22] == 0x01) {
                                /* 01 00 01 00: poll chat */

                                printf("poll_chat num=%u\n", client->num_chats);

                                if (client->num_chats > 0) {
                                    size_t pos;

                                    memcpy(buffer2, packet_chat, sizeof(packet_chat));
                                    pos = sizeof(packet_chat);

                                    memcpy(buffer2 + pos, client->chats[0]->data,
                                           client->chats[0]->size);
                                    pos += client->chats[0]->size;

                                    free(client->chats[0]);
                                    client->num_chats--;
                                    if (client->num_chats > 0)
                                        memmove(client->chats, client->chats + 1,
                                                sizeof(client->chats[0]) * client->num_chats);

                                    memset(buffer2 + pos, 0, 5);
                                    pos += 5;

                                    buffer2[8] = pos & 0xff;
                                    buffer2[9] = (pos >> 8) & 0xff;
                                    buffer2[10] = 0;
                                    buffer2[11] = 0;
                                    buffer2[16] = (pos - 24) & 0xff;
                                    buffer2[17] = ((pos - 24) >> 8) & 0xff;
                                    buffer2[18] = 0;
                                    buffer2[19] = 0;

                                    respond(client, buffer, buffer2, pos);
                                } else {
                                    respond(client, buffer,
                                            packet_ack2,
                                            sizeof(packet_ack2));
                                }
                            } else if (buffer[20] == 0x01) {
                                /* 01 00 00 00: client sends chat message */
                                if (buffer[52] == 0x01)
                                    enqueue_chat(&domains[z], buffer + 60,
                                                 (size_t)nbytes - 60);

                                respond(client, buffer,
                                        packet_ack,
                                        sizeof(packet_ack));
                            } else {
                                /* 00 00 10 00 or 00 00 00 00: client sends player position */

                                memcpy(&client->info, buffer + 44, sizeof(client->info));

                                respond(client, buffer,
                                        packet_ack,
                                        sizeof(packet_ack));
                            }
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
