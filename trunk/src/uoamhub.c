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

/*
 * dedicated server for UOAutoMap (which is non-free)
 *
 * Home page: http://max.kellermann.name/projects/uoamhub/
 *
 */

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>

#define MAX_DOMAINS 8
#define MAX_CLIENTS 64
#define MAX_CHATS 8

static const char VERSION[] = "0.1.0";
static int verbose = 1;
static int should_exit = 0;

struct config {
    struct addrinfo *bind_address;
};

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
    unsigned id;
    int sockfd;
    struct domain *domain;
    int should_destroy:1, handshake:1, authorized:1, have_position:1;
    struct player_info info;
    struct chat *chats[MAX_CHATS];
    unsigned num_chats;
};

struct domain {
    char password[20];
    struct host *host;
    struct client clients[MAX_CLIENTS];
    unsigned num_clients;
};

struct host {
    struct domain domains[MAX_DOMAINS];
    unsigned num_domains;
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

    if (verbose >= 2)
        printf("signal received, shutting down...\n");

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

static void usage(void) __attribute__ ((noreturn));
static void usage(void) {
    fprintf(stderr, "usage: uoamhub [options]\n\n"
            "valid options:\n"
            " -h             help (this text)\n"
            " -V             print version number\n"
            " --verbose\n"
            " -v             increase verbosity (default 1)\n"
            " --quiet\n"
            " -q             reset verbosity to 0\n"
            );
    exit(1);
}

static void read_config(struct config *config, int argc, char **argv) {
    int ret;
    struct addrinfo hints;
    static const struct option long_options[] = {
        {"version", 0, 0, 'V'},
        {"verbose", 0, 0, 'v'},
        {"quiet", 0, 0, 'q'},
        {"help", 0, 0, 'h'},
        {0,0,0,0}
    };

    memset(config, 0, sizeof(*config));

    while (1) {
        int option_index = 0;

        ret = getopt_long(argc, argv, "Vvqh",
                          long_options, &option_index);
        if (ret == -1)
            break;

        switch (ret) {
        case 'V':
            printf("uoamhub v%s\n", VERSION);
            exit(0);
        case 'v':
            verbose++;
            break;
        case 'q':
            verbose = 0;
            break;
        case 'h':
            usage();
        default:
            exit(1);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "unrecognized argument: %s\n", argv[optind]);
        usage();
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo_helper("*", 2000, &hints, &config->bind_address);
    if (ret < 0) {
        fprintf(stderr, "getaddrinfo_helper failed: %s\n",
                strerror(errno));
        exit(1);
    }
}

static void free_config(struct config *config) {
    if (config->bind_address)
        freeaddrinfo(config->bind_address);

    memset(config, 0, sizeof(*config));
}

static unsigned client_index(struct client *client) {
    assert(client != NULL);
    assert(client->domain != NULL);
    assert(client->domain->num_clients > 0);
    assert(client >= client->domain->clients);
    assert(client < client->domain->clients + client->domain->num_clients);

    return (client - client->domain->clients) / sizeof(*client);
}

static struct client *add_client(struct domain *domain, const struct client *old) {
    struct client *client;

    if (domain->num_clients >= MAX_CLIENTS)
        return NULL;

    client = &domain->clients[domain->num_clients++];
    memcpy(client, old, sizeof(*client));

    client->domain = domain;

    return client;
}

static void remove_client(struct domain *domain, unsigned n) {
    assert(domain != NULL);
    assert(domain->num_clients > 0);
    assert(n < domain->num_clients);

    domain->num_clients--;

    if (n < domain->num_clients)
        memmove(domain->clients + n, domain->clients + n + 1,
                (domain->num_clients - n) * sizeof(*domain->clients));
}

static struct client *create_client(struct domain *domain, int sockfd, unsigned id) {
    struct client client, *ret;

    memset(&client, 0, sizeof(client));
    client.id = id;
    client.sockfd = sockfd;

    ret = add_client(domain, &client);
    if (ret == NULL) {
        fprintf(stderr, "domain 0 is full, rejecting new client %u\n", id);
        close(sockfd);
        return NULL;
    }

    if (verbose >= 1)
        printf("new client: %u\n", ret->id);

    return ret;
}

static void kill_client(struct domain *domain, unsigned n) {
    unsigned z;
    struct client *client = &domain->clients[n];

    assert(domain != NULL);
    assert(domain->num_clients < MAX_CLIENTS);
    assert(domain->num_clients > 0);
    assert(n < domain->num_clients);
    assert(client->domain == domain);

    if (verbose > 0)
        printf("kill_client %u\n", client->id);

    close(domain->clients[n].sockfd);

    for (z = 0; z < client->num_chats; z++) {
        free(client->chats[z]);
    }

    remove_client(domain, n);
}

static struct domain *get_domain(struct host *host, const char *password) {
    unsigned char z;

    for (z = 0; z < host->num_domains; z++) {
        if (strcmp(password, host->domains[z].password) == 0)
            return &host->domains[z];
    }

    return NULL;
}

static struct domain *create_domain(struct host *host, const char *password) {
    size_t password_len;
    struct domain *domain;

    password_len = strlen(password);
    if (password_len == 0) {
        fprintf(stderr, "no password\n");
        return NULL;
    }

    if (password_len >= sizeof(domain->password)) {
        fprintf(stderr, "password too long\n");
        return NULL;
    }

    if (host->num_domains >= MAX_DOMAINS) {
        fprintf(stderr, "domain table is full\n");
        return NULL;
    }

    domain = &host->domains[host->num_domains++];
    memset(domain, 0, sizeof(domain));

    memcpy(domain->password, password, password_len);
    domain->host = host;

    if (verbose >= 2)
        printf("created domain '%s'\n", password);

    return domain;
}

static void kill_domain(struct host *host, unsigned n) {
    struct domain *domain = &host->domains[n];

    while (domain->num_clients > 0)
        kill_client(domain, domain->num_clients - 1);

    host->num_domains--;

    if (n < host->num_domains)
        memmove(host->domains + n, host->domains + n + 1,
                (host->num_domains - n) * sizeof(*host->domains));
}

static struct client *move_client(struct client *client, struct domain *domain) {
    struct client *new_client;

    assert(client != NULL);
    assert(client->domain != NULL);
    assert(domain != NULL);
    assert(client->domain->host == domain->host);

    if (client->domain == domain)
        return client;

    new_client = add_client(domain, client);
    if (new_client == NULL)
        return NULL;

    remove_client(client->domain, client_index(client));

    return new_client;
}

static void enqueue_client_chat(struct client *client,
                                const void *data, size_t size) {
    struct chat *chat;

    /*if (client->info.noip.name[0] == 0)
      continue;*/

    if (client->num_chats >= MAX_CHATS)
        return;

    chat = malloc(sizeof(*chat) - sizeof(chat->data) + size);
    if (chat == NULL)
        return;

    chat->size = size;
    memcpy(chat->data, data, size);

    client->chats[client->num_chats++] = chat;
}

static void enqueue_chat(struct domain *domain,
                         const void *data, size_t size) {
    unsigned z;

    assert(size <= 2048);

    for (z = 0; z < domain->num_clients; z++) {
        enqueue_client_chat(&domain->clients[z], data, size);
    }
}

static void dump_packet(FILE *file, unsigned char *data, size_t length) {
    size_t y;

    for (y = 0; y < length; y += 0x10, data += 0x10) {
        size_t x, columns = length - y;
        if (columns > 0x10)
            columns = 0x10;

        fprintf(file, "%08lx   ", (unsigned long)y);
        for (x = 0; x < columns; x++) {
            if (x == 0x08)
                fprintf(file, " ");

            fprintf(file, "%02x ", data[x]);
        }

        for (; x < 0x10; x++) {
            if (x == 0x08)
                fprintf(file, " ");

            fprintf(file, "   ");
        }

        fprintf(file, " ");
        for (x = 0; x < columns; x++)
            fputc(data[x] >= 0x20 ? data[x] : '.', file);

        fprintf(file, "\n");
    }
}

static uint32_t read_uint32(const unsigned char *buffer) {
    return buffer[0] |
        buffer[1] << 8 |
        buffer[2] << 16 |
        buffer[3] << 24;
}

static void write_uint32(unsigned char *buffer, uint32_t value) {
    buffer[0] = value & 0xff;
    buffer[1] = (value >> 8) & 0xff;
    buffer[2] = (value >> 16) & 0xff;
    buffer[3] = (value >> 24) & 0xff;
}

static void respond(struct client *client, unsigned sequence,
                    unsigned char *response, size_t response_length) {
    assert(response_length >= 16);
    assert(response[2] != 0x02 || response_length >= 24);

    /* copy packet sequence number */
    write_uint32(response + 12, (uint32_t)sequence);

    /* write the packet length */
    write_uint32(response + 8, (uint32_t)response_length);

    if (response[2] == 0x02)
        write_uint32(response + 16, (uint32_t)(response_length - 24));

    /* dump it */
    if (verbose >= 4) {
        printf("sending to client %u\n", client->id);
        dump_packet(stdout, response, response_length);
        printf("\n");
    }

    /* send it */
    send(client->sockfd, response, response_length, 0);
}

static void process_position_update(struct client *client,
                                    const unsigned char *data, size_t length) {
    const struct player_info *info = (const struct player_info*)(data + 44);

    if (length != 0x8c) {
        fprintf(stderr, "client %u: wrong length %lu in position_update packet\n",
                client->id, (unsigned long)length);
        return;
    }

    if (memchr(info->noip.name, 0, sizeof(info->noip.name)) == NULL) {
        fprintf(stderr, "client %u: no NUL character in name\n",
                client->id);
        return;
    }

    memcpy(&client->info, info, sizeof(client->info));
    client->have_position = 1;
}

static void handle_query_list(struct client *client, unsigned sequence) {
    struct domain *domain = client->domain;
    unsigned char buffer[4096];
    const size_t max_pos = sizeof(buffer) - sizeof(client->info.noip) - 4;
    size_t pos;
    unsigned f, num = 0;

    memcpy(buffer, packet_poll, sizeof(packet_poll));
    pos = sizeof(packet_poll);

    for (f = 0; f < domain->num_clients && pos <= max_pos; f++) {
        if (domain->clients[f].info.noip.name[0] == 0)
            continue;
        memcpy(buffer + pos, &domain->clients[f].info.noip,
               sizeof(domain->clients[f].info.noip));
        num++;
        pos += sizeof(client->info.noip);
    }

    write_uint32(buffer + 24, (uint32_t)num);
    write_uint32(buffer + 32, (uint32_t)num);

    memset(buffer + pos, 0, 4);
    pos += 4;

    respond(client, sequence, buffer, pos);
}

static struct client *login(struct client *client, const char *password) {
    struct domain *domain;
    struct client *new_client;

    if (password[0] == 0) {
        fprintf(stderr, "empty password from client %u, rejecting\n",
                client->id);
        client->should_destroy = 1;
        return NULL;
    }

    domain = get_domain(client->domain->host, password);
    if (domain == NULL) {
        domain = create_domain(client->domain->host, password);
        if (domain == NULL) {
            fprintf(stderr, "domain creation failed, rejecting client %u\n",
                    client->id);
            client->should_destroy = 1;
            return NULL;
        }
    }

    new_client = move_client(client, domain);
    if (new_client == NULL) {
        client->should_destroy = 1;
        return NULL;
    }

    new_client->authorized = 1;

    if (verbose >= 1)
        printf("client %u logged into domain '%s'\n",
               new_client->id, domain->password);

    return new_client;
}

static void handle_poll(struct client *client, unsigned sequence) {
    if (client->num_chats > 0) {
        /* send the first chat entry */
        unsigned char buffer[4096];
        size_t pos;

        /* build the packet */
        memcpy(buffer, packet_chat, sizeof(packet_chat));
        pos = sizeof(packet_chat);

        memcpy(buffer + pos, client->chats[0]->data,
               client->chats[0]->size);
        pos += client->chats[0]->size;

        memset(buffer + pos, 0, 5);
        pos += 5;

        /* free memory */
        free(client->chats[0]);
        client->num_chats--;
        if (client->num_chats > 0)
            memmove(client->chats, client->chats + 1,
                    sizeof(client->chats[0]) * client->num_chats);

        /* send packet */
        respond(client, sequence, buffer, pos);
    } else {
        /* nothing in the queue */
        respond(client, sequence,
                packet_ack2,
                sizeof(packet_ack2));
    }
}

static void handle_packet(struct client *client,
                          const unsigned char *data, size_t length) {
    unsigned sequence;

    sequence = read_uint32(data + 12);

    switch (data[2]) {
    case 0x0b:
        client->handshake = 1;
        respond(client, sequence,
                packet_handshake_response,
                sizeof(packet_handshake_response));
        break;

    case 0x00:
        if (!client->authorized) {
            struct client *new_client;

            if (memchr(data + 24, 0, 20) == NULL) {
                fprintf(stderr, "malformed password field from, killing client %u\n",
                        client->id);
                client->should_destroy = 1;
                return;
            }

            new_client = login(client, (const char*)(data + 24));
            if (new_client == NULL)
                return;

            client = new_client;
        }

        if (data[22] == 0x02) {
            /* 00 00 02 00: client polls */

            handle_query_list(client, sequence);
        } else if (data[20] == 0x01 && data[22] == 0x01) {
            /* 01 00 01 00: poll chat */

            handle_poll(client, sequence);
        } else if (data[20] == 0x01) {
            /* 01 00 00 00: chat */

            if (data[52] == 0x01 && length < 2048)
                enqueue_chat(client->domain, data + 60, length - 60);

            respond(client, sequence,
                    packet_ack,
                    sizeof(packet_ack));
        } else {
            /* 00 00 10 00 or 00 00 00 00: client sends player position */

            process_position_update(client, data, length);
            respond(client, sequence,
                    packet_ack,
                    sizeof(packet_ack));
        }
        break;

    case 0x0e:
        respond(client, sequence,
                packet_response2,
                sizeof(packet_response2));
        break;
    }
}

static ssize_t select_more_data(int sockfd, unsigned char *buffer,
                                size_t max_len) {
    fd_set rfds;
    int ret;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    ret = select(sockfd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0)
        return -1;
    if (ret == 0)
        return 0;

    return recv(sockfd, buffer, max_len, 0);
}

static void client_data_available(struct client *client) {
    unsigned char buffer[4096];
    ssize_t nbytes;
    struct packet_header *header = (struct packet_header*)buffer;
    size_t position = 0, length;

    /* read from stream */
    nbytes = recv(client->sockfd, buffer, sizeof(buffer), 0);
    if (nbytes <= 0) {
        printf("client %u disconnected\n", client->id);
        client->should_destroy = 1;
        return;
    }

    if (verbose >= 4) {
        printf("received from client %u\n", client->id);
        dump_packet(stdout, buffer, (size_t)nbytes);
        printf("\n");
    }

    while (nbytes > 0 && !client->should_destroy) {
        if (nbytes < 16) {
            /* we need 16 bytes for a header */
            fprintf(stderr, "packet from client %u is too small (%lu bytes)\n",
                   client->id, (unsigned long)nbytes);
            client->should_destroy = 1;
            return;
        }

        /* check header */
        if (header->five != 0x05 || header->zero1 != 0x00 ||
            header->three != 0x03 || header->ten != 0x10) {
            fprintf(stderr, "malformed packet, killing client %u\n",
                    client->id);
            client->should_destroy = 1;
            return;
        }

        /* length check - check if the UOAM packet length is OK */
        length = read_uint32(buffer + 8);

        if (length < 16 || length > (size_t)nbytes) {
            fprintf(stderr, "malformed length %lu in packet, killing client %u\n",
                    (unsigned long)length, client->id);
            client->should_destroy = 1;
            return;
        }

        /* handle packet */
        handle_packet(client, buffer + position, length);

        nbytes -= (ssize_t)length;
        position += length;

        /* try to read more data - the first read may have stopped at
           the buffer boundary, i.e. the rest of a packet may come
           with the next recv() call, so do it here to prevent an
           error at the length check */
        if (nbytes > 0) {
            ssize_t ret;

            memmove(buffer, buffer + position, (size_t)nbytes);
            position = 0;

            ret = select_more_data(client->sockfd, buffer + nbytes,
                                   sizeof(buffer) - nbytes);
            if (ret > 0)
                nbytes += ret;
        }
    }
}

int main(int argc, char **argv) {
    struct config config;
    int ret, sockfd;
    struct host host;
    unsigned z, next_client_id = 1;
    struct sigaction sa;
    fd_set rfds;

    read_config(&config, argc, argv);

    /* create domain 0 */
    memset(&host, 0, sizeof(host));
    host.num_domains = 1;
    host.domains[0].host = &host;

    /* server socket stuff */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "failed to create socket: %s\n",
                strerror(errno));
        exit(1);
    }

    ret = bind(sockfd, config.bind_address->ai_addr,
               config.bind_address->ai_addrlen);
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
        int max_fd, i;

        /* select() on all sockets */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        max_fd = sockfd;
        for (i = 0; i < (int)host.num_domains; i++) {
            struct client *client = host.domains[i].clients;
            int w;

            for (w = 0; w < (int)host.domains[i].num_clients; w++, client++) {
                assert(client->domain == &host.domains[i]);

                if (client->should_destroy) {
                    kill_client(&host.domains[i], w--);
                    client--;
                    continue;
                }

                FD_SET(client->sockfd, &rfds);
                if (client->sockfd > max_fd)
                    max_fd = client->sockfd;
            }

            if (i > 0 && host.domains[i].num_clients == 0) {
                /* empty domain, delete it */
                kill_domain(&host, i);
                i--;
            }
        }

        ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR)
                continue;

            fprintf(stderr, "select failed: %s\n", strerror(errno));
            break;
        }

        if (ret == 0) {
            fprintf(stderr, "select returned zero\n");
            sleep(1);
        }

        /* read on all sockets where FD_ISSET is true */
        if (FD_ISSET(sockfd, &rfds)) {
            struct sockaddr addr;
            socklen_t addrlen = sizeof(addr);

            ret = accept(sockfd, &addr, &addrlen);
            if (ret >= 0) {
                create_client(&host.domains[0], ret, next_client_id++);
            } else {
                fprintf(stderr, "accept failed: %s\n", strerror(errno));
            }
        }

        for (z = 0; z < host.num_domains; z++) {
            struct client *client = host.domains[z].clients;
            unsigned w;

            for (w = 0; w < host.domains[z].num_clients; w++, client++) {
                assert(client->domain == &host.domains[z]);

                if (FD_ISSET(client->sockfd, &rfds))
                    client_data_available(client);
            }
        }
    } while (!should_exit);

    /* cleanup */
    close(sockfd);

    while (host.num_domains > 0)
        kill_domain(&host, host.num_domains - 1);

    free_config(&config);

    if (verbose >= 1)
        printf("exiting\n");
}
