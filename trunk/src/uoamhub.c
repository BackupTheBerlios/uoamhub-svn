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
#include <sys/stat.h>
#include <sys/wait.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#define MAX_DOMAINS 64
#define MAX_CLIENTS 256
#define MAX_CHATS 8

static const char VERSION[] = "0.1.0";
static int verbose = 1;
static int should_exit = 0;

struct config {
    unsigned port;
    struct addrinfo *bind_address;
    char *password;
    int no_daemon;
    const char *pidfile, *logger, *chroot_dir;
    uid_t uid;
    gid_t gid;
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
    struct client *prev, *next;
    unsigned id, master_id;
    int sockfd;
    struct domain *domain;
    int should_destroy:1, handshake:1, authorized:1, have_position:1,
        chat_enabled:1;
    struct player_info info;
    struct chat *chats[MAX_CHATS];
    unsigned num_chats;
};

struct domain {
    struct domain *prev, *next;
    char password[20];
    struct host *host;
    struct client *clients_head;
    unsigned num_clients;
};

struct host {
    const struct config *config;
    struct domain *domains_head;
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
    0xd0, 0x16, 0xd0, 0x16, 0xff, 0xff, 0xff, 0xff,
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
};

static unsigned char packet_poll[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff,
};

static unsigned char packet_response2[] = {
    0x05, 0x00, 0x0f, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x38, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0xd0, 0x16, 0xd0, 0x16, 0xff, 0xff, 0xff, 0xff,
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
            " --password file    single-domain, only accept the password from the file\n"
            " --port port\n"
            " -p port        listen on this port (default 2000)\n"
            " --logger program\n"
            " -l program     specifies a logger program (executed by /bin/sh)\n"
            " --chroot dir   chroot into this directory (requires root)\n"
            " --user username\n"
            " -u username    change user id (don't run uoamhub as root!)\n"
            " -D             don't detach (daemonize)\n"
            " --pidfile file create a pid file\n"
            "\n"
            );
    exit(1);
}

static int read_file_string(const char *filename, char **value) {
    FILE *file;
    char line[1024], *p;
    int save_errno;
    size_t len;

    assert(value != NULL);
    assert(*value == NULL);

    file = fopen(filename, "r");
    if (file == NULL)
        return -1;

    p = fgets(line, sizeof(line), file);
    save_errno = errno;
    fclose(file);
    if (p == NULL) {
        errno = save_errno;
        return -1;
    }

    while (*p > 0 && *p <= 0x20)
        p++;

    len = strlen(p);

    while (p[len - 1] > 0 && p[len - 1] <= 0x20)
        len--;

    p[len] = 0;

    *value = strdup(p);
    if (*value == NULL)
        return -1;

    return 0;
}

static void read_config(struct config *config, int argc, char **argv) {
    int ret;
    struct addrinfo hints;
    static const struct option long_options[] = {
        {"version", 0, 0, 'V'},
        {"verbose", 0, 0, 'v'},
        {"quiet", 0, 0, 'q'},
        {"help", 0, 0, 'h'},
        {"port", 1, 0, 'p'},
        {"chroot", 1, 0, 'r'},
        {"user", 1, 0, 'u'},
        {"logger", 1, 0, 'l'},
        {"pidfile", 1, 0, 'P'},
        {"password", 1, 0, 'w'},
        {0,0,0,0}
    };
    struct passwd *pw;
    struct stat st;

    memset(config, 0, sizeof(*config));
    config->port = 2000;

    while (1) {
        int option_index = 0;

        ret = getopt_long(argc, argv, "Vvqhp:r:u:Dl:w:",
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
        case 'p':
            config->port = (unsigned)strtoul(optarg, NULL, 10);
            if (config->port == 0) {
                fprintf(stderr, "invalid port specification\n");
                exit(1);
            }
            break;
        case 'w':
            if (config->password != NULL) {
                free(config->password);
                config->password = NULL;
            }

            ret = read_file_string(optarg, &config->password);
            if (ret < 0) {
                fprintf(stderr, "failed to read '%s': %s\n",
                        optarg, strerror(errno));
                exit(1);
            }

            break;
        case 'D':
            config->no_daemon = 1;
            break;
        case 'P':
            config->pidfile = optarg;
            break;
        case 'l':
            config->logger = optarg;
            break;
        case 'r':
            ret = stat(optarg, &st);
            if (ret < 0) {
                fprintf(stderr, "failed to stat '%s': %s\n",
                        optarg, strerror(errno));
                exit(1);
            }
            if (!S_ISDIR(st.st_mode)) {
                fprintf(stderr, "not a directory: '%s'\n",
                        optarg);
                exit(1);
            }

            config->chroot_dir = optarg;
            break;
        case 'u':
            pw = getpwnam(optarg);
            if (pw == NULL) {
                fprintf(stderr, "user '%s' not found\n", optarg);
                exit(1);
            }
            if (pw->pw_uid == 0) {
                fprintf(stderr, "setuid root is not allowed\n");
                exit(1);
            }
            config->uid = pw->pw_uid;
            config->gid = pw->pw_gid;
            break;
        default:
            exit(1);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "unrecognized argument: %s\n", argv[optind]);
        usage();
    }

    if (geteuid() == 0 && config->uid == 0) {
        fprintf(stderr, "running uoamhub as root is a Bad Thing(TM), please use --user\n");
        exit(1);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo_helper("*", config->port, &hints, &config->bind_address);
    if (ret < 0) {
        fprintf(stderr, "getaddrinfo_helper failed: %s\n",
                strerror(errno));
        exit(1);
    }
}

static void free_config(struct config *config) {
    if (config->bind_address != NULL)
        freeaddrinfo(config->bind_address);

    if (config->password != NULL)
        free(config->password);

    memset(config, 0, sizeof(*config));
}

static void setup(struct config *config, int *sockfdp) {
    int ret, sockfd, parentfd = -1, loggerfd = -1;
    pid_t logger_pid = -1;
    struct sigaction sa;

    /* server socket stuff */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "failed to create socket: %s\n",
                strerror(errno));
        exit(1);
    }

    ret = bind(sockfd, config->bind_address->ai_addr,
               config->bind_address->ai_addrlen);
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

    *sockfdp = sockfd;

    /* daemonize */
    if (!config->no_daemon && getppid() != 1) {
        int fds[2];
        pid_t pid;

        ret = pipe(fds);
        if (ret < 0) {
            fprintf(stderr, "pipe failed: %s\n", strerror(errno));
            exit(1);
        }

        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "fork failed: %s\n", strerror(errno));
            exit(1);
        }

        if (pid > 0) {
            int status;
            fd_set rfds;
            char buffer[256];
            struct timeval tv;

            close(fds[1]);

            if (verbose >= 4)
                fprintf(stderr, "waiting for daemon process\n");

            do {
                FD_ZERO(&rfds);
                FD_SET(fds[0], &rfds);
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                ret = select(fds[0] + 1, &rfds, NULL, NULL, &tv);
                if (ret > 0 && read(fds[0], buffer, sizeof(buffer)) > 0) {
                    if (verbose >= 2)
                        fprintf(stderr, "detaching\n");
                    exit(0);
                }

                pid = waitpid(pid, &status, WNOHANG);
            } while (pid <= 0);

            if (verbose >= 3)
                fprintf(stderr, "daemon process exited with %d\n",
                        WEXITSTATUS(status));
            exit(WEXITSTATUS(status));
        }

        close(fds[0]);
        parentfd = fds[1];

        setsid();

        close(0);

        signal(SIGTSTP, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);
        signal(SIGTTIN, SIG_IGN);

        if (verbose >= 3)
            printf("daemonized as pid %d\n", getpid());
    }

    /* write PID file */
    if (config->pidfile != NULL) {
        FILE *file;

        file = fopen(config->pidfile, "w");
        if (file == NULL) {
            fprintf(stderr, "failed to create '%s': %s\n",
                    config->pidfile, strerror(errno));
            exit(1);
        }

        fprintf(file, "%d\n", getpid());
        fclose(file);
    }

    /* start logger process */
    if (config->logger != NULL) {
        int fds[2];

        if (verbose >= 3)
            printf("starting logger '%s'\n", config->logger);

        ret = pipe(fds);
        if (ret < 0) {
            fprintf(stderr, "pipe failed: %s\n", strerror(errno));
            exit(1);
        }

        logger_pid = fork();
        if (logger_pid < 0) {
            fprintf(stderr, "fork failed: %s\n", strerror(errno));
            exit(1);
        } else if (logger_pid == 0) {
            if (fds[0] != 0) {
                dup2(fds[0], 0);
                close(fds[0]);
            }

            close(fds[1]);
            close(1);
            close(2);
            close(sockfd);

            execl("/bin/sh", "sh", "-c", config->logger, NULL);
            exit(1);
        }

        if (verbose >= 2)
            printf("logger started as pid %d\n", logger_pid);

        close(fds[0]);
        loggerfd = fds[1];

        if (verbose >= 3)
            printf("logger connected\n");
    }

    /* chroot */
    if (config->chroot_dir != NULL) {
        ret = chroot(config->chroot_dir);
        if (ret < 0) {
            fprintf(stderr, "chroot '%s' failed: %s\n",
                    config->chroot_dir, strerror(errno));
            exit(1);
        }
    }

    chdir("/");

    /* setuid */
    if (config->uid > 0) {
        ret = setgroups(0, NULL);
        if (ret < 0) {
            fprintf(stderr, "setgroups failed: %s\n", strerror(errno));
            exit(1);
        }

        ret = setregid(config->gid, config->gid);
        if (ret < 0) {
            fprintf(stderr, "setgid failed: %s\n", strerror(errno));
            exit(1);
        }

        ret = setreuid(config->uid, config->uid);
        if (ret < 0) {
            fprintf(stderr, "setuid failed: %s\n", strerror(errno));
            exit(1);
        }
    } else if (getuid() == 0) {
        /* drop a real_uid root */
        setuid(geteuid());
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

    /* send parent process a signal */
    if (parentfd >= 0) {
        if (verbose >= 4)
            fprintf(stderr, "closing parent pipe\n");
        write(parentfd, &parentfd, sizeof(parentfd));
        close(parentfd);
    }

    /* now connect logger */
    if (loggerfd >= 0) {
        dup2(loggerfd, 1);
        dup2(loggerfd, 2);
        close(loggerfd);
    }
}

static void free_client(struct client *client) {
    unsigned z;

    assert(client != NULL);
    assert(client->domain == NULL);
    assert(client->prev == NULL);
    assert(client->next == NULL);

    if (client->sockfd >= 0)
        close(client->sockfd);

    for (z = 0; z < client->num_chats; z++) {
        free(client->chats[z]);
    }

    free(client);
}

static int add_client(struct domain *domain, struct client *client) {
    assert(client->domain == NULL);

    if (domain->num_clients >= MAX_CLIENTS)
        return 0;

    if (domain->clients_head == NULL) {
        assert(domain->num_clients == 0);

        client->next = client;
        client->prev = client;
        domain->clients_head = client;
    } else {
        assert(domain->num_clients > 0);

        client->prev = domain->clients_head->prev;
        client->next = domain->clients_head;
        client->prev->next = client;
        client->next->prev = client;
    }

    domain->num_clients++;
    client->domain = domain;

    return 1;
}

static void remove_client(struct client *client) {
    assert(client->domain != NULL);
    assert(client->domain->num_clients > 0);

    client->domain->num_clients--;

    if (client->domain->num_clients == 0) {
        client->domain->clients_head = NULL;
    } else {
        client->prev->next = client->next;
        client->next->prev = client->prev;

        if (client->domain->clients_head == client)
            client->domain->clients_head = client->next;
    }

    client->prev = NULL;
    client->next = NULL;
    client->domain = NULL;
}

static struct client *create_client(struct domain *domain, int sockfd, unsigned id) {
    struct client *client;
    int ret;

    client = calloc(1, sizeof(*client));
    if (client == NULL)
        return NULL;

    client->id = id;
    client->sockfd = sockfd;

    ret = add_client(domain, client);
    if (!ret) {
        fprintf(stderr, "domain 0 is full, rejecting new client %u\n", id);
        free_client(client);
        return NULL;
    }

    if (verbose >= 1)
        printf("new client: %u\n", client->id);

    return client;
}

static void kill_client(struct client *client) {
    if (verbose > 0)
        printf("kill_client %u\n", client->id);

    remove_client(client);
    free_client(client);
}

/** find a client with the specified id on the whole host (all
    domains) */
static struct client *get_client(struct host *host, unsigned id) {
    struct domain *domain = host->domains_head;

    if (domain == NULL)
        return NULL;

    do {
        struct client *client = domain->clients_head;

        assert(domain->host == host);

        if (client != NULL) {
            do {
                assert(client->domain == domain);

                if (client->id == id)
                    return client;

                client = client->next;
            } while (client != domain->clients_head);
        }

        domain = domain->next;
    } while (domain != host->domains_head);

    return NULL;
}

static struct domain *get_domain(struct host *host, const char *password) {
    struct domain *domain = host->domains_head;

    if (domain == NULL)
        return NULL;

    do {
        if (strcmp(password, domain->password) == 0)
            return domain;

        domain = domain->next;
    } while (domain != host->domains_head);

    return NULL;
}

static struct domain *create_domain(struct host *host, const char *password) {
    size_t password_len;
    struct domain *domain;

    password_len = strlen(password);
    if (password_len >= sizeof(domain->password)) {
        fprintf(stderr, "password too long\n");
        return NULL;
    }

    if (host->num_domains >= MAX_DOMAINS) {
        fprintf(stderr, "domain table is full\n");
        return NULL;
    }

    domain = calloc(1, sizeof(*domain));
    if (domain == NULL)
        return NULL;

    memcpy(domain->password, password, password_len);
    domain->host = host;

    if (host->domains_head == NULL) {
        assert(host->num_domains == 0);

        domain->prev = domain;
        domain->next = domain;
        host->domains_head = domain;
    } else {
        assert(host->num_domains > 0);

        domain->prev = host->domains_head->prev;
        domain->next = host->domains_head;

        host->domains_head->prev->next = domain;
        host->domains_head->prev = domain;
    }

    host->num_domains++;

    if (verbose >= 2)
        printf("created domain '%s'\n", password);

    return domain;
}

static void kill_domain(struct domain *domain) {
    struct host *host;

    assert(domain != NULL);
    assert(domain->host != NULL);

    host = domain->host;

    while (domain->num_clients > 0)
        kill_client(domain->clients_head->prev);

    host->num_domains--;

    if (host->num_domains == 0) {
        assert(domain->next == domain);
        assert(domain->prev == domain);

        host->domains_head = NULL;
    } else {
        if (domain == host->domains_head)
            host->domains_head = domain->next;

        domain->next->prev = domain->prev;
        domain->prev->next = domain->next;
    }
}

static int move_client(struct client *client, struct domain *domain) {
    int ret;
    struct domain *old_domain = client->domain;

    assert(client != NULL);
    assert(client->domain != NULL);
    assert(domain != NULL);
    assert(client->domain->host == domain->host);

    if (client->domain == domain)
        return 1;

    remove_client(client);
    ret = add_client(domain, client);
    if (!ret) {
        printf("domain '%s' is full\n", domain->password);
        add_client(old_domain, client);
        return 0;
    }

    return 1;
}

static void enqueue_client_chat(struct client *client,
                                const void *data, size_t size) {
    struct chat *chat;

    if (!client->chat_enabled || client->num_chats >= MAX_CHATS)
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
    struct client *client = domain->clients_head;

    assert(size <= 2048);

    if (client == NULL)
        return;

    do {
        enqueue_client_chat(client, data, size);

        client = client->next;
    } while (client != domain->clients_head);
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
            fputc(data[x] >= 0x20 && data[x] < 0x80 ? data[x] : '.', file);

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

    if (response[2] == 0x0c || response[2] == 0x0f) {
        unsigned master_id = client->master_id == 0
            ? client->id : client->master_id;
        write_uint32(response + 20, (uint32_t)master_id);
    }

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
    size_t pos;
    unsigned num = 0;

    memcpy(buffer, packet_poll, sizeof(packet_poll));
    pos = sizeof(packet_poll);

    if (domain->clients_head != NULL) {
        struct client *client2 = domain->clients_head;
        const size_t max_pos = sizeof(buffer) - sizeof(client->info.noip) - 4;

        do {
            if (client2->info.noip.name[0] == 0 ||
                client2->master_id != 0) {
                client2 = client2->next;
                continue;
            }

            memcpy(buffer + pos, &client2->info.noip,
                   sizeof(client2->info.noip));
            num++;
            pos += sizeof(client2->info.noip);

            client2 = client2->next;
        } while (pos <= max_pos && client2 != domain->clients_head);
    }

    write_uint32(buffer + 24, (uint32_t)num);
    write_uint32(buffer + 32, (uint32_t)num);

    memset(buffer + pos, 0, 4);
    pos += 4;

    respond(client, sequence, buffer, pos);
}

static int login(struct client *client, const char *password) {
    struct domain *domain;
    int ret;

    if (password[0] == 0) {
        fprintf(stderr, "empty password from client %u, rejecting\n",
                client->id);
        client->should_destroy = 1;
        return 0;
    }

    domain = get_domain(client->domain->host, password);
    if (domain == NULL) {
        if (client->domain->host->config->password != NULL &&
            strcmp(password, client->domain->host->config->password) != 0) {
            fprintf(stderr, "wrong password, rejecting client %u\n",
                    client->id);
            client->should_destroy = 1;
            return 0;
        }

        domain = create_domain(client->domain->host, password);
        if (domain == NULL) {
            fprintf(stderr, "domain creation failed, rejecting client %u\n",
                    client->id);
            client->should_destroy = 1;
            return 0;
        }
    }

    ret = move_client(client, domain);
    if (!ret) {
        client->should_destroy = 1;
        return 0;
    }

    client->authorized = 1;

    if (verbose >= 1)
        printf("client %u logged into domain '%s'\n",
               client->id, domain->password);

    return 1;
}

static void handle_poll(struct client *client, unsigned sequence) {
    client->chat_enabled = 1;

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

    if (data[2] == 0x0b) {
        if (!client->handshake) {
            if (length < 24) {
                /* too short */
                client->should_destroy = 1;
                return;
            }

            client->master_id = read_uint32(data + 20);
            if (client->master_id != 0) {
                struct client *master;

                master = get_client(client->domain->host, client->master_id);
                if (master == NULL) {
                    if (verbose >= 1)
                        fprintf(stderr, "invalid master id in handshake, killing client %u\n",
                                client->id);
                    client->should_destroy = 1;
                    return;
                }

            }
        }

        client->handshake = 1;

        snprintf((char*)packet_handshake_response + 26, 6, "%u", client->domain->host->config->port);

        respond(client, sequence,
                packet_handshake_response,
                sizeof(packet_handshake_response));
        return;
    }

    if (!client->handshake) {
        /* handshake omitted, kill this client */
        if (verbose >= 1)
            fprintf(stderr, "handshake omitted, killing client %u\n",
                    client->id);
        client->should_destroy = 1;
        return;
    }

    switch (data[2]) {
    case 0x00:
        if (!client->authorized) {
            int ret;

            if (memchr(data + 24, 0, 20) == NULL) {
                fprintf(stderr, "malformed password field from, killing client %u\n",
                        client->id);
                client->should_destroy = 1;
                return;
            }

            ret = login(client, (const char*)(data + 24));
            if (!ret)
                return;
        }

        if (data[22] == 0x02) {
            /* 00 00 02 00: client polls */

            handle_query_list(client, sequence);
        } else if (data[20] == 0x01 && data[22] == 0x01) {
            /* 01 00 01 00: poll chat */

            handle_poll(client, sequence);
        } else if (data[20] == 0x01) {
            /* 01 00 00 00: chat */

            if (length < 2048)
                enqueue_chat(client->domain, data + 52, length - 52);

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
    struct domain *domain_zero, *domain;
    unsigned next_client_id = 1;

    read_config(&config, argc, argv);

    /* setup uid, sockets, chroot, logger etc. */
    setup(&config, &sockfd);
    
    /* create domain 0 */
    memset(&host, 0, sizeof(host));
    host.config = &config;

    domain_zero = create_domain(&host, "");
    if (domain_zero == NULL) {
        fprintf(stderr, "failed to create domain 0\n");
        exit(1);
    }

    /* main loop */
    do {
        fd_set rfds;
        int max_fd;

        /* select() on all sockets */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        max_fd = sockfd;

        domain = host.domains_head;
        assert(domain == domain_zero);

        do {
            struct client *client, *next_client = domain->clients_head;

            while (next_client != NULL) {
                client = next_client;
                next_client = client->next;
                if (next_client == domain->clients_head)
                    next_client = NULL;

                assert(client->domain == domain);

                if (client->should_destroy) {
                    kill_client(client);
                    continue;
                }

                FD_SET(client->sockfd, &rfds);
                if (client->sockfd > max_fd)
                    max_fd = client->sockfd;
            }

            if (domain != domain_zero && domain->num_clients == 0) {
                /* empty domain, delete it */
                domain = domain->next;
                kill_domain(domain->prev);
                assert(host.domains_head == domain_zero);
                continue;
            }

            domain = domain->next;
        } while (domain != host.domains_head);

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
                create_client(domain_zero, ret, next_client_id++);
            } else {
                fprintf(stderr, "accept failed: %s\n", strerror(errno));
            }
        }

        domain = host.domains_head;
        assert(domain == domain_zero);

        do {
            struct client *client, *next_client = domain->clients_head;

            while (next_client != NULL) {
                client = next_client;
                next_client = client->next;
                if (next_client == domain->clients_head)
                    next_client = NULL;

                assert(client->domain == domain);

                if (FD_ISSET(client->sockfd, &rfds)) {
                    FD_CLR(client->sockfd, &rfds);
                    client_data_available(client);
                }
            }

            domain = domain->next;
        } while (domain != host.domains_head);
    } while (!should_exit);

    /* cleanup */
    close(sockfd);

    while (host.num_domains > 0)
        kill_domain(host.domains_head->prev);

    free_config(&config);

    if (verbose >= 1)
        printf("exiting\n");
}
