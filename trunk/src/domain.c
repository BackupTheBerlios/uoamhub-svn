/*
 * uoamhub
 *
 * (c) 2004-2007 Max Kellermann <max@duempel.org>
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

#include "domain.h"
#include "client.h"
#include "config.h"
#include "host.h"
#include "log.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct domain *
create_domain(struct host *host, const char *password)
{
    size_t password_len;
    struct domain *domain;

    password_len = strlen(password);
    if (password_len >= sizeof(domain->password)) {
        log(1, "password too long: %u\n", (unsigned)password_len);
        return NULL;
    }

    if (host_domains_full(host)) {
        log(1, "domain table is full: %u\n", host->num_domains);
        return NULL;
    }

    domain = calloc(1, sizeof(*domain));
    if (domain == NULL)
        return NULL;

    memcpy(domain->password, password, password_len);

    host_add_domain(host, domain);

    log(2, "created domain '%s'\n", password);

    return domain;
}

void
kill_domain(struct domain *domain)
{
    assert(domain != NULL);
    assert(domain->host != NULL);

    log(2, "killing domain '%s'\n", domain->password);

    while (domain->num_clients > 0)
        kill_client(domain->clients_head->prev);

    host_remove_domain(domain->host, domain);

    free(domain);
}

struct client *
domain_get_client(struct domain *domain, uint32_t id)
{
    struct client *client = domain->clients_head;

    if (client == NULL)
        return NULL;

    do {
        assert(client->domain == domain);

        if (client->id == id)
            return client;

        client = client->next;
    } while (client != domain->clients_head);

    return NULL;
}

int
add_client(struct domain *domain, struct client *client)
{
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

void
remove_client(struct client *client)
{
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
