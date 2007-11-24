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

#include "host.h"
#include "domain.h"
#include "client.h"
#include "config.h"

#include <assert.h>
#include <string.h>

int
host_domains_full(struct host *host)
{
    return host->num_domains >= MAX_DOMAINS;
}

void
host_add_domain(struct host *host, struct domain *domain)
{
    assert(host != NULL);
    assert(domain != NULL);
    assert(domain->host == NULL);

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
}

void
host_remove_domain(struct host *host, struct domain *domain)
{
    assert(host != NULL);
    assert(domain != NULL);
    assert(domain->host == host);

    domain->host = NULL;

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

struct client *
get_client(struct host *host, uint32_t id)
{
    struct domain *domain = host->domains_head;
    struct client *client;

    if (domain == NULL)
        return NULL;

    do {
        assert(domain->host == host);

        client = domain_get_client(domain, id);
        if (client != NULL)
            return client;

        domain = domain->next;
    } while (domain != host->domains_head);

    return NULL;
}

struct domain *
get_domain(struct host *host, const char *password)
{
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
