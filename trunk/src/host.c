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

#include <assert.h>
#include <string.h>

struct client *
get_client(struct host *host, uint32_t id)
{
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
