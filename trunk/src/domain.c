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

#include <assert.h>

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
