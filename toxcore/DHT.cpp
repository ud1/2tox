/* DHT.c
 *
 * An implementation of the DHT as seen in docs/updates/DHT.md
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*----------------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef DEBUG
#include <assert.h>
#endif

#include "logger.hpp"

#include "DHT.hpp"

#ifdef ENABLE_ASSOC_DHT
#include "assoc.h"
#endif

#include "ping.hpp"

#include "network.hpp"
#include "LAN_discovery.hpp"
#include "misc_tools.hpp"
#include "util.hpp"
#include "protocol_impl.hpp"

/* The timeout after which a node is discarded completely. */
#define KILL_NODE_TIMEOUT (BAD_NODE_TIMEOUT + PING_INTERVAL)

/* Ping interval in seconds for each random sending of a get nodes request. */
#define GET_NODE_INTERVAL 20

#define MAX_PUNCHING_PORTS 48

/* Interval in seconds between punching attempts*/
#define PUNCH_INTERVAL 3

#define MAX_NORMAL_PUNCHING_TRIES 5

#define NAT_PING_REQUEST    0
#define NAT_PING_RESPONSE   1

/* Number of get node requests to send to quickly find close nodes. */
#define MAX_BOOTSTRAP_TIMES 5

using namespace bitox;

/* Compares pk1 and pk2 with pk.
 *
 *  return 0 if both are same distance.
 *  return 1 if pk1 is closer.
 *  return 2 if pk2 is closer.
 */
int id_closest (const uint8_t *pk, const uint8_t *pk1, const uint8_t *pk2)
{
    size_t   i;
    uint8_t distance1, distance2;

    for (i = 0; i < crypto_box_PUBLICKEYBYTES; ++i)
    {

        distance1 = pk[i] ^ pk1[i];
        distance2 = pk[i] ^ pk2[i];

        if (distance1 < distance2)
        {
            return 1;
        }

        if (distance1 > distance2)
        {
            return 2;
        }
    }

    return 0;
}

/* Return index of first unequal bit number.
 */
static unsigned int bit_by_bit_cmp (const uint8_t *pk1, const uint8_t *pk2)
{
    unsigned int i, j = 0;

    for (i = 0; i < crypto_box_PUBLICKEYBYTES; ++i)
    {
        if (pk1[i] == pk2[i])
        {
            continue;
        }

        for (j = 0; j < 8; ++j)
        {
            if ( (pk1[i] & (1 << (7 - j))) != (pk2[i] & (1 << (7 - j))))
            {
                break;
            }
        }

        break;
    }

    return i * 8 + j;
}

/* Shared key generations are costly, it is therefor smart to store commonly used
 * ones so that they can re used later without being computed again.
 *
 * If shared key is already in shared_keys, copy it to shared_key.
 * else generate it into shared_key and copy it to shared_keys
 */
void get_shared_key (Shared_Keys *shared_keys, uint8_t *shared_key, const uint8_t *secret_key, const uint8_t *public_key)
{
    uint32_t i, num = ~0, curr = 0;

    for (i = 0; i < MAX_KEYS_PER_SLOT; ++i)
    {
        int index = public_key[30] * MAX_KEYS_PER_SLOT + i;

        if (shared_keys->keys[index].stored)
        {
            if (public_key_cmp (public_key, shared_keys->keys[index].public_key) == 0)
            {
                memcpy (shared_key, shared_keys->keys[index].shared_key, crypto_box_BEFORENMBYTES);
                ++shared_keys->keys[index].times_requested;
                shared_keys->keys[index].time_last_requested = unix_time();
                return;
            }

            if (num != 0)
            {
                if (is_timeout (shared_keys->keys[index].time_last_requested, KEYS_TIMEOUT))
                {
                    num = 0;
                    curr = index;
                }
                else if (num > shared_keys->keys[index].times_requested)
                {
                    num = shared_keys->keys[index].times_requested;
                    curr = index;
                }
            }
        }
        else
        {
            if (num != 0)
            {
                num = 0;
                curr = index;
            }
        }
    }

    encrypt_precompute (public_key, secret_key, shared_key);

    if (num != (uint32_t) ~0)
    {
        shared_keys->keys[curr].stored = 1;
        shared_keys->keys[curr].times_requested = 1;
        memcpy (shared_keys->keys[curr].public_key, public_key, crypto_box_PUBLICKEYBYTES);
        memcpy (shared_keys->keys[curr].shared_key, shared_key, crypto_box_BEFORENMBYTES);
        shared_keys->keys[curr].time_last_requested = unix_time();
    }
}

/* Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
 * for packets that we receive.
 */
void DHT::get_shared_key_recv (uint8_t *shared_key, const uint8_t *public_key)
{
    get_shared_key (&shared_keys_recv, shared_key, self_secret_key.data.data(), public_key);
}

void DHT::get_shared_key_sent (uint8_t *shared_key, const uint8_t *public_key)
{
    get_shared_key (&shared_keys_sent, shared_key, self_secret_key.data.data(), public_key);
}

void to_net_family (IP *ip)
{
    if (ip->family == AF_INET)
    {
        ip->family = bitox::impl::network::TOX_AF_INET;
    }
    else if (ip->family == AF_INET6)
    {
        ip->family = bitox::impl::network::TOX_AF_INET6;
    }
}

int to_host_family (IP *ip)
{
    if (ip->family == bitox::impl::network::TOX_AF_INET)
    {
        ip->family = AF_INET;
        return 0;
    }
    else if (ip->family == bitox::impl::network::TOX_AF_INET6)
    {
        ip->family = AF_INET6;
        return 0;
    }
    else
    {
        return -1;
    }
}

#define PACKED_NODE_SIZE_IP4 (1 + SIZE_IP4 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES)
#define PACKED_NODE_SIZE_IP6 (1 + SIZE_IP6 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES)

/* Return packet size of packed node with ip_family on success.
 * Return -1 on failure.
 */
int packed_node_size (uint8_t ip_family)
{
    if (ip_family == AF_INET)
    {
        return PACKED_NODE_SIZE_IP4;
    }
    else if (ip_family == TCP_INET)
    {
        return PACKED_NODE_SIZE_IP4;
    }
    else if (ip_family == AF_INET6)
    {
        return PACKED_NODE_SIZE_IP6;
    }
    else if (ip_family == TCP_INET6)
    {
        return PACKED_NODE_SIZE_IP6;
    }
    else
    {
        return -1;
    }
}


/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_nodes (uint8_t *data, uint16_t length, const Node_format *nodes, uint16_t number)
{
    uint32_t i, packed_length = 0;

    for (i = 0; i < number; ++i)
    {
        int ipv6 = -1;
        uint8_t net_family;

        // FIXME use functions to convert endianness
        if (nodes[i].ip_port.ip.family == AF_INET)
        {
            ipv6 = 0;
            net_family = bitox::impl::network::TOX_AF_INET;
        }
        else if (nodes[i].ip_port.ip.family == TCP_INET)
        {
            ipv6 = 0;
            net_family = bitox::impl::network::TOX_TCP_INET;
        }
        else if (nodes[i].ip_port.ip.family == AF_INET6)
        {
            ipv6 = 1;
            net_family = bitox::impl::network::TOX_AF_INET6;
        }
        else if (nodes[i].ip_port.ip.family == TCP_INET6)
        {
            ipv6 = 1;
            net_family = bitox::impl::network::TOX_TCP_INET6;
        }
        else
        {
            return -1;
        }

        if (ipv6 == 0)
        {
            uint32_t size = PACKED_NODE_SIZE_IP4;

            if (packed_length + size > length)
            {
                return -1;
            }

            data[packed_length] = net_family;
            memcpy (data + packed_length + 1, &nodes[i].ip_port.ip.ip4, SIZE_IP4);
            memcpy (data + packed_length + 1 + SIZE_IP4, &nodes[i].ip_port.port, sizeof (uint16_t));
            memcpy (data + packed_length + 1 + SIZE_IP4 + sizeof (uint16_t), nodes[i].public_key, crypto_box_PUBLICKEYBYTES);
            packed_length += size;
        }
        else if (ipv6 == 1)
        {
            uint32_t size = PACKED_NODE_SIZE_IP6;

            if (packed_length + size > length)
            {
                return -1;
            }

            data[packed_length] = net_family;
            memcpy (data + packed_length + 1, &nodes[i].ip_port.ip.ip6, SIZE_IP6);
            memcpy (data + packed_length + 1 + SIZE_IP6, &nodes[i].ip_port.port, sizeof (uint16_t));
            memcpy (data + packed_length + 1 + SIZE_IP6 + sizeof (uint16_t), nodes[i].public_key, crypto_box_PUBLICKEYBYTES);
            packed_length += size;
        }
        else
        {
            return -1;
        }
    }

    return packed_length;
}

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_nodes (Node_format *nodes, uint16_t max_num_nodes, uint16_t *processed_data_len, const uint8_t *data,
                  uint16_t length, uint8_t tcp_enabled)
{
    uint32_t num = 0, len_processed = 0;

    while (num < max_num_nodes && len_processed < length)
    {
        int ipv6 = -1;
        uint8_t host_family;

        if (data[len_processed] == bitox::impl::network::TOX_AF_INET)
        {
            ipv6 = 0;
            host_family = AF_INET;
        }
        else if (data[len_processed] == bitox::impl::network::TOX_TCP_INET)
        {
            if (!tcp_enabled)
            {
                return -1;
            }

            ipv6 = 0;
            host_family = TCP_INET;
        }
        else if (data[len_processed] == bitox::impl::network::TOX_AF_INET6)
        {
            ipv6 = 1;
            host_family = AF_INET6;
        }
        else if (data[len_processed] == bitox::impl::network::TOX_TCP_INET6)
        {
            if (!tcp_enabled)
            {
                return -1;
            }

            ipv6 = 1;
            host_family = TCP_INET6;
        }
        else
        {
            return -1;
        }

        if (ipv6 == 0)
        {
            uint32_t size = PACKED_NODE_SIZE_IP4;

            if (len_processed + size > length)
            {
                return -1;
            }

            nodes[num].ip_port.ip.family = host_family;
            memcpy (&nodes[num].ip_port.ip.ip4, data + len_processed + 1, SIZE_IP4);
            memcpy (&nodes[num].ip_port.port, data + len_processed + 1 + SIZE_IP4, sizeof (uint16_t));
            memcpy (nodes[num].public_key, data + len_processed + 1 + SIZE_IP4 + sizeof (uint16_t), crypto_box_PUBLICKEYBYTES);
            len_processed += size;
            ++num;
        }
        else if (ipv6 == 1)
        {
            uint32_t size = PACKED_NODE_SIZE_IP6;

            if (len_processed + size > length)
            {
                return -1;
            }

            nodes[num].ip_port.ip.family = host_family;
            memcpy (&nodes[num].ip_port.ip.ip6, data + len_processed + 1, SIZE_IP6);
            memcpy (&nodes[num].ip_port.port, data + len_processed + 1 + SIZE_IP6, sizeof (uint16_t));
            memcpy (nodes[num].public_key, data + len_processed + 1 + SIZE_IP6 + sizeof (uint16_t), crypto_box_PUBLICKEYBYTES);
            len_processed += size;
            ++num;
        }
        else
        {
            return -1;
        }
    }

    if (processed_data_len)
    {
        *processed_data_len = len_processed;
    }

    return num;
}



/* Check if client with public_key is already in list of length length.
 * If it is then set its corresponding timestamp to current time.
 * If the id is already in the list with a different ip_port, update it.
 *  TODO: Maybe optimize this.
 *
 *  return True(1) or False(0)
 */
static int client_or_ip_port_in_list (Client_data *list, uint16_t length, const uint8_t *public_key, IP_Port ip_port)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    /* if public_key is in list, find it and maybe overwrite ip_port */
    for (i = 0; i < length; ++i)
        if (id_equal (list[i].public_key.data.data(), public_key))
        {
            /* Refresh the client timestamp. */
            if (ip_port.ip.family == AF_INET)
            {

                LOGGER_SCOPE (if (!ipport_equal (&list[i].assoc4.ip_port, &ip_port))
            {
                LOGGER_TRACE ("coipil[%u]: switching ipv4 from %s:%u to %s:%u", i,
                              ip_ntoa (&list[i].assoc4.ip_port.ip), ntohs (list[i].assoc4.ip_port.port),
                              ip_ntoa (&ip_port.ip), ntohs (ip_port.port));
                }
                             );

                if (LAN_ip (list[i].assoc4.ip_port.ip) != 0 && LAN_ip (ip_port.ip) == 0)
                {
                    return 1;
                }

                list[i].assoc4.ip_port = ip_port;
                list[i].assoc4.timestamp = temp_time;
            }
            else if (ip_port.ip.family == AF_INET6)
            {

                LOGGER_SCOPE (if (!ipport_equal (&list[i].assoc4.ip_port, &ip_port))
            {
                LOGGER_TRACE ("coipil[%u]: switching ipv6 from %s:%u to %s:%u", i,
                              ip_ntoa (&list[i].assoc6.ip_port.ip), ntohs (list[i].assoc6.ip_port.port),
                              ip_ntoa (&ip_port.ip), ntohs (ip_port.port));
                }
                             );

                if (LAN_ip (list[i].assoc6.ip_port.ip) != 0 && LAN_ip (ip_port.ip) == 0)
                {
                    return 1;
                }

                list[i].assoc6.ip_port = ip_port;
                list[i].assoc6.timestamp = temp_time;
            }

            return 1;
        }

    /* public_key not in list yet: see if we can find an identical ip_port, in
     * that case we kill the old public_key by overwriting it with the new one
     * TODO: maybe we SHOULDN'T do that if that public_key is in a friend_list
     * and the one who is the actual friend_'s public_key/address set? */
    for (i = 0; i < length; ++i)
    {
        /* MAYBE: check the other address, if valid, don't nuke? */
        if ( (ip_port.ip.family == AF_INET) && ipport_equal (&list[i].assoc4.ip_port, &ip_port))
        {
            /* Initialize client timestamp. */
            list[i].assoc4.timestamp = temp_time;
            memcpy (list[i].public_key.data.data(), public_key, crypto_box_PUBLICKEYBYTES);

            LOGGER_DEBUG ("coipil[%u]: switching public_key (ipv4)", i);

            /* kill the other address, if it was set */
            memset (&list[i].assoc6, 0, sizeof (list[i].assoc6));
            return 1;
        }
        else if ( (ip_port.ip.family == AF_INET6) && ipport_equal (&list[i].assoc6.ip_port, &ip_port))
        {
            /* Initialize client timestamp. */
            list[i].assoc6.timestamp = temp_time;
            memcpy (list[i].public_key.data.data(), public_key, crypto_box_PUBLICKEYBYTES);

            LOGGER_DEBUG ("coipil[%u]: switching public_key (ipv6)", i);

            /* kill the other address, if it was set */
            memset (&list[i].assoc4, 0, sizeof (list[i].assoc4));
            return 1;
        }
    }

    return 0;
}

/* Check if client with public_key is already in node format list of length length.
 *
 *  return 1 if true.
 *  return 0 if false.
 */
static int client_in_nodelist (const Node_format *list, uint16_t length, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < length; ++i)
    {
        if (id_equal (list[i].public_key, public_key))
        {
            return 1;
        }
    }

    return 0;
}

/*  return friend_ number from the public_key.
 *  return -1 if a failure occurs.
 */
static int friend_number (const DHT *dht, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < dht->friends_list.size(); ++i)
    {
        if (id_equal (dht->friends_list[i].public_key.data.data(), public_key))
        {
            return i;
        }
    }

    return -1;
}

/* Add node to the node list making sure only the nodes closest to cmp_pk are in the list.
 */
_Bool add_to_list (Node_format *nodes_list, unsigned int length, const uint8_t *pk, IP_Port ip_port,
                   const uint8_t *cmp_pk)
{
    uint8_t pk_bak[crypto_box_PUBLICKEYBYTES];
    IP_Port ip_port_bak;

    unsigned int i;

    for (i = 0; i < length; ++i)
    {
        if (id_closest (cmp_pk, nodes_list[i].public_key, pk) == 2)
        {
            memcpy (pk_bak, nodes_list[i].public_key, crypto_box_PUBLICKEYBYTES);
            ip_port_bak = nodes_list[i].ip_port;
            memcpy (nodes_list[i].public_key, pk, crypto_box_PUBLICKEYBYTES);
            nodes_list[i].ip_port = ip_port;

            if (i != (length - 1))
            {
                add_to_list (nodes_list, length, pk_bak, ip_port_bak, cmp_pk);
            }

            return 1;
        }
    }

    return 0;
}

/*TODO: change this to 7 when done*/
#define HARDENING_ALL_OK 2
/* return 0 if not.
 * return 1 if route request are ok
 * return 2 if it responds to send node packets correctly
 * return 4 if it can test other nodes correctly
 * return HARDENING_ALL_OK if all ok.
 */
static uint8_t hardening_correct (const Hardening *h)
{
    return h->routes_requests_ok + (h->send_nodes_ok << 1) + (h->testing_requests << 2);
}
/*
 * helper for get_close_nodes(). argument list is a monster :D
 */
static void get_close_nodes_inner (const uint8_t *public_key, Node_format *nodes_list,
                                   sa_family_t sa_family, const Client_data *client_list, uint32_t client_list_length,
                                   uint32_t *num_nodes_ptr, uint8_t is_LAN, uint8_t want_good)
{
    if ( (sa_family != AF_INET) && (sa_family != AF_INET6) && (sa_family != 0))
    {
        return;
    }

    uint32_t num_nodes = *num_nodes_ptr;
    uint32_t i;

    for (i = 0; i < client_list_length; i++)
    {
        const Client_data *client = &client_list[i];

        /* node already in list? */
        if (client_in_nodelist (nodes_list, MAX_SENT_NODES, client->public_key.data.data())) // TODO BUG use num_nodes instead of MAX_SENT_NODES ?
        {
            continue;
        }

        const IPPTsPng *ipptp = NULL;

        if (sa_family == AF_INET)
        {
            ipptp = &client->assoc4;
        }
        else if (sa_family == AF_INET6)
        {
            ipptp = &client->assoc6;
        }
        else
        {
            if (client->assoc4.timestamp >= client->assoc6.timestamp)
            {
                ipptp = &client->assoc4;
            }
            else
            {
                ipptp = &client->assoc6;
            }
        }

        /* node not in a good condition? */
        if (is_timeout (ipptp->timestamp, BAD_NODE_TIMEOUT))
        {
            continue;
        }

        /* don't send LAN ips to non LAN peers */
        if (LAN_ip (ipptp->ip_port.ip) == 0 && !is_LAN)
        {
            continue;
        }

        if (LAN_ip (ipptp->ip_port.ip) != 0 && want_good && hardening_correct (&ipptp->hardening) != HARDENING_ALL_OK
                && !id_equal (public_key, client->public_key.data.data()))
        {
            continue;
        }

        if (num_nodes < MAX_SENT_NODES)
        {
            memcpy (nodes_list[num_nodes].public_key,
                    client->public_key.data.data(),
                    crypto_box_PUBLICKEYBYTES);

            nodes_list[num_nodes].ip_port = ipptp->ip_port;
            num_nodes++;
        }
        else
        {
            add_to_list (nodes_list, MAX_SENT_NODES, client->public_key.data.data(), ipptp->ip_port, public_key);
        }
    }

    *num_nodes_ptr = num_nodes;
}

/* Find MAX_SENT_NODES nodes closest to the public_key for the send nodes request:
 * put them in the nodes_list and return how many were found.
 *
 * TODO: For the love of based <your favorite deity, in doubt use "love"> make
 * this function cleaner and much more efficient.
 *
 * want_good : do we want only good nodes as checked with the hardening returned or not?
 */
static int get_somewhat_close_nodes (const DHT *dht, const uint8_t *public_key, Node_format *nodes_list,
                                     sa_family_t sa_family, uint8_t is_LAN, uint8_t want_good)
{
    uint32_t num_nodes = 0, i;
    get_close_nodes_inner (public_key, nodes_list, sa_family,
                           dht->close_clientlist, LCLIENT_LIST, &num_nodes, is_LAN, 0);

    /*TODO uncomment this when hardening is added to close friend_ clients
        for (i = 0; i < dht->num_friends; ++i)
            get_close_nodes_inner(dht, public_key, nodes_list, sa_family,
                                  dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                                  &num_nodes, is_LAN, want_good);
    */
    for (i = 0; i < dht->friends_list.size(); ++i)
        get_close_nodes_inner (public_key, nodes_list, sa_family,
                               dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                               &num_nodes, is_LAN, 0);

    return num_nodes;
}

int DHT::get_close_nodes (const uint8_t *public_key, Node_format *nodes_list, sa_family_t sa_family,
                          uint8_t is_LAN, uint8_t want_good) const
{
    memset (nodes_list, 0, MAX_SENT_NODES * sizeof (Node_format));
#ifdef ENABLE_ASSOC_DHT

    if (!dht->assoc)
#endif
        return get_somewhat_close_nodes (this, public_key, nodes_list, sa_family, is_LAN, want_good);

#ifdef ENABLE_ASSOC_DHT
    //TODO: assoc, sa_family 0 (don't care if ipv4 or ipv6) support.
    Client_data *result[MAX_SENT_NODES];

    Assoc_close_entries request;
    memset (&request, 0, sizeof (request));
    request.count = MAX_SENT_NODES;
    request.count_good = MAX_SENT_NODES - 2; /* allow 2 'indirect' nodes */
    request.result = result;
    request.wanted_id = public_key;
    request.flags = (is_LAN ? LANOk : 0) + (sa_family == AF_INET ? ProtoIPv4 : ProtoIPv6);

    uint8_t num_found = Assoc_get_close_entries (dht->assoc, &request);

    if (!num_found)
    {
        LOGGER_DEBUG ("get_close_nodes(): Assoc_get_close_entries() returned zero nodes");
        return get_somewhat_close_nodes (dht, public_key, nodes_list, sa_family, is_LAN, want_good);
    }

    LOGGER_DEBUG ("get_close_nodes(): Assoc_get_close_entries() returned %i 'direct' and %i 'indirect' nodes",
                  request.count_good, num_found - request.count_good);

    uint8_t i, num_returned = 0;

    for (i = 0; i < num_found; i++)
    {
        Client_data *client = result[i];

        if (client)
        {
            id_copy (nodes_list[num_returned].public_key, client->public_key);

            if (sa_family == AF_INET)
                if (ipport_isset (&client->assoc4.ip_port))
                {
                    nodes_list[num_returned].ip_port = client->assoc4.ip_port;
                    num_returned++;
                    continue;
                }

            if (sa_family == AF_INET6)
                if (ipport_isset (&client->assoc6.ip_port))
                {
                    nodes_list[num_returned].ip_port = client->assoc6.ip_port;
                    num_returned++;
                    continue;
                }
        }
    }

    return num_returned;
#endif
}

static uint8_t cmp_public_key[crypto_box_PUBLICKEYBYTES];
static int cmp_dht_entry (const void *a, const void *b)
{
    Client_data entry1, entry2;
    memcpy (&entry1, a, sizeof (Client_data));
    memcpy (&entry2, b, sizeof (Client_data));
    int t1 = is_timeout (entry1.assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout (entry1.assoc6.timestamp, BAD_NODE_TIMEOUT);
    int t2 = is_timeout (entry2.assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout (entry2.assoc6.timestamp, BAD_NODE_TIMEOUT);

    if (t1 && t2)
    {
        return 0;
    }

    if (t1)
    {
        return -1;
    }

    if (t2)
    {
        return 1;
    }

    t1 = hardening_correct (&entry1.assoc4.hardening) != HARDENING_ALL_OK
         && hardening_correct (&entry1.assoc6.hardening) != HARDENING_ALL_OK;
    t2 = hardening_correct (&entry2.assoc4.hardening) != HARDENING_ALL_OK
         && hardening_correct (&entry2.assoc6.hardening) != HARDENING_ALL_OK;

    if (t1 != t2)
    {
        if (t1)
        {
            return -1;
        }

        if (t2)
        {
            return 1;
        }
    }

    int close = id_closest (cmp_public_key, entry1.public_key.data.data(), entry2.public_key.data.data());

    if (close == 1)
    {
        return 1;
    }

    if (close == 2)
    {
        return -1;
    }

    return 0;
}

/* Is it ok to store node with public_key in client.
 *
 * return 0 if node can't be stored.
 * return 1 if it can.
 */
static unsigned int store_node_ok (const Client_data *client, const uint8_t *public_key, const uint8_t *comp_public_key)
{
    if ( (is_timeout (client->assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout (client->assoc6.timestamp, BAD_NODE_TIMEOUT))
            || (id_closest (comp_public_key, client->public_key.data.data(), public_key) == 2))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

static void sort_client_list (Client_data *list, unsigned int length, const uint8_t *comp_public_key)
{
    memcpy (cmp_public_key, comp_public_key, crypto_box_PUBLICKEYBYTES);
    qsort (list, length, sizeof (Client_data), cmp_dht_entry);
}

/* Replace a first bad (or empty) node with this one
 *  or replace a possibly bad node (tests failed or not done yet)
 *  that is further than any other in the list
 *  from the comp_public_key
 *  or replace a good node that is further
 *  than any other in the list from the comp_public_key
 *  and further than public_key.
 *
 * Do not replace any node if the list has no bad or possibly bad nodes
 *  and all nodes in the list are closer to comp_public_key
 *  than public_key.
 *
 *  returns True(1) when the item was stored, False(0) otherwise */
static int replace_all (Client_data    *list,
                        uint16_t        length,
                        const uint8_t  *public_key,
                        IP_Port         ip_port,
                        const uint8_t  *comp_public_key)
{
    if ( (ip_port.ip.family != AF_INET) && (ip_port.ip.family != AF_INET6))
    {
        return 0;
    }

    if (store_node_ok (&list[1], public_key, comp_public_key) || store_node_ok (&list[0], public_key, comp_public_key))
    {
        sort_client_list (list, length, comp_public_key);

        IPPTsPng *ipptp_write = NULL;
        IPPTsPng *ipptp_clear = NULL;

        Client_data *client = &list[0];

        if (ip_port.ip.family == AF_INET)
        {
            ipptp_write = &client->assoc4;
            ipptp_clear = &client->assoc6;
        }
        else
        {
            ipptp_write = &client->assoc6;
            ipptp_clear = &client->assoc4;
        }

        id_copy (client->public_key.data.data(), public_key);
        ipptp_write->ip_port = ip_port;
        ipptp_write->timestamp = unix_time();

        ip_reset (&ipptp_write->ret_ip_port.ip);
        ipptp_write->ret_ip_port.port = 0;
        ipptp_write->ret_timestamp = 0;

        /* zero out other address */
        memset (ipptp_clear, 0, sizeof (*ipptp_clear));

        return 1;
    }

    return 0;
}

/* Add node to close list.
 *
 * simulate is set to 1 if we want to check if a node can be added to the list without adding it.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int DHT::add_to_close (const uint8_t *public_key, IP_Port ip_port, bool simulate)
{
    unsigned int i;

    unsigned int index = bit_by_bit_cmp (public_key, self_public_key.data.data());

    if (index > LCLIENT_LENGTH)
    {
        index = LCLIENT_LENGTH - 1;
    }

    for (i = 0; i < LCLIENT_NODES; ++i)
    {
        Client_data *client = &close_clientlist[ (index * LCLIENT_NODES) + i];

        if (is_timeout (client->assoc4.timestamp, BAD_NODE_TIMEOUT) && is_timeout (client->assoc6.timestamp, BAD_NODE_TIMEOUT))
        {
            if (!simulate)
            {
                IPPTsPng *ipptp_write = NULL;
                IPPTsPng *ipptp_clear = NULL;

                if (ip_port.ip.family == AF_INET)
                {
                    ipptp_write = &client->assoc4;
                    ipptp_clear = &client->assoc6;
                }
                else
                {
                    ipptp_write = &client->assoc6;
                    ipptp_clear = &client->assoc4;
                }

                id_copy (client->public_key.data.data(), public_key);
                ipptp_write->ip_port = ip_port;
                ipptp_write->timestamp = unix_time();

                ip_reset (&ipptp_write->ret_ip_port.ip);
                ipptp_write->ret_ip_port.port = 0;
                ipptp_write->ret_timestamp = 0;

                /* zero out other address */
                memset (ipptp_clear, 0, sizeof (*ipptp_clear));
            }

            return 0;
        }
    }

    return -1;
}

/* Return 1 if node can be added to close list, 0 if it can't.
 */
bool DHT::node_addable_to_close_list (const uint8_t *public_key, IP_Port ip_port)
{
    if (add_to_close (public_key, ip_port, 1) == 0)
    {
        return 1;
    }

    return 0;
}

static _Bool is_pk_in_client_list (Client_data *list, unsigned int client_list_length, const uint8_t *public_key,
                                   IP_Port ip_port)
{
    unsigned int i;

    for (i = 0; i < client_list_length; ++i)
    {
        if ( (ip_port.ip.family == AF_INET && !is_timeout (list[i].assoc4.timestamp, BAD_NODE_TIMEOUT))
                || (ip_port.ip.family == AF_INET6 && !is_timeout (list[i].assoc6.timestamp, BAD_NODE_TIMEOUT)))
        {
            if (public_key_cmp (list[i].public_key.data.data(), public_key) == 0)
            {
                return 1;
            }
        }
    }

    return 0;
}

/* Check if the node obtained with a get_nodes with public_key should be pinged.
 * NOTE: for best results call it after addto_lists;
 *
 * return 0 if the node should not be pinged.
 * return 1 if it should.
 */
unsigned int DHT::ping_node_from_getnodes_ok (const uint8_t *public_key, IP_Port ip_port)
{
    _Bool ret = 0;

    if (add_to_close (public_key, ip_port, 1) == 0)
    {
        ret = 1;
    }

    if (ret && !client_in_nodelist (to_bootstrap, num_to_bootstrap, public_key))
    {
        if (num_to_bootstrap < MAX_CLOSE_TO_BOOTSTRAP_NODES)
        {
            memcpy (to_bootstrap[num_to_bootstrap].public_key, public_key, crypto_box_PUBLICKEYBYTES);
            to_bootstrap[num_to_bootstrap].ip_port = ip_port;
            ++num_to_bootstrap;
        }
        else
        {
            //TODO: ipv6 vs v4
            add_to_list (to_bootstrap, MAX_CLOSE_TO_BOOTSTRAP_NODES, public_key, ip_port, self_public_key.data.data());
        }
    }

    unsigned int i;

    for (i = 0; i < friends_list.size(); ++i)
    {
        _Bool store_ok = 0;

        DHT_Friend *friend_ = &friends_list[i];

        if (store_node_ok (&friend_->client_list[1], public_key, friend_->public_key.data.data()))
        {
            store_ok = 1;
        }

        if (store_node_ok (&friend_->client_list[0], public_key, friend_->public_key.data.data()))
        {
            store_ok = 1;
        }

        if (store_ok && !client_in_nodelist (friend_->to_bootstrap, friend_->num_to_bootstrap, public_key)
                && !is_pk_in_client_list (friend_->client_list, MAX_FRIEND_CLIENTS, public_key, ip_port))
        {
            if (friend_->num_to_bootstrap < MAX_SENT_NODES)
            {
                memcpy (friend_->to_bootstrap[friend_->num_to_bootstrap].public_key, public_key, crypto_box_PUBLICKEYBYTES);
                friend_->to_bootstrap[friend_->num_to_bootstrap].ip_port = ip_port;
                ++friend_->num_to_bootstrap;
            }
            else
            {
                add_to_list (friend_->to_bootstrap, MAX_SENT_NODES, public_key, ip_port, friend_->public_key.data.data());
            }

            ret = 1;
        }
    }

    return ret;
}

/* Attempt to add client with ip_port and public_key to the friends client list
 * and close_clientlist.
 *
 *  returns 1+ if the item is used in any list, 0 else
 */
int DHT::addto_lists (IP_Port ip_port, const uint8_t *public_key)
{
    uint32_t i, used = 0;

    /* convert IPv4-in-IPv6 to IPv4 */
    if ( (ip_port.ip.family == AF_INET6) && IPV6_IPV4_IN_V6 (ip_port.ip.ip6))
    {
        ip_port.ip.family = AF_INET;
        ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
    }

    /* NOTE: Current behavior if there are two clients with the same id is
     * to replace the first ip by the second.
     */
    if (!client_or_ip_port_in_list (close_clientlist, LCLIENT_LIST, public_key, ip_port))
    {
        if (add_to_close (public_key, ip_port, 0))
        {
            used++;
        }
    }
    else
    {
        used++;
    }

    DHT_Friend *friend_foundip = 0;

    for (i = 0; i < friends_list.size(); ++i)
    {
        if (!client_or_ip_port_in_list (friends_list[i].client_list,
                                        MAX_FRIEND_CLIENTS, public_key, ip_port))
        {
            if (replace_all (friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                             public_key, ip_port, friends_list[i].public_key.data.data()))
            {

                DHT_Friend *friend_ = &friends_list[i];

                if (public_key_cmp (public_key, friend_->public_key.data.data()) == 0)
                {
                    friend_foundip = friend_;
                }

                used++;
            }
        }
        else
        {
            DHT_Friend *friend_ = &friends_list[i];

            if (public_key_cmp (public_key, friend_->public_key.data.data()) == 0)
            {
                friend_foundip = friend_;
            }

            used++;
        }
    }

    if (friend_foundip)
    {
        uint32_t j;

        for (j = 0; j < friend_foundip->lock_count; ++j)
        {
            if (friend_foundip->callbacks[j].ip_callback)
                friend_foundip->callbacks[j].ip_callback (friend_foundip->callbacks[j].data, friend_foundip->callbacks[j].number,
                                                          ip_port);
        }
    }

#ifdef ENABLE_ASSOC_DHT

    if (dht->assoc)
    {
        IPPTs ippts;

        ippts.ip_port = ip_port;
        ippts.timestamp = unix_time();

        Assoc_add_entry (dht->assoc, public_key, &ippts, NULL, used ? 1 : 0);
    }

#endif
    return used;
}

/* If public_key is a friend_ or us, update ret_ip_port
 * nodepublic_key is the id of the node that sent us this info.
 */
int DHT::returnedip_ports (IP_Port ip_port, const uint8_t *public_key, const uint8_t *nodepublic_key)
{
    uint32_t i, j;
    uint64_t temp_time = unix_time();

    uint32_t used = 0;

    /* convert IPv4-in-IPv6 to IPv4 */
    if ( (ip_port.ip.family == AF_INET6) && IPV6_IPV4_IN_V6 (ip_port.ip.ip6))
    {
        ip_port.ip.family = AF_INET;
        ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
    }

    if (id_equal (public_key, self_public_key.data.data()))
    {
        for (i = 0; i < LCLIENT_LIST; ++i)
        {
            if (id_equal (nodepublic_key, close_clientlist[i].public_key.data.data()))
            {
                if (ip_port.ip.family == AF_INET)
                {
                    close_clientlist[i].assoc4.ret_ip_port = ip_port;
                    close_clientlist[i].assoc4.ret_timestamp = temp_time;
                }
                else if (ip_port.ip.family == AF_INET6)
                {
                    close_clientlist[i].assoc6.ret_ip_port = ip_port;
                    close_clientlist[i].assoc6.ret_timestamp = temp_time;
                }

                ++used;
                break;
            }
        }
    }
    else
    {
        for (i = 0; i < friends_list.size(); ++i)
        {
            if (id_equal (public_key, friends_list[i].public_key.data.data()))
            {
                for (j = 0; j < MAX_FRIEND_CLIENTS; ++j)
                {
                    if (id_equal (nodepublic_key, friends_list[i].client_list[j].public_key.data.data()))
                    {
                        if (ip_port.ip.family == AF_INET)
                        {
                            friends_list[i].client_list[j].assoc4.ret_ip_port = ip_port;
                            friends_list[i].client_list[j].assoc4.ret_timestamp = temp_time;
                        }
                        else if (ip_port.ip.family == AF_INET6)
                        {
                            friends_list[i].client_list[j].assoc6.ret_ip_port = ip_port;
                            friends_list[i].client_list[j].assoc6.ret_timestamp = temp_time;
                        }

                        ++used;
                        goto end;
                    }
                }
            }
        }
    }

end:
#ifdef ENABLE_ASSOC_DHT

    if (assoc)
    {
        IPPTs ippts;
        ippts.ip_port = ip_port;
        ippts.timestamp = temp_time;
        /* this is only a hear-say entry, so ret-ipp is NULL, but used is required
         * to decide how valuable it is ("used" may throw an "unused" entry out) */
        Assoc_add_entry (assoc, public_key, &ippts, NULL, used ? 1 : 0);
    }

#endif
    return 0;
}

int DHT::getnodes (IP_Port ip_port, const uint8_t *public_key, const uint8_t *client_id,
                   const Node_format *sendback_node)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal (public_key, self_public_key.data.data()))
    {
        return -1;
    }

    uint8_t plain_message[sizeof (Node_format) * 2] = {0};

    Node_format receiver;
    memcpy (receiver.public_key, public_key, crypto_box_PUBLICKEYBYTES);
    receiver.ip_port = ip_port;
    memcpy (plain_message, &receiver, sizeof (receiver));

    uint64_t ping_id = 0;

    if (sendback_node != NULL)
    {
        memcpy (plain_message + sizeof (receiver), sendback_node, sizeof (Node_format));
        ping_id = dht_harden_ping_array.add (plain_message, sizeof (plain_message));
    }
    else
    {
        ping_id = dht_ping_array.add (plain_message, sizeof (receiver));
    }

    if (ping_id == 0)
    {
        return -1;
    }

    uint8_t plain[crypto_box_PUBLICKEYBYTES + sizeof (ping_id)];
    uint8_t encrypt[sizeof (plain) + crypto_box_MACBYTES];
    uint8_t data[1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + sizeof (encrypt)];

    memcpy (plain, client_id, crypto_box_PUBLICKEYBYTES);
    memcpy (plain + crypto_box_PUBLICKEYBYTES, &ping_id, sizeof (ping_id));

    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    get_shared_key_sent (shared_key, public_key);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce (nonce);

    int len = encrypt_data_symmetric (shared_key,
                                      nonce,
                                      plain,
                                      sizeof (plain),
                                      encrypt);

    if (len != sizeof (encrypt))
    {
        return -1;
    }

    data[0] = NET_PACKET_GET_NODES;
    memcpy (data + 1, self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    memcpy (data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    memcpy (data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket (net, ip_port, data, sizeof (data));
}

/* Send a send nodes response: message for IPv6 nodes */
static int sendnodes_ipv6 (const DHT *dht, IP_Port ip_port, const uint8_t *public_key, const uint8_t *client_id,
                           const uint8_t *sendback_data, uint16_t length, const uint8_t *shared_encryption_key)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal (public_key, dht->self_public_key.data.data()))
    {
        return -1;
    }

    if (length != sizeof (uint64_t))
    {
        return -1;
    }

    size_t Node_format_size = sizeof (Node_format);
    uint8_t data[1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES
                 + Node_format_size * MAX_SENT_NODES + length + crypto_box_MACBYTES];

    Node_format nodes_list[MAX_SENT_NODES];
    uint32_t num_nodes = dht->get_close_nodes (client_id, nodes_list, 0, LAN_ip (ip_port.ip) == 0, 1);

    uint8_t plain[1 + Node_format_size * MAX_SENT_NODES + length];
    uint8_t encrypt[sizeof (plain) + crypto_box_MACBYTES];
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce (nonce);

    int nodes_length = 0;

    if (num_nodes)
    {
        nodes_length = pack_nodes (plain + 1, Node_format_size * MAX_SENT_NODES, nodes_list, num_nodes);

        if (nodes_length <= 0)
        {
            return -1;
        }
    }

    plain[0] = num_nodes;
    memcpy (plain + 1 + nodes_length, sendback_data, length);
    int len = encrypt_data_symmetric (shared_encryption_key,
                                      nonce,
                                      plain,
                                      1 + nodes_length + length,
                                      encrypt);

    if (len != 1 + nodes_length + length + crypto_box_MACBYTES)
    {
        return -1;
    }

    data[0] = NET_PACKET_SEND_NODES_IPV6;
    memcpy (data + 1, dht->self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    memcpy (data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    memcpy (data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket (dht->net, ip_port, data, 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + len);
}

static int handle_getnodes (void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    if (length != (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + sizeof (
                       uint64_t) + crypto_box_MACBYTES))
    {
        return 1;
    }

    DHT *dht = reinterpret_cast<DHT *> (object);

    /* Check if packet is from ourself. */
    if (id_equal (packet + 1, dht->self_public_key.data.data()))
    {
        return 1;
    }

    uint8_t plain[crypto_box_PUBLICKEYBYTES + sizeof (uint64_t)];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];

    dht->get_shared_key_recv (shared_key, packet + 1);
    int len = decrypt_data_symmetric (shared_key,
                                      packet + 1 + crypto_box_PUBLICKEYBYTES,
                                      packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                                      crypto_box_PUBLICKEYBYTES + sizeof (uint64_t) + crypto_box_MACBYTES,
                                      plain);

    if (len != crypto_box_PUBLICKEYBYTES + sizeof (uint64_t))
    {
        return 1;
    }

    sendnodes_ipv6 (dht, source, packet + 1, plain, plain + crypto_box_PUBLICKEYBYTES, sizeof (uint64_t), shared_key);

    add_to_ping (dht->ping.get(), packet + 1, source);

    return 0;
}
/* return 0 if no
   return 1 if yes */
uint8_t DHT::sent_getnode_to_node (const uint8_t *public_key, IP_Port node_ip_port, uint64_t ping_id,
                                   Node_format *sendback_node)
{
    uint8_t data[sizeof (Node_format) * 2];

    if (dht_ping_array.check (data, sizeof (data), ping_id) == sizeof (Node_format))
    {
        memset (sendback_node, 0, sizeof (Node_format));
    }
    else if (dht_harden_ping_array.check (data, sizeof (data), ping_id) == sizeof (data))
    {
        memcpy (sendback_node, data + sizeof (Node_format), sizeof (Node_format));
    }
    else
    {
        return 0;
    }

    Node_format test;
    memcpy (&test, data, sizeof (Node_format));

    if (!ipport_equal (&test.ip_port, &node_ip_port) || public_key_cmp (test.public_key, public_key) != 0)
    {
        return 0;
    }

    return 1;
}

/* Function is needed in following functions. */
static int send_hardening_getnode_res (const DHT *dht, const Node_format *sendto, const uint8_t *queried_client_id,
                                       const uint8_t *nodes_data, uint16_t nodes_data_length);

static int handle_sendnodes_core (void *object, IP_Port source, const uint8_t *packet, uint16_t length,
                                  Node_format *plain_nodes, uint16_t size_plain_nodes, uint32_t *num_nodes_out)
{
    DHT *dht = reinterpret_cast<DHT *> (object);
    uint32_t cid_size = 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + 1 + sizeof (uint64_t) + crypto_box_MACBYTES;

    if (length < cid_size) /* too short */
    {
        return 1;
    }

    uint32_t data_size = length - cid_size;

    if (data_size == 0)
    {
        return 1;
    }

    if (data_size > sizeof (Node_format) * MAX_SENT_NODES) /* invalid length */
    {
        return 1;
    }

    uint8_t plain[1 + data_size + sizeof (uint64_t)];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    dht->get_shared_key_sent (shared_key, packet + 1);
    int len = decrypt_data_symmetric (
                  shared_key,
                  packet + 1 + crypto_box_PUBLICKEYBYTES,
                  packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                  1 + data_size + sizeof (uint64_t) + crypto_box_MACBYTES,
                  plain);

    if ( (unsigned int) len != sizeof (plain))
    {
        return 1;
    }

    if (plain[0] > size_plain_nodes)
    {
        return 1;
    }

    Node_format sendback_node;

    uint64_t ping_id;
    memcpy (&ping_id, plain + 1 + data_size, sizeof (ping_id));

    if (!dht->sent_getnode_to_node (packet + 1, source, ping_id, &sendback_node))
    {
        return 1;
    }

    uint16_t length_nodes = 0;
    int num_nodes = unpack_nodes (plain_nodes, plain[0], &length_nodes, plain + 1, data_size, 0);

    if (length_nodes != data_size)
    {
        return 1;
    }

    if (num_nodes != plain[0])
    {
        return 1;
    }

    if (num_nodes < 0)
    {
        return 1;
    }

    /* store the address the *request* was sent to */
    dht->addto_lists (source, packet + 1);

    *num_nodes_out = num_nodes;

    send_hardening_getnode_res (dht, &sendback_node, packet + 1, plain + 1, data_size);
    return 0;
}

static int handle_sendnodes_ipv6 (void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    DHT *dht = reinterpret_cast<DHT *> (object);
    Node_format plain_nodes[MAX_SENT_NODES];
    uint32_t num_nodes;

    if (handle_sendnodes_core (object, source, packet, length, plain_nodes, MAX_SENT_NODES, &num_nodes))
    {
        return 1;
    }

    if (num_nodes == 0)
    {
        return 0;
    }

    uint32_t i;

    for (i = 0; i < num_nodes; i++)
    {

        if (ipport_isset (&plain_nodes[i].ip_port))
        {
            dht->ping_node_from_getnodes_ok (plain_nodes[i].public_key, plain_nodes[i].ip_port);
            dht->returnedip_ports (plain_nodes[i].ip_port, plain_nodes[i].public_key, packet + 1);
        }
    }

    return 0;
}

/*----------------------------------------------------------------------------------*/
/*------------------------END of packet handling functions--------------------------*/

bool DHT::addfriend (const uint8_t *public_key, void (*ip_callback) (void *data, int32_t number, IP_Port),
                     void *data, int32_t number, uint16_t *lock_count)
{
    int friend_num = friend_number (this, public_key);

    uint16_t lock_num;

    if (friend_num != -1)   /* Is friend_ already in DHT? */
    {
        DHT_Friend *friend_ = &friends_list[friend_num];

        if (friend_->lock_count == DHT_FRIEND_MAX_LOCKS)
        {
            return false;
        }

        lock_num = friend_->lock_count;
        ++friend_->lock_count;
        friend_->callbacks[lock_num].ip_callback = ip_callback;
        friend_->callbacks[lock_num].data = data;
        friend_->callbacks[lock_num].number = number;

        if (lock_count)
        {
            *lock_count = lock_num + 1;
        }

        return true;
    }

    friends_list.emplace_back();

    DHT_Friend *friend_ = & (friends_list.back());
    memset (friend_, 0, sizeof (DHT_Friend));
    memcpy (friend_->public_key.data.data(), public_key, crypto_box_PUBLICKEYBYTES);

    friend_->nat.NATping_id = random_64b();

    lock_num = friend_->lock_count;
    ++friend_->lock_count;
    friend_->callbacks[lock_num].ip_callback = ip_callback;
    friend_->callbacks[lock_num].data = data;
    friend_->callbacks[lock_num].number = number;

    if (lock_count)
    {
        *lock_count = lock_num + 1;
    }

    friend_->num_to_bootstrap = get_close_nodes (friend_->public_key.data.data(), friend_->to_bootstrap, 0, 1, 0);

    return true;
}

bool DHT::delfriend (const uint8_t *public_key, uint16_t lock_count)
{
    int friend_num = friend_number (this, public_key);

    if (friend_num == -1)
    {
        return false;
    }

    DHT_Friend *friend_ = &friends_list[friend_num];
    --friend_->lock_count;

    if (friend_->lock_count && lock_count)   /* DHT friend_ is still in use.*/
    {
        --lock_count;
        friend_->callbacks[lock_count].ip_callback = NULL;
        friend_->callbacks[lock_count].data = NULL;
        friend_->callbacks[lock_count].number = 0;
        return true;
    }

    DHT_Friend *temp;

    if (friends_list.size() - 1 != friend_num)
    {
        memcpy (&friends_list[friend_num],
                &friends_list[friends_list.size() - 1],
                sizeof (DHT_Friend));
    }

    friends_list.pop_back();
    return true;
}

/* TODO: Optimize this. */
int DHT::getfriendip (const uint8_t *public_key, IP_Port *ip_port) const
{
    uint32_t i, j;

    ip_reset (&ip_port->ip);
    ip_port->port = 0;

    for (i = 0; i < friends_list.size(); ++i)
    {
        /* Equal */
        if (id_equal (friends_list[i].public_key.data.data(), public_key))
        {
            for (j = 0; j < MAX_FRIEND_CLIENTS; ++j)
            {
                const Client_data *client = &friends_list[i].client_list[j];

                if (id_equal (client->public_key.data.data(), public_key))
                {
                    const IPPTsPng *assoc = NULL;
                    uint32_t a;

                    for (a = 0, assoc = &client->assoc6; a < 2; a++, assoc = &client->assoc4)
                        if (!is_timeout (assoc->timestamp, BAD_NODE_TIMEOUT))
                        {
                            *ip_port = assoc->ip_port;
                            return 1;
                        }
                }
            }

            return 0;
        }
    }

    return -1;
}

/* returns number of nodes not in kill-timeout */
uint8_t DHT::do_ping_and_sendnode_requests (uint64_t *lastgetnode, const uint8_t *public_key,
                                            Client_data *list, uint32_t list_count, uint32_t *bootstrap_times, bool sortable)
{
    uint32_t i;
    uint8_t not_kill = 0;
    uint64_t temp_time = unix_time();

    uint32_t num_nodes = 0;
    Client_data *client_list[list_count * 2];
    IPPTsPng    *assoc_list[list_count * 2];
    unsigned int sort = 0;
    _Bool sort_ok = 0;

    for (i = 0; i < list_count; i++)
    {
        /* If node is not dead. */
        Client_data *client = &list[i];
        IPPTsPng *assoc;
        uint32_t a;

        for (a = 0, assoc = &client->assoc6; a < 2; a++, assoc = &client->assoc4)
            if (!is_timeout (assoc->timestamp, KILL_NODE_TIMEOUT))
            {
                sort = 0;
                not_kill++;

                if (is_timeout (assoc->last_pinged, PING_INTERVAL))
                {
                    getnodes (assoc->ip_port, client->public_key.data.data(), public_key, NULL);
                    assoc->last_pinged = temp_time;
                }

                /* If node is good. */
                if (!is_timeout (assoc->timestamp, BAD_NODE_TIMEOUT))
                {
                    client_list[num_nodes] = client;
                    assoc_list[num_nodes] = assoc;
                    ++num_nodes;
                }
            }
            else
            {
                ++sort;

                /* Timed out should be at beginning, if they are not, sort the list. */
                if (sort > 1 && sort < ( ( (i + 1) * 2) - 1))
                {
                    sort_ok = 1;
                }
            }
    }

    if (sortable && sort_ok)
    {
        sort_client_list (list, list_count, public_key);
    }

    if ( (num_nodes != 0) && (is_timeout (*lastgetnode, GET_NODE_INTERVAL) || *bootstrap_times < MAX_BOOTSTRAP_TIMES))
    {
        uint32_t rand_node = rand() % (num_nodes);

        if ( (num_nodes - 1) != rand_node)
        {
            rand_node += rand() % (num_nodes - (rand_node + 1));
        }

        getnodes (assoc_list[rand_node]->ip_port, client_list[rand_node]->public_key.data.data(), public_key, NULL);

        *lastgetnode = temp_time;
        ++*bootstrap_times;
    }

    return not_kill;
}

/* Ping each client in the "friends" list every PING_INTERVAL seconds. Send a get nodes request
 * every GET_NODE_INTERVAL seconds to a random good node for each "friend_" in our "friends" list.
 */
void DHT::do_DHT_friends ()
{
    unsigned int i, j;

    for (i = 0; i < friends_list.size(); ++i)
    {
        DHT_Friend *friend_ = &friends_list[i];

        for (j = 0; j < friend_->num_to_bootstrap; ++j)
        {
            getnodes (friend_->to_bootstrap[j].ip_port, friend_->to_bootstrap[j].public_key, friend_->public_key.data.data(), NULL);
        }

        friend_->num_to_bootstrap = 0;

        do_ping_and_sendnode_requests (&friend_->lastgetnode, friend_->public_key.data.data(), friend_->client_list, MAX_FRIEND_CLIENTS,
                                       &friend_->bootstrap_times, 1);
    }
}

/* Ping each client in the close nodes list every PING_INTERVAL seconds.
 * Send a get nodes request every GET_NODE_INTERVAL seconds to a random good node in the list.
 */
void DHT::do_Close ()
{
    unsigned int i;

    for (i = 0; i < num_to_bootstrap; ++i)
    {
        getnodes (to_bootstrap[i].ip_port, to_bootstrap[i].public_key, self_public_key.data.data(), NULL);
    }

    num_to_bootstrap = 0;

    uint8_t not_killed = do_ping_and_sendnode_requests (&close_lastgetnodes, self_public_key.data.data(),
                                                        close_clientlist, LCLIENT_LIST, &close_bootstrap_times, 0);

    if (!not_killed)
    {
        /* all existing nodes are at least KILL_NODE_TIMEOUT,
         * which means we are mute, as we only send packets to
         * nodes NOT in KILL_NODE_TIMEOUT
         *
         * so: reset all nodes to be BAD_NODE_TIMEOUT, but not
         * KILL_NODE_TIMEOUT, so we at least keep trying pings */
        uint64_t badonly = unix_time() - BAD_NODE_TIMEOUT;
        size_t i, a;

        for (i = 0; i < LCLIENT_LIST; i++)
        {
            Client_data *client = &close_clientlist[i];
            IPPTsPng *assoc;

            for (a = 0, assoc = &client->assoc4; a < 2; a++, assoc = &client->assoc6)
                if (assoc->timestamp)
                {
                    assoc->timestamp = badonly;
                }
        }
    }
}

void DHT::getnodes (const IP_Port *from_ipp, const uint8_t *from_id, const uint8_t *which_id)
{
    getnodes (*from_ipp, from_id, which_id, NULL);
}

void DHT::bootstrap (IP_Port ip_port, const uint8_t *public_key)
{
    /*#ifdef ENABLE_ASSOC_DHT
       if (dht->assoc) {
           IPPTs ippts;
           ippts.ip_port = ip_port;
           ippts.timestamp = 0;

           Assoc_add_entry(dht->assoc, public_key, &ippts, NULL, 0);
       }
       #endif*/

    getnodes (ip_port, public_key, self_public_key.data.data(), NULL);
}

bool DHT::bootstrap_from_address (const char *address, uint8_t ipv6enabled,
                                  uint16_t port, const uint8_t *public_key)
{
    IP_Port ip_port_v64;
    IP *ip_extra = NULL;
    IP_Port ip_port_v4;
    ip_init (&ip_port_v64.ip, ipv6enabled);

    if (ipv6enabled)
    {
        /* setup for getting BOTH: an IPv6 AND an IPv4 address */
        ip_port_v64.ip.family = AF_UNSPEC;
        ip_reset (&ip_port_v4.ip);
        ip_extra = &ip_port_v4.ip;
    }

    if (addr_resolve_or_parse_ip (address, &ip_port_v64.ip, ip_extra))
    {
        ip_port_v64.port = port;
        bootstrap (ip_port_v64, public_key);

        if ( (ip_extra != NULL) && ip_isset (ip_extra))
        {
            ip_port_v4.port = port;
            bootstrap (ip_port_v4, public_key);
        }

        return true;
    }
    else
    {
        return false;
    }
}

int DHT::route_packet (const uint8_t *public_key, const uint8_t *packet, uint16_t length) const
{
    uint32_t i;

    for (i = 0; i < LCLIENT_LIST; ++i)
    {
        if (id_equal (public_key, close_clientlist[i].public_key.data.data()))
        {
            const Client_data *client = &close_clientlist[i];

            if (ip_isset (&client->assoc6.ip_port.ip))
            {
                return sendpacket (net, client->assoc6.ip_port, packet, length);
            }
            else if (ip_isset (&client->assoc4.ip_port.ip))
            {
                return sendpacket (net, client->assoc4.ip_port, packet, length);
            }
            else
            {
                break;
            }
        }
    }

    return -1;
}

/* Puts all the different ips returned by the nodes for a friend_num into array ip_portlist.
 * ip_portlist must be at least MAX_FRIEND_CLIENTS big.
 *
 *  return the number of ips returned.
 *  return 0 if we are connected to friend_ or if no ips were found.
 *  return -1 if no such friend_.
 */
int DHT::friend_iplist (IP_Port *ip_portlist, uint16_t friend_num) const
{
    if (friend_num >= friends_list.size())
    {
        return -1;
    }

    const DHT_Friend *friend_ = &friends_list[friend_num];
    const Client_data *client;
    IP_Port ipv4s[MAX_FRIEND_CLIENTS];
    int num_ipv4s = 0;
    IP_Port ipv6s[MAX_FRIEND_CLIENTS];
    int num_ipv6s = 0;
    int i;

    for (i = 0; i < MAX_FRIEND_CLIENTS; ++i)
    {
        client = & (friend_->client_list[i]);

        /* If ip is not zero and node is good. */
        if (ip_isset (&client->assoc4.ret_ip_port.ip) && !is_timeout (client->assoc4.ret_timestamp, BAD_NODE_TIMEOUT))
        {
            ipv4s[num_ipv4s] = client->assoc4.ret_ip_port;
            ++num_ipv4s;
        }

        if (ip_isset (&client->assoc6.ret_ip_port.ip) && !is_timeout (client->assoc6.ret_timestamp, BAD_NODE_TIMEOUT))
        {
            ipv6s[num_ipv6s] = client->assoc6.ret_ip_port;
            ++num_ipv6s;
        }

        if (id_equal (client->public_key.data.data(), friend_->public_key.data.data()))
            if (!is_timeout (client->assoc6.timestamp, BAD_NODE_TIMEOUT) || !is_timeout (client->assoc4.timestamp, BAD_NODE_TIMEOUT))
            {
                return 0;    /* direct connectivity */
            }
    }

#ifdef FRIEND_IPLIST_PAD
    memcpy (ip_portlist, ipv6s, num_ipv6s * sizeof (IP_Port));

    if (num_ipv6s == MAX_FRIEND_CLIENTS)
    {
        return MAX_FRIEND_CLIENTS;
    }

    int num_ipv4s_used = MAX_FRIEND_CLIENTS - num_ipv6s;

    if (num_ipv4s_used > num_ipv4s)
    {
        num_ipv4s_used = num_ipv4s;
    }

    memcpy (&ip_portlist[num_ipv6s], ipv4s, num_ipv4s_used * sizeof (IP_Port));
    return num_ipv6s + num_ipv4s_used;

#else /* !FRIEND_IPLIST_PAD */

    /* there must be some secret reason why we can't pad the longer list
     * with the shorter one...
     */
    if (num_ipv6s >= num_ipv4s)
    {
        memcpy (ip_portlist, ipv6s, num_ipv6s * sizeof (IP_Port));
        return num_ipv6s;
    }

    memcpy (ip_portlist, ipv4s, num_ipv4s * sizeof (IP_Port));
    return num_ipv4s;

#endif /* !FRIEND_IPLIST_PAD */
}


/* Send the following packet to everyone who tells us they are connected to friend_id.
 *
 *  return ip for friend_.
 *  return number of nodes the packet was sent to. (Only works if more than (MAX_FRIEND_CLIENTS / 4).
 */
int DHT::route_tofriend (const uint8_t *friend_id, const uint8_t *packet, uint16_t length) const
{
    int num = friend_number (this, friend_id);

    if (num == -1)
    {
        return 0;
    }

    uint32_t i, sent = 0;
    uint8_t friend_sent[MAX_FRIEND_CLIENTS] = {0};

    IP_Port ip_list[MAX_FRIEND_CLIENTS];
    int ip_num = friend_iplist (ip_list, num);

    if (ip_num < (MAX_FRIEND_CLIENTS / 4))
    {
        return 0;    /* Reason for that? */
    }

    const DHT_Friend *friend_ = &friends_list[num];
    const Client_data *client;

    /* extra legwork, because having the outside allocating the space for us
     * is *usually* good(tm) (bites us in the behind in this case though) */
    uint32_t a;

    for (a = 0; a < 2; a++)
        for (i = 0; i < MAX_FRIEND_CLIENTS; ++i)
        {
            if (friend_sent[i]) /* Send one packet per client.*/
            {
                continue;
            }

            client = &friend_->client_list[i];
            const IPPTsPng *assoc = NULL;

            if (!a)
            {
                assoc = &client->assoc4;
            }
            else
            {
                assoc = &client->assoc6;
            }

            /* If ip is not zero and node is good. */
            if (ip_isset (&assoc->ret_ip_port.ip) &&
                    !is_timeout (assoc->ret_timestamp, BAD_NODE_TIMEOUT))
            {
                int retval = sendpacket (net, assoc->ip_port, packet, length);

                if ( (unsigned int) retval == length)
                {
                    ++sent;
                    friend_sent[i] = 1;
                }
            }
        }

    return sent;
}

/* Send the following packet to one random person who tells us they are connected to friend_id.
 *
 *  return number of nodes the packet was sent to.
 */
int DHT::routeone_tofriend (const uint8_t *friend_id, const uint8_t *packet, uint16_t length)
{
    int num = friend_number (this, friend_id);

    if (num == -1)
    {
        return 0;
    }

    DHT_Friend *friend_ = &friends_list[num];
    Client_data *client;

    IP_Port ip_list[MAX_FRIEND_CLIENTS * 2];
    int n = 0;
    uint32_t i;

    /* extra legwork, because having the outside allocating the space for us
     * is *usually* good(tm) (bites us in the behind in this case though) */
    uint32_t a;

    for (a = 0; a < 2; a++)
        for (i = 0; i < MAX_FRIEND_CLIENTS; ++i)
        {
            client = &friend_->client_list[i];
            IPPTsPng *assoc = NULL;

            if (!a)
            {
                assoc = &client->assoc4;
            }
            else
            {
                assoc = &client->assoc6;
            }

            /* If ip is not zero and node is good. */
            if (ip_isset (&assoc->ret_ip_port.ip) && !is_timeout (assoc->ret_timestamp, BAD_NODE_TIMEOUT))
            {
                ip_list[n] = assoc->ip_port;
                ++n;
            }
        }

    if (n < 1)
    {
        return 0;
    }

    int retval = sendpacket (net, ip_list[rand() % n], packet, length);

    if ( (unsigned int) retval == length)
    {
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------------*/
/*---------------------BEGINNING OF NAT PUNCHING FUNCTIONS--------------------------*/

int DHT::send_NATping (const uint8_t *public_key, uint64_t ping_id, uint8_t type)
{
    uint8_t data[sizeof (uint64_t) + 1];
    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];

    int num = 0;

    data[0] = type;
    memcpy (data + 1, &ping_id, sizeof (uint64_t));
    /* 254 is NAT ping request packet id */
    int len = create_request (self_public_key.data.data(), self_secret_key.data.data(), packet, public_key, data,
                              sizeof (uint64_t) + 1, CRYPTO_PACKET_NAT_PING);

    if (len == -1)
    {
        return -1;
    }

    if (type == 0) /* If packet is request use many people to route it. */
    {
        num = route_tofriend (public_key, packet, len);
    }
    else if (type == 1) /* If packet is response use only one person to route it */
    {
        num = routeone_tofriend (public_key, packet, len);
    }

    if (num == 0)
    {
        return -1;
    }

    return num;
}

/* Handle a received ping request for. */
static int handle_NATping (void *object, IP_Port source, const uint8_t *source_pubkey, const uint8_t *packet,
                           uint16_t length)
{
    if (length != sizeof (uint64_t) + 1)
    {
        return 1;
    }

    DHT *dht = reinterpret_cast<DHT *> (object);
    uint64_t ping_id;
    memcpy (&ping_id, packet + 1, sizeof (uint64_t));

    int friendnumber = friend_number (dht, source_pubkey);

    if (friendnumber == -1)
    {
        return 1;
    }

    DHT_Friend *friend_ = &dht->friends_list[friendnumber];

    if (packet[0] == NAT_PING_REQUEST)
    {
        /* 1 is reply */
        dht->send_NATping (source_pubkey, ping_id, NAT_PING_RESPONSE);
        friend_->nat.recvNATping_timestamp = unix_time();
        return 0;
    }
    else if (packet[0] == NAT_PING_RESPONSE)
    {
        if (friend_->nat.NATping_id == ping_id)
        {
            friend_->nat.NATping_id = random_64b();
            friend_->nat.hole_punching = 1;
            return 0;
        }
    }

    return 1;
}

/* Get the most common ip in the ip_portlist.
 * Only return ip if it appears in list min_num or more.
 * len must not be bigger than MAX_FRIEND_CLIENTS.
 *
 *  return ip of 0 if failure.
 */
static IP NAT_commonip (IP_Port *ip_portlist, uint16_t len, uint16_t min_num)
{
    IP zero;
    ip_reset (&zero);

    if (len > MAX_FRIEND_CLIENTS)
    {
        return zero;
    }

    uint32_t i, j;
    uint16_t numbers[MAX_FRIEND_CLIENTS] = {0};

    for (i = 0; i < len; ++i)
    {
        for (j = 0; j < len; ++j)
        {
            if (ip_equal (&ip_portlist[i].ip, &ip_portlist[j].ip))
            {
                ++numbers[i];
            }
        }

        if (numbers[i] >= min_num)
        {
            return ip_portlist[i].ip;
        }
    }

    return zero;
}

/* Return all the ports for one ip in a list.
 * portlist must be at least len long,
 * where len is the length of ip_portlist.
 *
 *  return number of ports and puts the list of ports in portlist.
 */
static uint16_t NAT_getports (uint16_t *portlist, IP_Port *ip_portlist, uint16_t len, IP ip)
{
    uint32_t i;
    uint16_t num = 0;

    for (i = 0; i < len; ++i)
    {
        if (ip_equal (&ip_portlist[i].ip, &ip))
        {
            portlist[num] = ntohs (ip_portlist[i].port);
            ++num;
        }
    }

    return num;
}

void DHT::punch_holes (IP ip, uint16_t *port_list, uint16_t numports, uint16_t friend_num)
{
    if (numports > MAX_FRIEND_CLIENTS || numports == 0)
    {
        return;
    }

    uint32_t i;
    uint32_t top = friends_list[friend_num].nat.punching_index + MAX_PUNCHING_PORTS;
    uint16_t firstport = port_list[0];

    for (i = 0; i < numports; ++i)
    {
        if (firstport != port_list[i])
        {
            break;
        }
    }

    if (i == numports)   /* If all ports are the same, only try that one port. */
    {
        IP_Port pinging;
        ip_copy (&pinging.ip, &ip);
        pinging.port = htons (firstport);
        send_ping_request (ping.get(), pinging, friends_list[friend_num].public_key.data.data());
    }
    else
    {
        for (i = friends_list[friend_num].nat.punching_index; i != top; ++i)
        {
            /* TODO: Improve port guessing algorithm. */
            uint16_t port = port_list[ (i / 2) % numports] + (i / (2 * numports)) * ( (i % 2) ? -1 : 1);
            IP_Port pinging;
            ip_copy (&pinging.ip, &ip);
            pinging.port = htons (port);
            send_ping_request (ping.get(), pinging, friends_list[friend_num].public_key.data.data());
        }

        friends_list[friend_num].nat.punching_index = i;
    }

    if (friends_list[friend_num].nat.tries > MAX_NORMAL_PUNCHING_TRIES)
    {
        top = friends_list[friend_num].nat.punching_index2 + MAX_PUNCHING_PORTS;
        uint16_t port = 1024;
        IP_Port pinging;
        ip_copy (&pinging.ip, &ip);

        for (i = friends_list[friend_num].nat.punching_index2; i != top; ++i)
        {
            pinging.port = htons (port + i);
            send_ping_request (ping.get(), pinging, friends_list[friend_num].public_key.data.data());
        }

        friends_list[friend_num].nat.punching_index2 = i - (MAX_PUNCHING_PORTS / 2);
    }

    ++friends_list[friend_num].nat.tries;
}

void DHT::do_NAT ()
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < friends_list.size(); ++i)
    {
        IP_Port ip_list[MAX_FRIEND_CLIENTS];
        int num = friend_iplist (ip_list, i);

        /* If already connected or friend_ is not online don't try to hole punch. */
        if (num < MAX_FRIEND_CLIENTS / 2)
        {
            continue;
        }

        if (friends_list[i].nat.NATping_timestamp + PUNCH_INTERVAL < temp_time)
        {
            send_NATping (friends_list[i].public_key.data.data(), friends_list[i].nat.NATping_id, NAT_PING_REQUEST);
            friends_list[i].nat.NATping_timestamp = temp_time;
        }

        if (friends_list[i].nat.hole_punching == 1 &&
                friends_list[i].nat.punching_timestamp + PUNCH_INTERVAL < temp_time &&
                friends_list[i].nat.recvNATping_timestamp + PUNCH_INTERVAL * 2 >= temp_time)
        {

            IP ip = NAT_commonip (ip_list, num, MAX_FRIEND_CLIENTS / 2);

            if (!ip_isset (&ip))
            {
                continue;
            }

            uint16_t port_list[MAX_FRIEND_CLIENTS];
            uint16_t numports = NAT_getports (port_list, ip_list, num, ip);
            punch_holes (ip, port_list, numports, i);

            friends_list[i].nat.punching_timestamp = temp_time;
            friends_list[i].nat.hole_punching = 0;
        }
    }
}

/*----------------------------------------------------------------------------------*/
/*-----------------------END OF NAT PUNCHING FUNCTIONS------------------------------*/

#define HARDREQ_DATA_SIZE 384 /* Attempt to prevent amplification/other attacks*/

#define CHECK_TYPE_ROUTE_REQ 0
#define CHECK_TYPE_ROUTE_RES 1
#define CHECK_TYPE_GETNODE_REQ 2
#define CHECK_TYPE_GETNODE_RES 3
#define CHECK_TYPE_TEST_REQ 4
#define CHECK_TYPE_TEST_RES 5

int DHT::send_hardening_req (Node_format *sendto, uint8_t type, uint8_t *contents, uint16_t length)
{
    if (length > HARDREQ_DATA_SIZE - 1)
    {
        return -1;
    }

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t data[HARDREQ_DATA_SIZE] = {0};
    data[0] = type;
    memcpy (data + 1, contents, length);
    int len = create_request (self_public_key.data.data(), self_secret_key.data.data(), packet, sendto->public_key, data,
                              sizeof (data), CRYPTO_PACKET_HARDENING);

    if (len == -1)
    {
        return -1;
    }

    return sendpacket (net, sendto->ip_port, packet, len);
}

/* Send a get node hardening request */
int DHT::send_hardening_getnode_req (Node_format *dest, Node_format *node_totest, uint8_t *search_id)
{
    uint8_t data[sizeof (Node_format) + crypto_box_PUBLICKEYBYTES];
    memcpy (data, node_totest, sizeof (Node_format));
    memcpy (data + sizeof (Node_format), search_id, crypto_box_PUBLICKEYBYTES);
    return send_hardening_req (dest, CHECK_TYPE_GETNODE_REQ, data, sizeof (Node_format) + crypto_box_PUBLICKEYBYTES);
}

/* Send a get node hardening response */
static int send_hardening_getnode_res (const DHT *dht, const Node_format *sendto, const uint8_t *queried_client_id,
                                       const uint8_t *nodes_data, uint16_t nodes_data_length)
{
    if (!ip_isset (&sendto->ip_port.ip))
    {
        return -1;
    }

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t data[1 + crypto_box_PUBLICKEYBYTES + nodes_data_length];
    data[0] = CHECK_TYPE_GETNODE_RES;
    memcpy (data + 1, queried_client_id, crypto_box_PUBLICKEYBYTES);
    memcpy (data + 1 + crypto_box_PUBLICKEYBYTES, nodes_data, nodes_data_length);
    int len = create_request (dht->self_public_key.data.data(), dht->self_secret_key.data.data(), packet, sendto->public_key, data,
                              sizeof (data), CRYPTO_PACKET_HARDENING);

    if (len == -1)
    {
        return -1;
    }

    return sendpacket (dht->net, sendto->ip_port, packet, len);
}

/* TODO: improve */
IPPTsPng *DHT::get_closelist_IPPTsPng (const uint8_t *public_key, sa_family_t sa_family)
{
    uint32_t i;

    for (i = 0; i < LCLIENT_LIST; ++i)
    {
        if (public_key_cmp (close_clientlist[i].public_key.data.data(), public_key) != 0)
        {
            continue;
        }

        if (sa_family == AF_INET)
        {
            return &close_clientlist[i].assoc4;
        }
        else if (sa_family == AF_INET6)
        {
            return &close_clientlist[i].assoc6;
        }
    }

    return NULL;
}

/*
 * check how many nodes in nodes are also present in the closelist.
 * TODO: make this function better.
 */
uint32_t DHT::have_nodes_closelist (Node_format *nodes, uint16_t num)
{
    uint32_t counter = 0;
    uint32_t i;

    for (i = 0; i < num; ++i)
    {
        if (id_equal (nodes[i].public_key, self_public_key.data.data()))
        {
            ++counter;
            continue;
        }

        IPPTsPng *temp = get_closelist_IPPTsPng (nodes[i].public_key, nodes[i].ip_port.ip.family);

        if (temp)
        {
            if (!is_timeout (temp->timestamp, BAD_NODE_TIMEOUT))
            {
                ++counter;
            }
        }
    }

    return counter;
}

/* Interval in seconds between hardening checks */
#define HARDENING_INTERVAL 120
#define HARDEN_TIMEOUT 1200

/* Handle a received hardening packet */
static int handle_hardening (void *object, IP_Port source, const uint8_t *source_pubkey, const uint8_t *packet,
                             uint16_t length)
{
    DHT *dht = reinterpret_cast<DHT *> (object);

    if (length < 2)
    {
        return 1;
    }

    switch (packet[0])
    {
        case CHECK_TYPE_GETNODE_REQ:
        {
            if (length != HARDREQ_DATA_SIZE)
            {
                return 1;
            }

            Node_format node, tocheck_node;
            node.ip_port = source;
            memcpy (node.public_key, source_pubkey, crypto_box_PUBLICKEYBYTES);
            memcpy (&tocheck_node, packet + 1, sizeof (Node_format));

            if (dht->getnodes (tocheck_node.ip_port, tocheck_node.public_key, packet + 1 + sizeof (Node_format), &node) == -1)
            {
                return 1;
            }

            return 0;
        }

        case CHECK_TYPE_GETNODE_RES:
        {
            if (length <= crypto_box_PUBLICKEYBYTES + 1)
            {
                return 1;
            }

            if (length > 1 + crypto_box_PUBLICKEYBYTES + sizeof (Node_format) * MAX_SENT_NODES)
            {
                return 1;
            }

            uint16_t length_nodes = length - 1 - crypto_box_PUBLICKEYBYTES;
            Node_format nodes[MAX_SENT_NODES];
            int num_nodes = unpack_nodes (nodes, MAX_SENT_NODES, 0, packet + 1 + crypto_box_PUBLICKEYBYTES, length_nodes, 0);

            /* TODO: MAX_SENT_NODES nodes should be returned at all times
             (right now we have a small network size so it could cause problems for testing and etc..) */
            if (num_nodes <= 0)
            {
                return 1;
            }

            /* NOTE: This should work for now but should be changed to something better. */
            if (dht->have_nodes_closelist (nodes, num_nodes) < (uint32_t) ( (num_nodes + 2) / 2))
            {
                return 1;
            }

            IPPTsPng *temp = dht->get_closelist_IPPTsPng (packet + 1, nodes[0].ip_port.ip.family);

            if (temp == NULL)
            {
                return 1;
            }

            if (is_timeout (temp->hardening.send_nodes_timestamp, HARDENING_INTERVAL))
            {
                return 1;
            }

            if (public_key_cmp (temp->hardening.send_nodes_pingedid.data.data(), source_pubkey) != 0)
            {
                return 1;
            }

            /* If Nodes look good and the request checks out */
            temp->hardening.send_nodes_ok = 1;
            return 0;/* success*/
        }
    }

    return 1;
}

/* Return a random node from all the nodes we are connected to.
 * TODO: improve this function.
 */
Node_format DHT::random_node (sa_family_t sa_family)
{
    uint8_t id[crypto_box_PUBLICKEYBYTES];
    uint32_t i;

    for (i = 0; i < crypto_box_PUBLICKEYBYTES / 4; ++i)   /* populate the id with pseudorandom bytes.*/
    {
        uint32_t t = rand();
        memcpy (id + i * sizeof (t), &t, sizeof (t));
    }

    Node_format nodes_list[MAX_SENT_NODES];
    memset (nodes_list, 0, sizeof (nodes_list));
    uint32_t num_nodes = get_close_nodes (id, nodes_list, sa_family, 1, 0);

    if (num_nodes == 0)
    {
        return nodes_list[0];
    }
    else
    {
        return nodes_list[rand() % num_nodes];
    }
}

/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
uint16_t list_nodes (Client_data *list, unsigned int length, Node_format *nodes, uint16_t max_num)
{
    if (max_num == 0)
    {
        return 0;
    }

    uint16_t count = 0;

    unsigned int i;

    for (i = length; i != 0; --i)
    {
        IPPTsPng *assoc = NULL;

        if (!is_timeout (list[i - 1].assoc4.timestamp, BAD_NODE_TIMEOUT))
        {
            assoc = &list[i - 1].assoc4;
        }

        if (!is_timeout (list[i - 1].assoc6.timestamp, BAD_NODE_TIMEOUT))
        {
            if (assoc == NULL)
            {
                assoc = &list[i - 1].assoc6;
            }
            else if (rand() % 2)
            {
                assoc = &list[i - 1].assoc6;
            }
        }

        if (assoc != NULL)
        {
            memcpy (nodes[count].public_key, list[i - 1].public_key.data.data(), crypto_box_PUBLICKEYBYTES);
            nodes[count].ip_port = assoc->ip_port;
            ++count;

            if (count >= max_num)
            {
                return count;
            }
        }
    }

    return count;
}

/* Put up to max_num nodes in nodes from the random friends.
 *
 * return the number of nodes.
 */
uint16_t DHT::randfriends_nodes (Node_format *nodes, uint16_t max_num)
{
    if (max_num == 0)
    {
        return 0;
    }

    uint16_t count = 0;
    unsigned int i, r = rand();

    for (i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i)
    {
        count += list_nodes (friends_list[ (i + r) % DHT_FAKE_FRIEND_NUMBER].client_list, MAX_FRIEND_CLIENTS, nodes + count,
                             max_num - count);

        if (count >= max_num)
        {
            break;
        }
    }

    return count;
}

/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
uint16_t DHT::closelist_nodes (Node_format *nodes, uint16_t max_num)
{
    return list_nodes (close_clientlist, LCLIENT_LIST, nodes, max_num);
}

void DHT::do_hardening ()
{
    uint32_t i;

    for (i = 0; i < LCLIENT_LIST * 2; ++i)
    {
        IPPTsPng  *cur_iptspng;
        sa_family_t sa_family;
        uint8_t   *public_key = close_clientlist[i / 2].public_key.data.data();

        if (i % 2 == 0)
        {
            cur_iptspng = &close_clientlist[i / 2].assoc4;
            sa_family = AF_INET;
        }
        else
        {
            cur_iptspng = &close_clientlist[i / 2].assoc6;
            sa_family = AF_INET6;
        }

        if (is_timeout (cur_iptspng->timestamp, BAD_NODE_TIMEOUT))
        {
            continue;
        }

        if (cur_iptspng->hardening.send_nodes_ok == 0)
        {
            if (is_timeout (cur_iptspng->hardening.send_nodes_timestamp, HARDENING_INTERVAL))
            {
                Node_format rand_node = random_node (sa_family);

                if (!ipport_isset (&rand_node.ip_port))
                {
                    continue;
                }

                if (id_equal (public_key, rand_node.public_key))
                {
                    continue;
                }

                Node_format to_test;
                to_test.ip_port = cur_iptspng->ip_port;
                memcpy (to_test.public_key, public_key, crypto_box_PUBLICKEYBYTES);

                //TODO: The search id should maybe not be ours?
                if (send_hardening_getnode_req (&rand_node, &to_test, self_public_key.data.data()) > 0)
                {
                    memcpy (cur_iptspng->hardening.send_nodes_pingedid.data.data(), rand_node.public_key, crypto_box_PUBLICKEYBYTES);
                    cur_iptspng->hardening.send_nodes_timestamp = unix_time();
                }
            }
        }
        else
        {
            if (is_timeout (cur_iptspng->hardening.send_nodes_timestamp, HARDEN_TIMEOUT))
            {
                cur_iptspng->hardening.send_nodes_ok = 0;
            }
        }

        //TODO: add the 2 other testers.
    }
}

/*----------------------------------------------------------------------------------*/

void DHT::cryptopacket_registerhandler (uint8_t byte, cryptopacket_handler_callback cb, void *object)
{
    cryptopackethandlers[byte].function = cb;
    cryptopackethandlers[byte].object = object;
}

static int cryptopacket_handle (void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    DHT *dht = reinterpret_cast<DHT *> (object);

    if (packet[0] == NET_PACKET_CRYPTO)
    {
        if (length <= crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES ||
                length > MAX_CRYPTO_REQUEST_SIZE + crypto_box_MACBYTES)
        {
            return 1;
        }

        if (public_key_cmp (packet + 1, dht->self_public_key.data.data()) == 0)  // Check if request is for us.
        {
            uint8_t public_key[crypto_box_PUBLICKEYBYTES];
            uint8_t data[MAX_CRYPTO_REQUEST_SIZE];
            uint8_t number;
            int len = handle_request (dht->self_public_key.data.data(), dht->self_secret_key.data.data(), public_key, data, &number, packet, length);

            if (len == -1 || len == 0)
            {
                return 1;
            }

            if (!dht->cryptopackethandlers[number].function)
            {
                return 1;
            }

            return dht->cryptopackethandlers[number].function (dht->cryptopackethandlers[number].object, source, public_key,
                                                               data, len);

        }
        else     /* If request is not for us, try routing it. */
        {
            int retval = dht->route_packet (packet + 1, packet, length);

            if ( (unsigned int) retval == length)
            {
                return 0;
            }
        }
    }

    return 1;
}

/*----------------------------------------------------------------------------------*/

DHT::DHT (Networking_Core *net) :
    dht_ping_array (DHT_PING_ARRAY_SIZE, PING_TIMEOUT),
    dht_harden_ping_array (DHT_PING_ARRAY_SIZE, PING_TIMEOUT)
{
    /* init time */
    unix_time_update();
    assert (net && "Networking_Core must not be null");

    this->net = net;
    this->ping = std::unique_ptr<PING> (new PING (this));

    networking_registerhandler (this->net, NET_PACKET_GET_NODES, &handle_getnodes, this);
    networking_registerhandler (this->net, NET_PACKET_SEND_NODES_IPV6, &handle_sendnodes_ipv6, this);
    networking_registerhandler (this->net, NET_PACKET_CRYPTO, &cryptopacket_handle, this);
    this->cryptopacket_registerhandler (CRYPTO_PACKET_NAT_PING, &handle_NATping, this);
    this->cryptopacket_registerhandler (CRYPTO_PACKET_HARDENING, &handle_hardening, this);

    new_symmetric_key (this->secret_symmetric_key);
    crypto_box_keypair (this->self_public_key.data.data(), this->self_secret_key.data.data());

#ifdef ENABLE_ASSOC_DHT
    this->assoc = new_Assoc_default (this->self_public_key);
#endif
    uint32_t i;

    for (i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i)
    {
        uint8_t random_key_bytes[crypto_box_PUBLICKEYBYTES];
        randombytes (random_key_bytes, sizeof (random_key_bytes));

        if (!this->addfriend (random_key_bytes, 0, 0, 0, 0))
        {
            throw std::runtime_error ("Add friend error");
        }
    }
}

DHT *new_DHT (Networking_Core *net)
{
    return new DHT (net);
}

void DHT::do_DHT ()
{
    unix_time_update();

    if (last_run == unix_time())
    {
        return;
    }

    // Load friends/clients if first call to do_DHT
    if (loaded_num_nodes)
    {
        connect_after_load ();
    }

    do_Close ();
    do_DHT_friends ();
    do_NAT ();
    do_to_ping (ping.get());
    //do_hardening(dht);
#ifdef ENABLE_ASSOC_DHT

    if (assoc)
    {
        do_Assoc (assoc, this);
    }

#endif
    last_run = unix_time();
}

DHT::~DHT()
{
#ifdef ENABLE_ASSOC_DHT
    kill_Assoc (assoc);
#endif
    networking_registerhandler (net, NET_PACKET_GET_NODES, NULL, NULL);
    networking_registerhandler (net, NET_PACKET_SEND_NODES_IPV6, NULL, NULL);
    cryptopacket_registerhandler (CRYPTO_PACKET_NAT_PING, NULL, NULL);
    cryptopacket_registerhandler (CRYPTO_PACKET_HARDENING, NULL, NULL);
}

/* new DHT format for load/save, more robust and forward compatible */
//TODO: Move this closer to Messenger.
#define DHT_STATE_COOKIE_GLOBAL 0x159000d

#define DHT_STATE_COOKIE_TYPE      0x11ce
#define DHT_STATE_TYPE_NODES       4

#define MAX_SAVED_DHT_NODES (((DHT_FAKE_FRIEND_NUMBER * MAX_FRIEND_CLIENTS) + LCLIENT_LIST) * 2)

/* Get the size of the DHT (for saving). */
uint32_t DHT::size () const
{
    uint32_t numv4 = 0, numv6 = 0, i, j;

    for (i = 0; i < LCLIENT_LIST; ++i)
    {
        numv4 += (close_clientlist[i].assoc4.timestamp != 0);
        numv6 += (close_clientlist[i].assoc6.timestamp != 0);
    }

    for (i = 0; i < DHT_FAKE_FRIEND_NUMBER && i < friends_list.size(); ++i)
    {
        const DHT_Friend *fr = &friends_list[i];

        for (j = 0; j < MAX_FRIEND_CLIENTS; ++j)
        {
            numv4 += (fr->client_list[j].assoc4.timestamp != 0);
            numv6 += (fr->client_list[j].assoc6.timestamp != 0);
        }
    }

    uint32_t size32 = sizeof (uint32_t), sizesubhead = size32 * 2;

    return size32 + sizesubhead + (packed_node_size (AF_INET) * numv4) + (packed_node_size (AF_INET6) * numv6);
}

static uint8_t *z_state_save_subheader (uint8_t *data, uint32_t len, uint16_t type)
{
    host_to_lendian32 (data, len);
    data += sizeof (uint32_t);
    host_to_lendian32 (data, (host_tolendian16 (DHT_STATE_COOKIE_TYPE) << 16) | host_tolendian16 (type));
    data += sizeof (uint32_t);
    return data;
}


/* Save the DHT in data where data is an array of size DHT_size(). */
void DHT::save (uint8_t *data)
{
    host_to_lendian32 (data,  DHT_STATE_COOKIE_GLOBAL);
    data += sizeof (uint32_t);

    uint32_t num, i, j;

    uint8_t *old_data = data;

    /* get right offset. we write the actual header later. */
    data = z_state_save_subheader (data, 0, 0);

    Node_format clients[MAX_SAVED_DHT_NODES];

    for (num = 0, i = 0; i < LCLIENT_LIST; ++i)
    {
        if (close_clientlist[i].assoc4.timestamp != 0)
        {
            memcpy (clients[num].public_key, close_clientlist[i].public_key.data.data(), crypto_box_PUBLICKEYBYTES);
            clients[num].ip_port = close_clientlist[i].assoc4.ip_port;
            ++num;
        }

        if (close_clientlist[i].assoc6.timestamp != 0)
        {
            memcpy (clients[num].public_key, close_clientlist[i].public_key.data.data(), crypto_box_PUBLICKEYBYTES);
            clients[num].ip_port = close_clientlist[i].assoc6.ip_port;
            ++num;
        }
    }

    for (i = 0; i < DHT_FAKE_FRIEND_NUMBER && i < friends_list.size(); ++i)
    {
        DHT_Friend *fr = &friends_list[i];

        for (j = 0; j < MAX_FRIEND_CLIENTS; ++j)
        {
            if (fr->client_list[j].assoc4.timestamp != 0)
            {
                memcpy (clients[num].public_key, fr->client_list[j].public_key.data.data(), crypto_box_PUBLICKEYBYTES);
                clients[num].ip_port = fr->client_list[j].assoc4.ip_port;
                ++num;
            }

            if (fr->client_list[j].assoc6.timestamp != 0)
            {
                memcpy (clients[num].public_key, fr->client_list[j].public_key.data.data(), crypto_box_PUBLICKEYBYTES);
                clients[num].ip_port = fr->client_list[j].assoc6.ip_port;
                ++num;
            }
        }
    }

    z_state_save_subheader (old_data, pack_nodes (data, sizeof (Node_format) * num, clients, num), DHT_STATE_TYPE_NODES);
}

/* Bootstrap from this number of nodes every time DHT_connect_after_load() is called */
#define SAVE_BOOTSTAP_FREQUENCY 8

/* Start sending packets after DHT loaded_friends_list and loaded_clients_list are set */
bool DHT::connect_after_load ()
{
    if (loaded_nodes_list.empty())
    {
        return false;
    }

    /* DHT is connected, stop. */
    if (non_lan_connected())
    {
        loaded_nodes_list.clear();
        loaded_num_nodes = 0;
        return true;
    }

    unsigned int i;

    for (i = 0; i < loaded_num_nodes && i < SAVE_BOOTSTAP_FREQUENCY; ++i)
    {
        unsigned int index = loaded_nodes_index % loaded_num_nodes;
        bootstrap (loaded_nodes_list[index].ip_port, loaded_nodes_list[index].public_key);
        ++loaded_nodes_index;
    }

    return true;
}

static int dht_load_state_callback (void *outer, const uint8_t *data, uint32_t length, uint16_t type)
{
    DHT *dht = reinterpret_cast<DHT *> (outer);

    switch (type)
    {
        case DHT_STATE_TYPE_NODES:
            if (length == 0)
            {
                break;
            }

            {
                dht->loaded_nodes_list.clear();
                dht->loaded_nodes_list.resize (MAX_SAVED_DHT_NODES);

                int num = unpack_nodes (dht->loaded_nodes_list.data(), MAX_SAVED_DHT_NODES, NULL, data, length, 0);

                if (num > 0)
                {
                    dht->loaded_num_nodes = num;
                }
                else
                {
                    dht->loaded_num_nodes = 0;
                }

            } /* localize declarations */

            break;

#ifdef DEBUG

        default:
            fprintf (stderr, "Load state (DHT): contains unrecognized part (len %u, type %u)\n",
                     length, type);
            break;
#endif
    }

    return 0;
}

bool DHT::load (const uint8_t *data, uint32_t length)
{
    uint32_t cookie_len = sizeof (uint32_t);

    if (length > cookie_len)
    {
        uint32_t data32;
        lendian_to_host32 (&data32, data);

        if (data32 == DHT_STATE_COOKIE_GLOBAL)
            return load_state (dht_load_state_callback, this, data + cookie_len,
                               length - cookie_len, DHT_STATE_COOKIE_TYPE) == 0;
    }

    return false;
}


bool DHT::isconnected() const
{
    uint32_t i;
    unix_time_update();

    for (i = 0; i < LCLIENT_LIST; ++i)
    {
        const Client_data *client = &close_clientlist[i];

        if (!is_timeout (client->assoc4.timestamp, BAD_NODE_TIMEOUT) ||
                !is_timeout (client->assoc6.timestamp, BAD_NODE_TIMEOUT))
        {
            return true;
        }
    }

    return false;
}

bool DHT::non_lan_connected() const
{
    unix_time_update();

    for (size_t i = 0; i < LCLIENT_LIST; ++i)
    {
        const Client_data *client = &close_clientlist[i];

        if (!is_timeout (client->assoc4.timestamp, BAD_NODE_TIMEOUT) && LAN_ip (client->assoc4.ip_port.ip) == -1)
        {
            return true;
        }

        if (!is_timeout (client->assoc6.timestamp, BAD_NODE_TIMEOUT) && LAN_ip (client->assoc6.ip_port.ip) == -1)
        {
            return true;
        }

    }

    return false;
}
