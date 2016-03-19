/*
* onion_client.c -- Implementation of the client part of docs/Prevent_Tracking.txt
*                   (The part that uses the onion stuff to connect to the friend)
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "onion_client.hpp"
#include "util.hpp"
#include "LAN_discovery.hpp"
#include "protocol.hpp"

/* defines for the array size and
   timeout for onion announce packets. */
#define ANNOUNCE_ARRAY_SIZE 256
#define ANNOUNCE_TIMEOUT 10

using namespace bitox;
using namespace bitox::network;
using namespace bitox::dht;

constexpr size_t MAX_PATH_NODES = 32;

/* Add a node to the path_nodes bootstrap array */
bool Onion_Client::onion_add_bs_path_node(const IPPort &ip_port, const PublicKey &public_key)
{
    if (ip_port.ip.family != Family::FAMILY_AF_INET && ip_port.ip.family != Family::FAMILY_AF_INET6)
        return false;

    for (size_t i = 0; i < path_nodes_bs.size(); ++i) {
        if (public_key == path_nodes_bs[i].public_key)
            return false;
    }

    path_nodes_bs.emplace_back(public_key, ip_port);

    if (path_nodes_bs.size() > MAX_PATH_NODES)
        path_nodes_bs.pop_front();

    return true;
}

/* Add a node to the path_nodes array */
bool Onion_Client::onion_add_path_node(bitox::network::IPPort &ip_port, const PublicKey &public_key)
{
    if (ip_port.ip.family != Family::FAMILY_AF_INET && ip_port.ip.family != Family::FAMILY_AF_INET6)
        return false;

    for (size_t i = 0; i < path_nodes.size(); ++i) {
        if (public_key == path_nodes[i].public_key)
            return false;
    }

    path_nodes.emplace_back(public_key, ip_port);

    if (path_nodes.size() > MAX_PATH_NODES)
        path_nodes.pop_front();

    return true;
}

/* Put up to max_num nodes in nodes.
 *
 * return the number of nodes.
 */
uint16_t Onion_Client::onion_backup_nodes(NodeFormat *nodes, uint16_t max_num) const
{
    if (!max_num)
        return 0;

    unsigned int num_nodes = path_nodes.size();

    if (num_nodes == 0)
        return 0;

    if (max_num > num_nodes)
        max_num = num_nodes;

    for (size_t i = 0; i < max_num; ++i) {
        nodes[i] = path_nodes[num_nodes - 1 - i];
    }

    return max_num;
}

/* Put up to max_num random nodes in nodes.
 *
 * return the number of nodes.
 */
uint16_t Onion_Client::random_nodes_path_onion(NodeFormat *nodes, uint16_t max_num) const
{
    if (!max_num)
        return 0;

    unsigned int num_nodes = path_nodes.size();

    //if (DHT_non_lan_connected(dht)) {
    if (dht->isconnected()) {
        if (num_nodes == 0)
            return 0;

        for (size_t i = 0; i < max_num; ++i) {
            nodes[i] = path_nodes[rand() % num_nodes];
        }
    } else {
        int random_tcp = c->get_random_tcp_con_number();

        if (random_tcp == -1) {
            return 0;
        }

        if (num_nodes >= 2) {
            nodes[0].ip_port.ip.family = Family::FAMILY_TCP_FAMILY;
            nodes[0].ip_port.ip.from_uint32(random_tcp);

            for (size_t i = 1; i < max_num; ++i) {
                nodes[i] = path_nodes[rand() % num_nodes];
            }
        } else {
            unsigned int num_nodes_bs = path_nodes_bs.size();

            if (num_nodes_bs == 0)
                return 0;

            nodes[0].ip_port.ip.family = Family::FAMILY_TCP_FAMILY;
            nodes[0].ip_port.ip.from_uint32(random_tcp);

            for (size_t i = 1; i < max_num; ++i) {
                nodes[i] = path_nodes_bs[rand() % num_nodes_bs];
            }
        }
    }

    return max_num;
}

/*
 * return -1 if nodes are suitable for creating a new path.
 * return path number of already existing similar path if one already exists.
 */
static int is_path_used(const Onion_Client_Paths *onion_paths, const NodeFormat *nodes)
{
    for (size_t i = 0; i < NUMBER_ONION_PATHS; ++i) {
        if (is_timeout(onion_paths->last_path_success[i], ONION_PATH_TIMEOUT)) {
            continue;
        }

        if (is_timeout(onion_paths->path_creation_time[i], ONION_PATH_MAX_LIFETIME)) {
            continue;
        }

        // TODO: do we really have to check it with the last node?
        if (ipport_equal(&onion_paths->paths[i].ip_port1, &nodes[ONION_PATH_LENGTH - 1].ip_port)) {
            return i;
        }
    }

    return -1;
}

/* is path timed out */
static bool path_timed_out(Onion_Client_Paths *onion_paths, uint32_t pathnum)
{
    pathnum = pathnum % NUMBER_ONION_PATHS;

    return ((onion_paths->last_path_success[pathnum] + ONION_PATH_TIMEOUT < onion_paths->last_path_used[pathnum]
             && onion_paths->last_path_used_times[pathnum] >= ONION_PATH_MAX_NO_RESPONSE_USES)
            || is_timeout(onion_paths->path_creation_time[pathnum], ONION_PATH_MAX_LIFETIME));
}

/* Create a new path or use an old suitable one (if pathnum is valid)
 * or a random one from onion_paths.
 *
 * return -1 on failure
 * return 0 on success
 *
 * TODO: Make this function better, it currently probably is vulnerable to some attacks that
 * could de anonimize us.
 */
int Onion_Client::random_path(Onion_Client_Paths *onion_paths, uint32_t pathnum, Onion_Path *path) const
{
    if (pathnum == UINT32_MAX) {
        pathnum = rand() % NUMBER_ONION_PATHS;
    } else {
        pathnum = pathnum % NUMBER_ONION_PATHS;
    }

    if (path_timed_out(onion_paths, pathnum)) {
        NodeFormat nodes[ONION_PATH_LENGTH];

        if (random_nodes_path_onion(nodes, ONION_PATH_LENGTH) != ONION_PATH_LENGTH)
            return -1;

        int n = is_path_used(onion_paths, nodes);

        if (n == -1) {
            onion_paths->paths[pathnum] = Onion_Path(dht, nodes);

            onion_paths->last_path_success[pathnum] = unix_time() + ONION_PATH_FIRST_TIMEOUT - ONION_PATH_TIMEOUT;
            onion_paths->path_creation_time[pathnum] = unix_time();
            onion_paths->last_path_used_times[pathnum] = ONION_PATH_MAX_NO_RESPONSE_USES / 2;

            uint32_t path_num = rand();
            path_num /= NUMBER_ONION_PATHS;
            path_num *= NUMBER_ONION_PATHS;
            path_num += pathnum;

            onion_paths->paths[pathnum].path_num = path_num;
        } else {
            pathnum = n;
        }
    }

    ++onion_paths->last_path_used_times[pathnum];
    onion_paths->last_path_used[pathnum] = unix_time();
    memcpy(path, &onion_paths->paths[pathnum], sizeof(Onion_Path));
    return 0;
}

/* Does path with path_num exist. */
static bool path_exists(Onion_Client_Paths *onion_paths, uint32_t path_num)
{
    if (path_timed_out(onion_paths, path_num))
        return 0;

    return onion_paths->paths[path_num % NUMBER_ONION_PATHS].path_num == path_num;
}

/* Set path timeouts, return the path number.
 *
 */
uint32_t Onion_Client::set_path_timeouts(Onion_Friend *onion_friend, uint32_t path_num)
{
    Onion_Client_Paths *onion_paths;

    if (!onion_friend) {
        onion_paths = &this->onion_paths_self;
    } else {
        onion_paths = &this->onion_paths_friends;
    }

    if (onion_paths->paths[path_num % NUMBER_ONION_PATHS].path_num == path_num) {
        onion_paths->last_path_success[path_num % NUMBER_ONION_PATHS] = unix_time();
        onion_paths->last_path_used_times[path_num % NUMBER_ONION_PATHS] = 0;

        NodeFormat nodes[ONION_PATH_LENGTH];

        if (onion_path_to_nodes(nodes, ONION_PATH_LENGTH, &onion_paths->paths[path_num % NUMBER_ONION_PATHS]) == 0)
        {
            for (size_t i = 0; i < ONION_PATH_LENGTH; ++i)
            {
                this->onion_add_path_node(nodes[i].ip_port, nodes[i].public_key);
            }
        }

        return path_num;
    }

    return ~0;
}

/* Function to send onion packet via TCP and UDP.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Onion_Client::send_onion_packet_tcp_udp(const Onion_Path *path, const IPPort &dest,
        const uint8_t *data, uint16_t length) const
{
    if (path->ip_port1.ip.family == Family::FAMILY_AF_INET || path->ip_port1.ip.family == Family::FAMILY_AF_INET6) {
        uint8_t packet[ONION_MAX_PACKET_SIZE];
        int len = path->create_onion_packet(packet, sizeof(packet), dest, data, length);

        if (len == -1)
            return -1;

        if (sendpacket(net, path->ip_port1, packet, len) != len)
            return -1;

        return 0;
    } else if (path->ip_port1.ip.family == Family::FAMILY_TCP_FAMILY) {
        uint8_t packet[ONION_MAX_PACKET_SIZE];
        int len = create_onion_packet_tcp(packet, sizeof(packet), path, dest, data, length);

        if (len == -1)
            return -1;

        return c->send_tcp_onion_request(path->ip_port1.ip.to_uint32(), packet, len); // TODO TCP_conn_number ???
    } else {
        return -1;
    }
}

/* Creates a sendback for use in an announce request.
 *
 * num is 0 if we used our secret public key for the announce
 * num is 1 + friendnum if we use a temporary one.
 *
 * Public key is the key we will be sending it to.
 * ip_port is the ip_port of the node we will be sending
 * it to.
 *
 * sendback must be at least ONION_ANNOUNCE_SENDBACK_DATA_LENGTH big
 *
 * return -1 on failure
 * return 0 on success
 *
 */
int Onion_Client::new_sendback(Onion_Friend *onion_friend, const PublicKey &public_key, const bitox::network::IPPort &ip_port, uint32_t path_num, uint64_t *sendback)
{
    AnnounceRecord record;
    if (onion_friend)
        record.real_public_key = onion_friend->real_public_key;
    else
        record.real_public_key = PublicKey();

    record.public_key = public_key;
    record.ip_port = ip_port;
    record.path_num = path_num;

    *sendback = announce_ping_array.add(std::move(record));

    if (*sendback == 0)
        return -1;

    return 0;
}

/* Checks if the sendback is valid and returns the public key contained in it in ret_pubkey and the
 * ip contained in it in ret_ip_port
 *
 * sendback is the sendback ONION_ANNOUNCE_SENDBACK_DATA_LENGTH big
 * ret_pubkey must be at least crypto_box_PUBLICKEYBYTES big
 * ret_ip_port must be at least 1 big
 *
 * return ~0 on failure
 * return num (see new_sendback(...)) on success
 */
bool Onion_Client::check_sendback(const uint8_t *sendback, PublicKey &ret_pubkey, IPPort &ret_ip_port, uint32_t &path_num, PublicKey &real_public_key_out)
{
    uint64_t sback;
    memcpy(&sback, sendback, sizeof(uint64_t));
    uint8_t data[sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES + sizeof(IPPort) + sizeof(uint32_t)];

    AnnounceRecord record;

    if (announce_ping_array.check(record, sback))
        return false;

    ret_pubkey = record.public_key;
    ret_ip_port = record.ip_port;
    path_num = record.path_num;

    real_public_key_out = record.real_public_key;
    return true;
}

int Onion_Client::client_send_announce_request(Onion_Friend *onion_friend, const IPPort &dest, const PublicKey &dest_pubkey,
        const PublicKey &ping_id, uint32_t pathnum)
{
    uint64_t sendback;
    Onion_Path path;

    if (!onion_friend) {
        if (this->random_path(&this->onion_paths_self, pathnum, &path) == -1)
            return -1;
    } else {
        if (random_path(&this->onion_paths_friends, pathnum, &path) == -1)
            return -1;
    }

    if (new_sendback(onion_friend, dest_pubkey, dest, path.path_num, &sendback) == -1)
        return -1;

    PublicKey zero_ping_id;

    uint8_t request[ONION_ANNOUNCE_REQUEST_SIZE];
    int len;

    if (!onion_friend) {
        len = create_announce_request(request, sizeof(request), dest_pubkey, this->c->self_public_key,
                                      this->c->self_secret_key, ping_id, this->c->self_public_key, this->temp_public_key, sendback);

    } else {
        len = create_announce_request(request, sizeof(request), dest_pubkey, onion_friend->temp_public_key,
                                      onion_friend->temp_secret_key, ping_id, onion_friend->real_public_key, zero_ping_id,
                                      sendback);
    }

    if (len == -1) {
        return -1;
    }

    return send_onion_packet_tcp_udp(&path, dest, request, len);
}

static PublicKey cmp_public_key;
static int cmp_entry(const void *a, const void *b)
{
    Onion_Node entry1, entry2;
    memcpy(&entry1, a, sizeof(Onion_Node));
    memcpy(&entry2, b, sizeof(Onion_Node));
    int t1 = is_timeout(entry1.timestamp, ONION_NODE_TIMEOUT);
    int t2 = is_timeout(entry2.timestamp, ONION_NODE_TIMEOUT);

    if (t1 && t2)
        return 0;

    if (t1)
        return -1;

    if (t2)
        return 1;

    int close = id_closest(cmp_public_key, entry1.public_key, entry2.public_key);

    if (close == 1)
        return 1;

    if (close == 2)
        return -1;

    return 0;
}

int Onion_Client::client_add_to_list(Onion_Friend *onion_friend, const PublicKey &public_key, bitox::network::IPPort &ip_port,
                                     uint8_t is_stored, const PublicKey &pingid_or_key, uint32_t path_num)
{
    Onion_Node *list_nodes = NULL;
    PublicKey reference_id;
    unsigned int list_length;

    if (!onion_friend) {
        list_nodes = this->clients_announce_list;
        reference_id = this->c->self_public_key;
        list_length = MAX_ONION_CLIENTS_ANNOUNCE;

        if (is_stored == 1 && pingid_or_key != this->temp_public_key) {
            is_stored = 0;
        }

    } else {
        if (is_stored >= 2)
            return -1;

        list_nodes = onion_friend->clients_list;
        reference_id = onion_friend->real_public_key;
        list_length = MAX_ONION_CLIENTS;
    }

    cmp_public_key = reference_id;
    qsort(list_nodes, list_length, sizeof(Onion_Node), cmp_entry);

    int index = -1, stored = 0;

    if (is_timeout(list_nodes[0].timestamp, ONION_NODE_TIMEOUT)
            || id_closest(reference_id, list_nodes[0].public_key, public_key) == 2) {
        index = 0;
    }

    for (size_t i = 0; i < list_length; ++i) {
        if (list_nodes[i].public_key == public_key) {
            index = i;
            stored = 1;
            break;
        }
    }

    if (index == -1)
        return 0;

    list_nodes[index].public_key = public_key;
    list_nodes[index].ip_port = ip_port;

    //TODO: remove this and find a better source of nodes to use for paths.
    this->onion_add_path_node(ip_port, public_key);

    if (is_stored == 1) {
        list_nodes[index].data_public_key = pingid_or_key;
    } else {
        list_nodes[index].ping_id = pingid_or_key;
    }

    list_nodes[index].is_stored = is_stored;
    list_nodes[index].timestamp = unix_time();

    if (!stored)
        list_nodes[index].last_pinged = 0;

    list_nodes[index].path_used = set_path_timeouts(onion_friend, path_num);
    return 0;
}

static int good_to_ping(Last_Pinged *last_pinged, uint8_t *last_pinged_index, const PublicKey &public_key)
{
    for (size_t i = 0; i < MAX_STORED_PINGED_NODES; ++i) {
        if (!is_timeout(last_pinged[i].timestamp, MIN_NODE_PING_TIME))
            if (last_pinged[i].public_key == public_key)
                return 0;
    }

    last_pinged[*last_pinged_index % MAX_STORED_PINGED_NODES].public_key = public_key;
    last_pinged[*last_pinged_index % MAX_STORED_PINGED_NODES].timestamp = unix_time();
    ++*last_pinged_index;
    return 1;
}

int Onion_Client::client_ping_nodes(Onion_Friend *onion_friend, const NodeFormat *nodes, uint16_t num_nodes, IPPort source)
{
    if (num_nodes == 0)
        return 0;

    Onion_Node *list_nodes = NULL;
    PublicKey reference_id;
    unsigned int list_length;

    Last_Pinged *last_pinged = NULL;
    uint8_t *last_pinged_index = NULL;

    if (!onion_friend) {
        list_nodes = this->clients_announce_list;
        reference_id = this->c->self_public_key;
        list_length = MAX_ONION_CLIENTS_ANNOUNCE;
        last_pinged = this->last_pinged;
        last_pinged_index = &this->last_pinged_index;
    } else {
        list_nodes = onion_friend->clients_list;
        reference_id = onion_friend->real_public_key;
        list_length = MAX_ONION_CLIENTS;
        last_pinged = onion_friend->last_pinged;
        last_pinged_index = &onion_friend->last_pinged_index;
    }

    unsigned int i, j;
    int lan_ips_accepted = (LAN_ip(source.ip) == 0);

    for (i = 0; i < num_nodes; ++i) {

        if (!lan_ips_accepted)
            if (LAN_ip(nodes[i].ip_port.ip) == 0)
                continue;

        if (is_timeout(list_nodes[0].timestamp, ONION_NODE_TIMEOUT)
                || id_closest(reference_id, list_nodes[0].public_key, nodes[i].public_key) == 2
                || is_timeout(list_nodes[1].timestamp, ONION_NODE_TIMEOUT)
                || id_closest(reference_id, list_nodes[1].public_key, nodes[i].public_key) == 2 ) {
            /* check if node is already in list. */
            for (j = 0; j < list_length; ++j) {
                if (list_nodes[j].public_key == nodes[i].public_key) {
                    break;
                }
            }

            if (j == list_length && good_to_ping(last_pinged, last_pinged_index, nodes[i].public_key)) {
                client_send_announce_request(onion_friend, nodes[i].ip_port, nodes[i].public_key, PublicKey(), ~0);
            }
        }
    }

    return 0;
}

static int handle_announce_response(void *object, const IPPort &source, const uint8_t *packet, uint16_t length)
{
    Onion_Client *onion_c = (Onion_Client *) object;

    if (length < ONION_ANNOUNCE_RESPONSE_MIN_SIZE || length > ONION_ANNOUNCE_RESPONSE_MAX_SIZE)
        return 1;

    uint16_t len_nodes = length - ONION_ANNOUNCE_RESPONSE_MIN_SIZE;

    PublicKey public_key;
    IPPort ip_port;
    uint32_t path_num;
    PublicKey real_public_key;
    if (!onion_c->check_sendback(packet + 1, public_key, ip_port, path_num, real_public_key))
        return -1;

    uint8_t plain[1 + ONION_PING_ID_SIZE + len_nodes];
    int len = -1;

    Onion_Friend *onion_friend = nullptr;
    if (real_public_key == PublicKey()) {
        len = decrypt_data(public_key, onion_c->c->self_secret_key, packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES,
                           length - (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES), plain);
    } else {
        auto it = onion_c->friends.find(real_public_key);

        if (it == onion_c->friends.end())
            return 1;

        onion_friend = it->second;
        len = decrypt_data(public_key, onion_friend->temp_secret_key,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES,
                           length - (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES), plain);
    }

    if ((uint32_t)len != sizeof(plain))
        return 1;

    if (onion_c->client_add_to_list(onion_friend, public_key, ip_port, plain[0], PublicKey(plain + 1), path_num) == -1)
        return 1;

    if (len_nodes != 0) {
        NodeFormat nodes[MAX_SENT_NODES];
        int num_nodes = unpack_nodes(nodes, MAX_SENT_NODES, 0, plain + 1 + ONION_PING_ID_SIZE, len_nodes, 0);

        if (num_nodes <= 0)
            return 1;

        if (onion_c->client_ping_nodes(onion_friend, nodes, num_nodes, source) == -1)
            return 1;
    }

    //TODO: LAN vs non LAN ips?, if we are connected only to LAN, are we offline?
    onion_c->last_packet_recv = unix_time();
    return 0;
}

#define DATA_IN_RESPONSE_MIN_SIZE ONION_DATA_IN_RESPONSE_MIN_SIZE

static int handle_data_response(void *object, const IPPort &source, const uint8_t *packet, uint16_t length)
{
    Onion_Client *onion_c = (Onion_Client *) object;

    if (length <= (ONION_DATA_RESPONSE_MIN_SIZE + DATA_IN_RESPONSE_MIN_SIZE))
        return 1;

    if (length > MAX_DATA_REQUEST_SIZE)
        return 1;

    uint8_t temp_plain[length - ONION_DATA_RESPONSE_MIN_SIZE];
    int len = decrypt_data(PublicKey(packet + 1 + crypto_box_NONCEBYTES), onion_c->temp_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES), temp_plain);

    if ((uint32_t)len != sizeof(temp_plain))
        return 1;

    uint8_t plain[sizeof(temp_plain) - DATA_IN_RESPONSE_MIN_SIZE];
    len = decrypt_data(PublicKey(temp_plain), onion_c->c->self_secret_key, packet + 1, temp_plain + crypto_box_PUBLICKEYBYTES,
                       sizeof(temp_plain) - crypto_box_PUBLICKEYBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    if (!onion_c->Onion_Data_Handlers[plain[0]].function)
        return 1;

    return onion_c->Onion_Data_Handlers[plain[0]].function(onion_c->Onion_Data_Handlers[plain[0]].object, PublicKey(temp_plain), plain,
            sizeof(plain));
}

#define DHTPK_DATA_MIN_LENGTH (1 + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES)
#define DHTPK_DATA_MAX_LENGTH (DHTPK_DATA_MIN_LENGTH + sizeof(NodeFormat)*MAX_SENT_NODES)
static int handle_dhtpk_announce(void *object, const PublicKey &source_pubkey, const uint8_t *data, uint16_t length)
{
    Onion_Client *onion_c = (Onion_Client *) object;

    if (length < DHTPK_DATA_MIN_LENGTH)
        return 1;

    if (length > DHTPK_DATA_MAX_LENGTH)
        return 1;

    auto it = onion_c->friends.find(source_pubkey);

    if (it == onion_c->friends.end())
        return 1;

    Onion_Friend *onion_friend = it->second;

    uint64_t no_replay;
    memcpy(&no_replay, data + 1, sizeof(uint64_t));
    net_to_host((uint8_t *) &no_replay, sizeof(no_replay));

    if (no_replay <= onion_friend->last_noreplay)
        return 1;

    onion_friend->last_noreplay = no_replay;

    if (onion_friend->dht_pk_callback)
        onion_friend->dht_pk_callback(onion_friend->dht_pk_callback_object,
                                      onion_friend->dht_pk_callback_number, PublicKey(data + 1 + sizeof(uint64_t)));

    onion_friend->onion_set_friend_DHT_pubkey(PublicKey(data + 1 + sizeof(uint64_t)));
    onion_friend->last_seen = unix_time();

    uint16_t len_nodes = length - DHTPK_DATA_MIN_LENGTH;

    if (len_nodes != 0) {
        NodeFormat nodes[MAX_SENT_NODES];
        int num_nodes = unpack_nodes(nodes, MAX_SENT_NODES, 0, data + 1 + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES,
                                     len_nodes, 1);

        if (num_nodes <= 0)
            return 1;

        int i;

        for (i = 0; i < num_nodes; ++i) {
            Family family = nodes[i].ip_port.ip.family;

            if (family == Family::FAMILY_AF_INET || family == Family::FAMILY_AF_INET6) {
                onion_c->dht->getnodes(&nodes[i].ip_port, nodes[i].public_key, onion_friend->dht_public_key);
            } else if (family == Family::FAMILY_TCP_INET || family == Family::FAMILY_TCP_INET6) {
                if (onion_friend->tcp_relay_node_callback) {
                    void *obj = onion_friend->tcp_relay_node_callback_object;
                    uint32_t number = onion_friend->tcp_relay_node_callback_number;
                    onion_friend->tcp_relay_node_callback(obj, number, nodes[i].ip_port, nodes[i].public_key);
                }
            }
        }
    }

    return 0;
}

static int handle_tcp_onion(void *object, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return 1;

    IPPort ip_port;
    ip_port.port = 0;
    ip_port.ip.clear_v6();
    ip_port.ip.family = Family::FAMILY_TCP_FAMILY;

    if (data[0] == NET_PACKET_ANNOUNCE_RESPONSE) {
        return handle_announce_response(object, ip_port, data, length);
    } else if (data[0] == NET_PACKET_ONION_DATA_RESPONSE) {
        return handle_data_response(object, ip_port, data, length);
    }

    return 1;
}

/* Send data of length length to friendnum.
 * This data will be received by the friend using the Onion_Data_Handlers callbacks.
 *
 * Even if this function succeeds, the friend might not receive any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
int Onion_Friend::send_onion_data(const uint8_t *data, uint16_t length)
{
    if (length + DATA_IN_RESPONSE_MIN_SIZE > MAX_DATA_REQUEST_SIZE)
        return -1;

    if (length == 0)
        return -1;

    unsigned int i, good_nodes[MAX_ONION_CLIENTS], num_good = 0, num_nodes = 0;
    Onion_Node *list_nodes = clients_list;

    for (i = 0; i < MAX_ONION_CLIENTS; ++i) {
        if (is_timeout(list_nodes[i].timestamp, ONION_NODE_TIMEOUT))
            continue;

        ++num_nodes;

        if (list_nodes[i].is_stored) {
            good_nodes[num_good] = i;
            ++num_good;
        }
    }

    if (num_good < (num_nodes / 4) + 1)
        return -1;

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

    uint8_t packet[DATA_IN_RESPONSE_MIN_SIZE + length];
    memcpy(packet, client->c->self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    int len = encrypt_data(real_public_key, client->c->self_secret_key, nonce, data,
                           length, packet + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len + crypto_box_PUBLICKEYBYTES != sizeof(packet))
        return -1;

    unsigned int good = 0;

    for (i = 0; i < num_good; ++i) {
        Onion_Path path;

        if (client->random_path(&client->onion_paths_friends, ~0, &path) == -1)
            continue;

        uint8_t o_packet[ONION_MAX_PACKET_SIZE];
        len = create_data_request(o_packet, sizeof(o_packet), real_public_key,
                                  list_nodes[good_nodes[i]].data_public_key, nonce, packet, sizeof(packet));

        if (len == -1)
            continue;

        if (client->send_onion_packet_tcp_udp(&path, list_nodes[good_nodes[i]].ip_port, o_packet, len) == 0)
            ++good;
    }

    return good;
}

/* Try to send the dht public key via the DHT instead of onion
 *
 * Even if this function succeeds, the friend might not receive any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
int Onion_Friend::send_dht_dhtpk(const uint8_t *data, uint16_t length)
{
    if (!know_dht_public_key)
        return -1;

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t temp[DATA_IN_RESPONSE_MIN_SIZE + crypto_box_NONCEBYTES + length];
    memcpy(temp, client->c->self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    memcpy(temp + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    int len = encrypt_data(real_public_key, client->c->self_secret_key, nonce, data,
                           length, temp + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);

    if ((uint32_t)len + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES != sizeof(temp))
        return -1;

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    len = create_request(client->dht->self_public_key, client->dht->self_secret_key, packet,
                         dht_public_key, temp, sizeof(temp), CRYPTO_PACKET_DHTPK);

    if (len == -1)
        return -1;

    return client->dht->route_tofriend(dht_public_key, packet, len);
}

static int handle_dht_dhtpk(void *object, IPPort source, const bitox::PublicKey &source_pubkey, const uint8_t *packet,
                            uint16_t length)
{
    Onion_Client *onion_c = (Onion_Client *) object;

    if (length < DHTPK_DATA_MIN_LENGTH + DATA_IN_RESPONSE_MIN_SIZE + crypto_box_NONCEBYTES)
        return 1;

    if (length > DHTPK_DATA_MAX_LENGTH + DATA_IN_RESPONSE_MIN_SIZE + crypto_box_NONCEBYTES)
        return 1;

    uint8_t plain[DHTPK_DATA_MAX_LENGTH];
    int len = decrypt_data(PublicKey(packet), onion_c->c->self_secret_key, packet + crypto_box_PUBLICKEYBYTES,
                           packet + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                           length - (crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES), plain);

    if (len != length - (DATA_IN_RESPONSE_MIN_SIZE + crypto_box_NONCEBYTES))
        return 1;

    if (public_key_cmp(source_pubkey.data.data(), plain + 1 + sizeof(uint64_t)) != 0)
        return 1;

    return handle_dhtpk_announce(onion_c, PublicKey(packet), plain, len);
}
/* Send the packets to tell our friends what our DHT public key is.
 *
 * if onion_dht_both is 0, use only the onion to send the packet.
 * if it is 1, use only the dht.
 * if it is something else, use both.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
int Onion_Friend::send_dhtpk_announce(uint8_t onion_dht_both)
{
    uint8_t data[DHTPK_DATA_MAX_LENGTH];
    data[0] = ONION_DATA_DHTPK;
    uint64_t no_replay = unix_time();
    host_to_net((uint8_t *)&no_replay, sizeof(no_replay));
    memcpy(data + 1, &no_replay, sizeof(no_replay));
    memcpy(data + 1 + sizeof(uint64_t), client->dht->self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    NodeFormat nodes[MAX_SENT_NODES];
    uint16_t num_relays = client->c->copy_connected_tcp_relays(nodes, (MAX_SENT_NODES / 2));
    uint16_t num_nodes = client->dht->closelist_nodes(&nodes[num_relays], MAX_SENT_NODES - num_relays);
    num_nodes += num_relays;
    int nodes_len = 0;

    if (num_nodes != 0) {
        nodes_len = pack_nodes(data + DHTPK_DATA_MIN_LENGTH, DHTPK_DATA_MAX_LENGTH - DHTPK_DATA_MIN_LENGTH, nodes,
                               num_nodes);

        if (nodes_len <= 0)
            return -1;
    }

    int num1 = -1, num2 = -1;

    if (onion_dht_both != 1)
        num1 = send_onion_data(data, DHTPK_DATA_MIN_LENGTH + nodes_len);

    if (onion_dht_both != 0)
        num2 = send_dht_dhtpk(data, DHTPK_DATA_MIN_LENGTH + nodes_len);

    if (num1 == -1)
        return num2;

    if (num2 == -1)
        return num1;

    return num1 + num2;
}

Onion_Friend::Onion_Friend(Onion_Client *client, const bitox::PublicKey &real_public_key) : client(client), real_public_key(real_public_key)
{
    client->friends[real_public_key] = this;
}

Onion_Friend::~Onion_Friend()
{
    client->friends.erase(real_public_key);

    //if (onion_c->friends_list[friend_num].know_dht_public_key)
    //    DHT_delfriend(onion_c->dht, onion_c->friends_list[friend_num].dht_public_key, 0);
}

/* Add a friend who we want to connect to.
 *
 * return -1 on failure.
 * return the friend number on success or if the friend was already added.
 */
std::shared_ptr<Onion_Friend> Onion_Client::onion_addfriend(const PublicKey &public_key)
{
    auto it = friends.find(public_key);
    if (it != friends.end())
    {
        return it->second->shared_from_this();
    }

    std::shared_ptr<Onion_Friend> result = std::make_shared<Onion_Friend>(this, public_key);

    crypto_box_keypair(result->temp_public_key.data.data(), result->temp_secret_key.data.data());
    return result;
}

/* Set the function for this friend that will be callbacked with object and number
 * when that friends gives us one of the TCP relays he is connected to.
 *
 * object and number will be passed as argument to this function.
 */
void Onion_Friend::recv_tcp_relay_handler(int (*tcp_relay_node_callback)(void *object,
        uint32_t number, IPPort ip_port, const PublicKey &public_key), void *object, uint32_t number)
{
    this->tcp_relay_node_callback = tcp_relay_node_callback;
    this->tcp_relay_node_callback_object = object;
    this->tcp_relay_node_callback_number = number;
}

/* Set the function for this friend that will be callbacked with object and number
 * when that friend gives us his DHT temporary public key.
 *
 * object and number will be passed as argument to this function.
 */
void Onion_Friend::onion_dht_pk_callback(void (*function)(void *data, int32_t number,
        const PublicKey &dht_public_key), void *object, uint32_t number)
{
    this->dht_pk_callback = function;
    this->dht_pk_callback_object = object;
    this->dht_pk_callback_number = number;
}

/* Set a friends DHT public key.
 *
 * return -1 on failure.
 * return 0 on success.
 */
bool Onion_Friend::onion_set_friend_DHT_pubkey(const PublicKey &dht_key)
{
    if (know_dht_public_key) {
        if (dht_key == dht_public_key) {
            return false;
        }

        know_dht_public_key = 0;
    }

    last_seen = unix_time();
    know_dht_public_key = 1;
    dht_public_key = dht_key;

    return true;
}

/* Get the ip of friend friendnum and put it in ip_port
 *
 *  return -1, -- if public_key does NOT refer to a friend
 *  return  0, -- if public_key refers to a friend and we failed to find the friend (yet)
 *  return  1, ip if public_key refers to a friend and we found him
 *
 */
int Onion_Friend::onion_getfriendip(IPPort *ip_port)
{
    return client->dht->getfriendip(dht_public_key, ip_port);
}


/* Set if friend is online or not.
 * NOTE: This function is there and should be used so that we don't send useless packets to the friend if he is online.
 *
 * is_online 1 means friend is online.
 * is_online 0 means friend is offline
 */
void Onion_Friend::onion_set_friend_online(uint8_t is_online)
{
    if (is_online == 0 && this->is_online == 1)
        last_seen = unix_time();

    this->is_online = is_online;

    /* This should prevent some clock related issues */
    if (!is_online) {
        last_noreplay = 0;
        run_count = 0;
    }
}

void Onion_Client::populate_path_nodes()
{
    NodeFormat nodes_list[MAX_FRIEND_CLIENTS];

    unsigned int num_nodes = dht->randfriends_nodes(nodes_list, MAX_FRIEND_CLIENTS);

    for (size_t i = 0; i < num_nodes; ++i) {
        onion_add_path_node(nodes_list[i].ip_port, nodes_list[i].public_key);
    }
}

void Onion_Client::populate_path_nodes_tcp()
{
    NodeFormat nodes_list[MAX_SENT_NODES];

    unsigned int num_nodes = c->copy_connected_tcp_relays(nodes_list, MAX_SENT_NODES);;

    for (size_t i = 0; i < num_nodes; ++i) {
        onion_add_bs_path_node(nodes_list[i].ip_port, nodes_list[i].public_key);
    }
}

#define ANNOUNCE_FRIEND (ONION_NODE_PING_INTERVAL * 6)
#define ANNOUNCE_FRIEND_BEGINNING 3
#define FRIEND_ONION_NODE_TIMEOUT (ONION_NODE_TIMEOUT * 6)

#define RUN_COUNT_FRIEND_ANNOUNCE_BEGINNING 17

void Onion_Friend::do_friend()
{
    unsigned int interval = ANNOUNCE_FRIEND;

    if (run_count < RUN_COUNT_FRIEND_ANNOUNCE_BEGINNING)
        interval = ANNOUNCE_FRIEND_BEGINNING;

    unsigned int count = 0;
    Onion_Node *list_nodes = clients_list;

    if (!is_online)
    {
        for (size_t i = 0; i < MAX_ONION_CLIENTS; ++i)
        {
            if (is_timeout(list_nodes[i].timestamp, FRIEND_ONION_NODE_TIMEOUT))
                continue;

            ++count;


            if (list_nodes[i].last_pinged == 0) {
                list_nodes[i].last_pinged = unix_time();
                continue;
            }

            if (is_timeout(list_nodes[i].last_pinged, interval)) {
                if (client->client_send_announce_request(this, list_nodes[i].ip_port, list_nodes[i].public_key, PublicKey(), ~0) == 0) {
                    list_nodes[i].last_pinged = unix_time();
                }
            }
        }

        if (count != MAX_ONION_CLIENTS) {
            unsigned int num_nodes = client->path_nodes.size();

            unsigned int n = num_nodes;

            if (num_nodes > (MAX_ONION_CLIENTS / 2))
                n = (MAX_ONION_CLIENTS / 2);

            if (num_nodes != 0) {
                unsigned int j;

                for (j = 0; j < n; ++j) {
                    unsigned int num = rand() % num_nodes;
                    client->client_send_announce_request(this, client->path_nodes[num].ip_port,
                                                         client->path_nodes[num].public_key, PublicKey(), ~0);
                }

                ++run_count;
            }
        } else {
            ++run_count;
        }

        /* send packets to friend telling them our DHT public key. */
        if (is_timeout(last_dht_pk_onion_sent, ONION_DHTPK_SEND_INTERVAL))
            if (send_dhtpk_announce(0) >= 1)
                last_dht_pk_onion_sent = unix_time();

        if (is_timeout(last_dht_pk_dht_sent, DHT_DHTPK_SEND_INTERVAL))
            if (send_dhtpk_announce(1) >= 1)
                last_dht_pk_dht_sent = unix_time();

    }
}


/* Function to call when onion data packet with contents beginning with byte is received. */
void Onion_Client::oniondata_registerhandler(uint8_t byte, oniondata_handler_callback cb, void *object)
{
    Onion_Data_Handlers[byte].function = cb;
    Onion_Data_Handlers[byte].object = object;
}

#define ANNOUNCE_INTERVAL_NOT_ANNOUNCED 3
#define ANNOUNCE_INTERVAL_ANNOUNCED ONION_NODE_PING_INTERVAL

void Onion_Client::do_announce()
{
    unsigned count = 0;
    Onion_Node *list_nodes = clients_announce_list;

    for (size_t i = 0; i < MAX_ONION_CLIENTS_ANNOUNCE; ++i) {
        if (is_timeout(list_nodes[i].timestamp, ONION_NODE_TIMEOUT))
            continue;

        ++count;

        /* Don't announce ourselves the first time this is run to new peers */
        if (list_nodes[i].last_pinged == 0) {
            list_nodes[i].last_pinged = 1;
            continue;
        }

        unsigned int interval = ANNOUNCE_INTERVAL_NOT_ANNOUNCED;

        if (list_nodes[i].is_stored && path_exists(&onion_paths_self, list_nodes[i].path_used)) {
            interval = ANNOUNCE_INTERVAL_ANNOUNCED;
        }

        if (is_timeout(list_nodes[i].last_pinged, interval)) {
            if (client_send_announce_request(nullptr, list_nodes[i].ip_port, list_nodes[i].public_key,
                                             list_nodes[i].ping_id, list_nodes[i].path_used) == 0) {
                list_nodes[i].last_pinged = unix_time();
            }
        }
    }

    if (count != MAX_ONION_CLIENTS_ANNOUNCE) {
        std::deque<bitox::dht::NodeFormat> *path_nodes;

        if (path_nodes->empty() || rand() % 2 == 0)
        {
            path_nodes = &this->path_nodes_bs;
        }
        else
        {
            path_nodes = &this->path_nodes;
        }

        if (count < (uint32_t)rand() % MAX_ONION_CLIENTS_ANNOUNCE) {
            if (!path_nodes->empty()) {
                for (size_t i = 0; i < (MAX_ONION_CLIENTS_ANNOUNCE / 2); ++i) {
                    unsigned int num = rand() % path_nodes->size();
                    client_send_announce_request(nullptr, (*path_nodes)[num].ip_port, (*path_nodes)[num].public_key, PublicKey(), ~0);
                }
            }
        }
    }
}

/*  return 0 if we are not connected to the network.
 *  return 1 if we are.
 */
int Onion_Client::onion_isconnected() const
{
    unsigned num = 0, announced = 0;

    if (is_timeout(last_packet_recv, ONION_OFFLINE_TIMEOUT))
        return 0;

    if (path_nodes.empty())
        return 0;

    for (size_t i = 0; i < MAX_ONION_CLIENTS_ANNOUNCE; ++i) {
        if (!is_timeout(clients_announce_list[i].timestamp, ONION_NODE_TIMEOUT)) {
            ++num;

            if (clients_announce_list[i].is_stored) {
                ++announced;
            }
        }
    }

    unsigned int pnodes = path_nodes.size();

    if (pnodes > MAX_ONION_CLIENTS_ANNOUNCE) {
        pnodes = MAX_ONION_CLIENTS_ANNOUNCE;
    }

    /* Consider ourselves online if we are announced to half or more nodes
      we are connected to */
    if (num && announced) {
        if ((num / 2) <= announced && (pnodes / 2) <= num)
            return 1;
    }

    return 0;
}

#define ONION_CONNECTION_SECONDS 3

/*  return 0 if we are not connected to the network.
 *  return 1 if we are connected with TCP only.
 *  return 2 if we are also connected with UDP.
 */
unsigned int Onion_Client::onion_connection_status() const
{
    if (onion_connected >= ONION_CONNECTION_SECONDS) {
        if (UDP_connected) {
            return 2;
        } else {
            return 1;
        }
    }

    return 0;
}

void Onion_Client::do_onion_client()
{
    if (last_run == unix_time())
        return;

    if (is_timeout(first_run, ONION_CONNECTION_SECONDS)) {
        populate_path_nodes();
        do_announce();
    }

    if (onion_isconnected()) {
        if (onion_connected < ONION_CONNECTION_SECONDS * 2) {
            ++onion_connected;
        }

    } else {
        populate_path_nodes_tcp();

        if (onion_connected != 0) {
            --onion_connected;
        }
    }

    bool UDP_connected = dht->non_lan_connected();

    if (is_timeout(first_run, ONION_CONNECTION_SECONDS * 2)) {
        c->tcp_c->set_tcp_onion_status(!UDP_connected);
    }

    UDP_connected = UDP_connected || c->tcp_c->get_random_tcp_onion_conn_number() == -1; /* Check if connected to any TCP relays. */

    if (onion_connection_status()) {
        for (auto &kv : friends)
        {
            kv.second->do_friend();
        }
    }

    if (last_run == 0) {
        first_run = unix_time();
    }

    last_run = unix_time();
}

Onion_Client::Onion_Client(Net_Crypto *c) :
    announce_ping_array(ANNOUNCE_ARRAY_SIZE, ANNOUNCE_TIMEOUT)
{
    assert(c && "Net_Crypto must not be null");

    this->dht = c->dht;
    this->net = c->dht->net;
    this->c = c;
    new_symmetric_key(this->secret_symmetric_key);
    crypto_box_keypair(this->temp_public_key.data.data(), this->temp_secret_key.data.data());
    networking_registerhandler(this->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_announce_response, this);
    networking_registerhandler(this->net, NET_PACKET_ONION_DATA_RESPONSE, &handle_data_response, this);
    oniondata_registerhandler(ONION_DATA_DHTPK, &handle_dhtpk_announce, this);
    this->dht->cryptopacket_registerhandler(CRYPTO_PACKET_DHTPK, &handle_dht_dhtpk, this);
    set_onion_packet_tcp_connection_callback(this->c->tcp_c, &handle_tcp_onion, this);
}

Onion_Client::~Onion_Client()
{
    networking_registerhandler(this->net, NET_PACKET_ANNOUNCE_RESPONSE, NULL, NULL);
    networking_registerhandler(this->net, NET_PACKET_ONION_DATA_RESPONSE, NULL, NULL);
    oniondata_registerhandler(ONION_DATA_DHTPK, NULL, NULL);
    this->dht->cryptopacket_registerhandler(CRYPTO_PACKET_DHTPK, NULL, NULL);
    set_onion_packet_tcp_connection_callback(this->c->tcp_c, NULL, NULL);
    sodium_memzero(this, sizeof(Onion_Client));
}

