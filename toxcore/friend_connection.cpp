/* friend_connection.c
 *
 * Connection to friends.
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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

#include "friend_connection.hpp"
#include "util.hpp"

using namespace bitox;
using namespace bitox::network;
using namespace bitox::dht;

/* Add a TCP relay associated to the friend.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Friend_Conn::friend_add_tcp_relay(IPPort ip_port, const PublicKey &public_key)
{
    /* Local ip and same pk means that they are hosting a TCP relay. */
    if (Local_ip(ip_port.ip) && dht_temp_pk == public_key) {
        if (dht_ip_port.ip.family != Family::FAMILY_NULL) {
            ip_port.ip = dht_ip_port.ip;
        } else {
            hosting_tcp_relay = 0;
        }
    }

    unsigned int i;

    uint16_t index = tcp_relay_counter % FRIEND_MAX_STORED_TCP_RELAYS;

    for (i = 0; i < FRIEND_MAX_STORED_TCP_RELAYS; ++i) {
        if (tcp_relays[i].ip_port.ip.family != Family::FAMILY_NULL
                && tcp_relays[i].public_key == public_key) {
            memset(&tcp_relays[i], 0, sizeof(NodeFormat));
        }
    }

    tcp_relays[index].ip_port = ip_port;
    tcp_relays[index].public_key = public_key;
    ++tcp_relay_counter;

    return connections->net_crypto->add_tcp_relay_peer(crypt_connection_id, ip_port, public_key);
}

/* Connect to number saved relays for friend. */
static void connect_to_saved_tcp_relays(Friend_Conn *friend_con, unsigned int number)
{
    if (!friend_con)
        return;

    unsigned int i;

    for (i = 0; (i < FRIEND_MAX_STORED_TCP_RELAYS) && (number != 0); ++i) {
        uint16_t index = (friend_con->tcp_relay_counter - (i + 1)) % FRIEND_MAX_STORED_TCP_RELAYS;

        if (friend_con->tcp_relays[index].ip_port.ip.family != Family::FAMILY_NULL) {
            if (friend_con->connections->net_crypto->add_tcp_relay_peer(friend_con->crypt_connection_id, friend_con->tcp_relays[index].ip_port,
                                   friend_con->tcp_relays[index].public_key) == 0) {
                --number;
            }
        }
    }
}

unsigned int Friend_Conn::send_relays()
{
    NodeFormat nodes[MAX_SHARED_RELAYS];
    uint8_t data[1024];
    int n, length;

    n = connections->net_crypto->copy_connected_tcp_relays(nodes, MAX_SHARED_RELAYS);

    int i;

    for (i = 0; i < n; ++i) {
        /* Associated the relays being sent with this connection.
           On receiving the peer will do the same which will establish the connection. */
        friend_add_tcp_relay(nodes[i].ip_port, nodes[i].public_key);
    }

    length = pack_nodes(data + 1, sizeof(data) - 1, nodes, n);

    if (length <= 0)
        return 0;

    data[0] = PACKET_ID_SHARE_RELAYS;
    ++length;

    if (connections->net_crypto->write_cryptpacket(crypt_connection_id, data, length, 0) != -1) {
        share_relays_lastsent = unix_time();
        return 1;
    }

    return 0;
}

/* callback for recv TCP relay nodes. */
/*static int tcp_relay_node_callback(void *object, uint32_t number, IPPort ip_port, const PublicKey &public_key) // TODO
{
    Friend_Connections *fr_c = (Friend_Connections *) object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con)
        return -1;

    if (friend_con->crypt_connection_id != -1) {
        return friend_con->friend_add_tcp_relay(ip_port, public_key);
    } else {
        return fr_c->net_crypto->add_tcp_relay(ip_port, public_key);
    }
}*/

static int friend_new_connection(Friend_Conn *friend_con);
/* Callback for DHT ip_port changes. */
/*static void dht_ip_callback(void *object, int32_t number, IPPort ip_port) // TODO
{
    Friend_Connections *fr_c = (Friend_Connections *) object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con)
        return;

    if (friend_con->crypt_connection_id == -1) {
        friend_new_connection(friend_con);
    }

    fr_c->net_crypto->set_direct_ip_port(friend_con->crypt_connection_id, ip_port, 1);
    friend_con->dht_ip_port = ip_port;
    friend_con->dht_ip_port_lastrecv = unix_time();

    if (friend_con->hosting_tcp_relay) {
        friend_con->friend_add_tcp_relay(ip_port, friend_con->dht_temp_pk);
        friend_con->hosting_tcp_relay = 0;
    }
}*/

static void change_dht_pk(Friend_Conn *friend_con, const PublicKey &dht_public_key)
{
    friend_con->dht_pk_lastrecv = unix_time();

    if (friend_con->dht_lock) {
        if (friend_con->connections->dht->delfriend(friend_con->dht_temp_pk, friend_con->dht_lock) != 0) {
            printf("a. Could not delete dht peer. Please report this.\n");
            return;
        }

        friend_con->dht_lock = 0;
    }

    //friend_con->connections->dht->addfriend(dht_public_key, dht_ip_callback, friend_con->connections, friendcon_id, &friend_con->dht_lock); // TODO
    friend_con->dht_temp_pk = dht_public_key;
}

int Friend_Conn::on_status(Crypto_Connection *connection, uint8_t status)
{
    bool call_cb = 0;

    if (status) {  /* Went online. */
        call_cb = 1;
        this->status = FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTED;
        this->ping_lastrecv = unix_time();
        this->share_relays_lastsent = 0;
        onion_set_friend_online(connections->onion_c, this->onion_friendnum, status);
    } else {  /* Went offline. */
        if (this->status != FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTING) {
            call_cb = 1;
            this->dht_pk_lastrecv = unix_time();
            onion_set_friend_online(connections->onion_c, this->onion_friendnum, status);
        }

        this->status = FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTING;
        this->crypt_connection_id = -1;
        this->hosting_tcp_relay = 0;
    }

    if (call_cb) {
        unsigned int i;

        for (i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
            if (this->callbacks[i].status_callback)
                this->callbacks[i].status_callback(this->callbacks[i].status_callback_object,
                        this->callbacks[i].status_callback_id, status);
        }
    }

    return 0;
}

/* Callback for dht public key changes. */
void Friend_Conn::on_dht_pk(Crypto_Connection *connection, const bitox::PublicKey &dht_public_key) 
{
    if (this->dht_temp_pk == dht_public_key)
        return;

    change_dht_pk(this, dht_public_key);

    /* if pk changed, create a new connection.*/
    if (crypt_connection_id != -1) {
        connections->net_crypto->crypto_kill(crypt_connection_id);
        crypt_connection_id = -1;
        on_status(nullptr, 0); /* Going offline. */
    }

    friend_new_connection(this);
    onion_set_friend_DHT_pubkey(connections->onion_c, onion_friendnum, dht_public_key);
}

int Friend_Conn::on_data(Crypto_Connection *connection, uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    if (data[0] == PACKET_ID_FRIEND_REQUESTS) {
        if (connections->fr_request_callback)
            connections->fr_request_callback(connections->fr_request_object, real_public_key, data, length);

        return 0;
    } else if (data[0] == PACKET_ID_ALIVE) {
        ping_lastrecv = unix_time();
        return 0;
    } else if (data[0] == PACKET_ID_SHARE_RELAYS) {
        NodeFormat nodes[MAX_SHARED_RELAYS];
        int n;

        if ((n = unpack_nodes(nodes, MAX_SHARED_RELAYS, NULL, data + 1, length - 1, 1)) == -1)
            return -1;

        int j;

        for (j = 0; j < n; j++) {
            friend_add_tcp_relay(nodes[j].ip_port, nodes[j].public_key);
        }

        return 0;
    }

    unsigned int i;

    for (i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i)
    {
        if (callbacks[i].data_callback)
            callbacks[i].data_callback(callbacks[i].data_callback_object,
                callbacks[i].data_callback_id, data, length);
        // TODO Strange handle_packet code in original source code here
    }

    return 0;
}

int Friend_Conn::on_lossy_data(Crypto_Connection *connection, uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    unsigned int i;

    for (i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
        if (callbacks[i].lossy_data_callback)
            callbacks[i].lossy_data_callback(callbacks[i].lossy_data_callback_object,
                    callbacks[i].lossy_data_callback_id, data, length);

        // TODO Strange handle_lossy_packet code in original source code here
    }

    return 0;
}

static int handle_new_connections(void *object, New_Connection *n_c)
{
    Friend_Connections *fr_c = (Friend_Connections *) object;
    auto it = fr_c->connections_map.find(n_c->public_key);
    Friend_Conn *friend_con = (it == fr_c->connections_map.end() ? nullptr : it->second);

    if (friend_con) {

        if (friend_con->crypt_connection_id != -1)
            return -1;

        int id = fr_c->net_crypto->accept_crypto_connection(n_c);

        if (id == -1) {
            return -1;
        }

        set_event_listener(fr_c->net_crypto, id, friend_con);
        friend_con->crypt_connection_id = id;

        if (n_c->source.ip.family != Family::FAMILY_AF_INET && n_c->source.ip.family != Family::FAMILY_AF_INET6) {
            fr_c->net_crypto->set_direct_ip_port(friend_con->crypt_connection_id, friend_con->dht_ip_port, 0);
        } else {
            friend_con->dht_ip_port = n_c->source;
            friend_con->dht_ip_port_lastrecv = unix_time();
        }

        if (friend_con->dht_temp_pk != n_c->dht_public_key) {
            change_dht_pk(friend_con, n_c->dht_public_key);
        }

        return 0;
    }

    return -1;
}

static int friend_new_connection(Friend_Conn *friend_con)
{
    if (!friend_con)
        return -1;

    if (friend_con->crypt_connection_id != -1) {
        return -1;
    }

    /* If dht_temp_pk does not contains a pk. */
    if (!friend_con->dht_lock) {
        return -1;
    }

    Friend_Connections *fr_c = friend_con->connections;
    int id = fr_c->net_crypto->new_crypto_connection(friend_con->real_public_key, friend_con->dht_temp_pk);

    if (id == -1)
        return -1;

    friend_con->crypt_connection_id = id;
    set_event_listener(fr_c->net_crypto, id, friend_con);

    return 0;
}

static int send_ping(Friend_Conn *friend_con)
{
    if (!friend_con)
        return -1;

    uint8_t ping = PACKET_ID_ALIVE;
    int64_t ret = friend_con->connections->net_crypto->write_cryptpacket(friend_con->crypt_connection_id, &ping, sizeof(ping), 0);

    if (ret != -1) {
        friend_con->ping_lastsent = unix_time();
        return 0;
    }

    return -1;
}

/* Set the callbacks for the friend connection.
 * index is the index (0 to (MAX_FRIEND_CONNECTION_CALLBACKS - 1)) we want the callback to set in the array.
 *
 * return 0 on success.
 * return -1 on failure
 */
int friend_connection_callbacks(Friend_Conn *friend_connection, unsigned int index,
                                int (*status_callback)(void *object, int id, uint8_t status), int (*data_callback)(void *object, int id, uint8_t *data,
                                        uint16_t length), int (*lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length), void *object,
                                int number)
{
    if (!friend_connection)
        return -1;

    if (index >= MAX_FRIEND_CONNECTION_CALLBACKS)
        return -1;

    friend_connection->callbacks[index].status_callback = status_callback;
    friend_connection->callbacks[index].data_callback = data_callback;
    friend_connection->callbacks[index].lossy_data_callback = lossy_data_callback;

    friend_connection->callbacks[index].status_callback_object =
        friend_connection->callbacks[index].data_callback_object =
            friend_connection->callbacks[index].lossy_data_callback_object = object;

    friend_connection->callbacks[index].status_callback_id =
        friend_connection->callbacks[index].data_callback_id =
            friend_connection->callbacks[index].lossy_data_callback_id = number;
    return 0;
}

Friend_Conn::Friend_Conn(Friend_Connections *connections, const PublicKey &real_public_key) :
    connections(connections),
    real_public_key(real_public_key)
{
    assert(connections && "Connections must not be null");
    
}

/* Create a new friend connection.
 * If one to that real public key already exists, increase lock count and return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
std::shared_ptr<Friend_Conn> Friend_Connections::new_friend_connection(const bitox::PublicKey &real_public_key)
{
    auto it = connections_map.find(real_public_key);
    if (it != connections_map.end())
        return it->second->shared_from_this();
    
    std::shared_ptr<Friend_Conn> result = std::make_shared<Friend_Conn>(this, real_public_key);
    
    int32_t onion_friendnum = onion_addfriend(onion_c, real_public_key);

    if (onion_friendnum == -1)
        return std::shared_ptr<Friend_Conn>();

    Friend_Conn *friend_con = result.get();
    friend_con->crypt_connection_id = -1;
    friend_con->status = FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTING;
    friend_con->onion_friendnum = onion_friendnum;

    // recv_tcp_relay_handler(onion_c, onion_friendnum, &tcp_relay_node_callback, this, friendcon_id); // TODO
    // onion_dht_pk_callback(onion_c, onion_friendnum, &dht_pk_callback, this, friendcon_id); // TODO

    return result;
}

Friend_Conn::~Friend_Conn()
{
    onion_delfriend(connections->onion_c, onion_friendnum);
    connections->net_crypto->crypto_kill(crypt_connection_id);

    if (dht_lock) {
        connections->dht->delfriend(dht_temp_pk, dht_lock);
    }

    connections->connections_map.erase(real_public_key);
}

/* Set friend request callback.
 *
 * This function will be called every time a friend request packet is received.
 */
void set_friend_request_callback(Friend_Connections *fr_c, int (*fr_request_callback)(void *, const PublicKey &,
                                 const uint8_t *, uint16_t), void *object)
{
    fr_c->fr_request_callback = fr_request_callback;
    fr_c->fr_request_object = object;
    oniondata_registerhandler(fr_c->onion_c, CRYPTO_PACKET_FRIEND_REQ, fr_request_callback, object);
}

/* Send a Friend request packet.
 *
 *  return -1 if failure.
 *  return  0 if it sent the friend request directly to the friend.
 *  return the number of peers it was routed through if it did not send it directly.
 */
int Friend_Conn::send_friend_request_packet(uint32_t nospam_num, const uint8_t *data, uint16_t length)
{
    if (1 + sizeof(nospam_num) + length > ONION_CLIENT_MAX_DATA_SIZE || length == 0)
        return -1;

    uint8_t packet[1 + sizeof(nospam_num) + length];
    memcpy(packet + 1, &nospam_num, sizeof(nospam_num));
    memcpy(packet + 1 + sizeof(nospam_num), data, length);

    if (status == FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTED) {
        packet[0] = PACKET_ID_FRIEND_REQUESTS;
        return connections->net_crypto->write_cryptpacket(crypt_connection_id, packet, sizeof(packet), 0) != -1;
    } else {
        packet[0] = CRYPTO_PACKET_FRIEND_REQ;
        int num = send_onion_data(connections->onion_c, onion_friendnum, packet, sizeof(packet));

        if (num <= 0)
            return -1;

        return num;
    }
}

/* Create new friend_connections instance. */
Friend_Connections *new_friend_connections(Onion_Client *onion_c)
{
    if (!onion_c)
        return NULL;

    Friend_Connections *temp = (Friend_Connections *) calloc(1, sizeof(Friend_Connections));

    if (temp == NULL)
        return NULL;

    temp->dht = onion_c->dht;
    temp->net_crypto = onion_c->c;
    temp->onion_c = onion_c;

    new_connection_handler(temp->net_crypto, &handle_new_connections, temp);
    LANdiscovery_init(temp->dht);

    return temp;
}

/* Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds. */
static void LANdiscovery(Friend_Connections *fr_c)
{
    if (fr_c->last_LANdiscovery + LAN_DISCOVERY_INTERVAL < unix_time()) {
        send_LANdiscovery(htons(TOX_PORT_DEFAULT), fr_c->dht);
        fr_c->last_LANdiscovery = unix_time();
    }
}

/* main friend_connections loop. */
void do_friend_connections(Friend_Connections *fr_c)
{
    uint64_t temp_time = unix_time();

    for (auto &kv : fr_c->connections_map) {
        Friend_Conn *friend_con = kv.second;

        if (friend_con) {
            if (friend_con->status == FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTING) {
                if (friend_con->dht_pk_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    if (friend_con->dht_lock) {
                        fr_c->dht->delfriend(friend_con->dht_temp_pk, friend_con->dht_lock);
                        friend_con->dht_lock = 0;
                    }
                }

                if (friend_con->dht_ip_port_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    friend_con->dht_ip_port.ip.family = Family::FAMILY_NULL;
                }

                if (friend_con->dht_lock) {
                    if (friend_new_connection(friend_con) == 0) {
                        fr_c->net_crypto->set_direct_ip_port(friend_con->crypt_connection_id, friend_con->dht_ip_port, 0);
                        connect_to_saved_tcp_relays(friend_con, (MAX_FRIEND_TCP_CONNECTIONS / 2)); /* Only fill it half up. */
                    }
                }

            } else if (friend_con->status == FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTED) {
                if (friend_con->ping_lastsent + FRIEND_PING_INTERVAL < temp_time) {
                    send_ping(friend_con);
                }

                if (friend_con->share_relays_lastsent + SHARE_RELAYS_INTERVAL < temp_time) {
                    friend_con->send_relays();
                }

                if (friend_con->ping_lastrecv + FRIEND_CONNECTION_TIMEOUT < temp_time) {
                    /* If we stopped receiving ping packets, kill it. */
                    fr_c->net_crypto->crypto_kill(friend_con->crypt_connection_id);
                    friend_con->crypt_connection_id = -1;
                    friend_con->on_status(nullptr, 0); /* Going offline. */
                }
            }
        }
    }

    LANdiscovery(fr_c);
}

/* Free everything related with friend_connections. */
void kill_friend_connections(Friend_Connections *fr_c)
{
    if (!fr_c)
        return;

    uint32_t i;

    /*for (i = 0; i < fr_c->num_cons; ++i) { // TODO
        kill_friend_connection(fr_c, i);
    }*/

    LANdiscovery_kill(fr_c->dht);
    free(fr_c);
}
