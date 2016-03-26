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
#include "event_dispatcher.hpp"
#include "buffer.hpp"
#include "protocol_impl.hpp"

using namespace bitox;
using namespace bitox::network;
using namespace bitox::dht;

/* Add a TCP relay associated to the friend.
 */
bool Friend_Conn::friend_add_tcp_relay(IPPort ip_port, const PublicKey &public_key)
{
    if (!crypt_connection)
        return false;
        
    /* Local ip and same pk means that they are hosting a TCP relay. */
    if (Local_ip(ip_port.ip) && dht_temp_pk == public_key) {
        if (dht_ip_port.ip.family != Family::FAMILY_NULL) {
            ip_port.ip = dht_ip_port.ip;
        } else {
            hosting_tcp_relay = 0;
        }
    }

    uint16_t index = tcp_relay_counter % FRIEND_MAX_STORED_TCP_RELAYS;

    for (size_t i = 0; i < FRIEND_MAX_STORED_TCP_RELAYS; ++i) {
        if (tcp_relays[i].ip_port.ip.family != Family::FAMILY_NULL
                && tcp_relays[i].public_key == public_key) {
            memset(&tcp_relays[i], 0, sizeof(NodeFormat));
        }
    }

    tcp_relays[index].ip_port = ip_port;
    tcp_relays[index].public_key = public_key;
    ++tcp_relay_counter;

    return crypt_connection->add_tcp_relay_peer(ip_port, public_key) == 0;
}

/* Connect to number saved relays for friend. */
void Friend_Conn::connect_to_saved_tcp_relays(unsigned int number)
{
    if (!crypt_connection)
        return;
    
    for (size_t i = 0; (i < FRIEND_MAX_STORED_TCP_RELAYS) && (number != 0); ++i)
    {
        uint16_t index = (tcp_relay_counter - (i + 1)) % FRIEND_MAX_STORED_TCP_RELAYS;

        if (tcp_relays[index].ip_port.ip.family != Family::FAMILY_NULL)
        {
            if (crypt_connection->add_tcp_relay_peer(tcp_relays[index].ip_port, tcp_relays[index].public_key) == 0)
            {
                --number;
            }
        }
    }
}

unsigned int Friend_Conn::send_relays()
{
    if (!crypt_connection)
        return 0;
        
    NodeFormat nodes[MAX_SHARED_RELAYS];
    int n = connections->net_crypto->copy_connected_tcp_relays(nodes, MAX_SHARED_RELAYS);

    for (size_t i = 0; i < n; ++i)
    {
        /* Associated the relays being sent with this connection.
           On receiving the peer will do the same which will establish the connection. */
        friend_add_tcp_relay(nodes[i].ip_port, nodes[i].public_key);
    }

    OutputBuffer buffer;
    buffer.write_byte(PACKET_ID_SHARE_RELAYS);
    
    for (size_t i = 0; i < n; ++i)
    {
        if (!write_node_format(buffer, nodes[i]))
            return 0;
    }
    
    if (crypt_connection->write_cryptpacket(buffer.begin(), buffer.size(), 0) != -1)
    {
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

/* Callback for DHT ip_port changes. */
void Friend_Conn::on_ip_port(const bitox::network::IPPort &ip_port)
{
    if (!crypt_connection) {
        friend_new_connection();
    }

    if (crypt_connection)
    {
        crypt_connection->set_direct_ip_port(ip_port, 1);
    }
    dht_ip_port = ip_port;
    dht_ip_port_lastrecv = unix_time();

    if (hosting_tcp_relay) {
        friend_add_tcp_relay(ip_port, dht_temp_pk);
        hosting_tcp_relay = 0;
    }
}

void Friend_Conn::change_dht_pk(const PublicKey &dht_public_key)
{
    dht_pk_lastrecv = unix_time();
    dht_friend_link = connections->dht->addfriend(dht_public_key, this);
    dht_temp_pk = dht_public_key;
}

int Friend_Conn::on_status(uint8_t status)
{
    bool call_cb = 0;

    if (status) {  /* Went online. */
        call_cb = 1;
        this->status = FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTED;
        this->ping_lastrecv = unix_time();
        this->share_relays_lastsent = 0;
        this->onion_friend->onion_set_friend_online(status);
    } else {  /* Went offline. */
        if (this->status != FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTING) {
            call_cb = 1;
            this->dht_pk_lastrecv = unix_time();
            this->onion_friend->onion_set_friend_online(status);
        }

        this->status = FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTING;
        this->crypt_connection.reset();
        this->hosting_tcp_relay = 0;
    }

    if (call_cb) {
        if (event_listener)
            event_listener->on_status(status);
    }

    return 0;
}

void Friend_Conn::on_connection_killed()
{
    crypt_connection.reset();
}

/* Callback for dht public key changes. */
void Friend_Conn::on_dht_pk(const bitox::PublicKey &dht_public_key) 
{
    if (this->dht_temp_pk == dht_public_key)
        return;

    change_dht_pk(dht_public_key);

    /* if pk changed, create a new connection.*/
    if (crypt_connection) {
        crypt_connection.reset();
        on_status(0); /* Going offline. */
    }

    friend_new_connection();
    onion_friend->onion_set_friend_DHT_pubkey(dht_public_key);
}

int Friend_Conn::on_data(uint8_t *data, uint16_t length)
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

        for (size_t j = 0; j < n; j++) {
            friend_add_tcp_relay(nodes[j].ip_port, nodes[j].public_key);
        }

        return 0;
    }

    for (size_t i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i)
    {
        if (event_listener)
            event_listener->on_data(data, length);
        // TODO Strange handle_packet code in original source code here
    }

    return 0;
}

int Friend_Conn::on_lossy_data(uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    unsigned int i;

    for (i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
        if (event_listener)
            event_listener->on_lossy_data(data, length);

        // TODO Strange handle_lossy_packet code in original source code here
    }

    return 0;
}

int Friend_Connections::on_net_crypto_new_connection(const New_Connection &n_c)
{
    auto it = connections_map.find(n_c.public_key);
    Friend_Conn *friend_con = (it == connections_map.end() ? nullptr : it->second);

    if (friend_con) {

        if (friend_con->crypt_connection)
            return -1;

        friend_con->crypt_connection = net_crypto->accept_crypto_connection(n_c);

        if (!friend_con->crypt_connection) {
            return -1;
        }

        set_event_listener(net_crypto, friend_con->crypt_connection->id, friend_con);

        if (n_c.source.ip.family != Family::FAMILY_AF_INET && n_c.source.ip.family != Family::FAMILY_AF_INET6) {
            friend_con->crypt_connection->set_direct_ip_port(friend_con->dht_ip_port, 0);
        } else {
            friend_con->dht_ip_port = n_c.source;
            friend_con->dht_ip_port_lastrecv = unix_time();
        }

        if (friend_con->dht_temp_pk != n_c.dht_public_key) {
            friend_con->change_dht_pk(n_c.dht_public_key);
        }

        return 0;
    }

    return -1;
}

int Friend_Conn::friend_new_connection()
{
    if (crypt_connection) {
        return -1;
    }

    /* If dht_temp_pk does not contains a pk. */
    if (!dht_friend_link) {
        return -1;
    }

    crypt_connection = connections->net_crypto->new_crypto_connection(real_public_key, dht_temp_pk);

    if (!crypt_connection)
        return -1;

    set_event_listener(connections->net_crypto, crypt_connection->id, this);

    return 0;
}

int Friend_Conn::send_ping()
{
    if (!crypt_connection)
        return -1;
    
    uint8_t ping = PACKET_ID_ALIVE;
    
    int64_t ret = crypt_connection->write_cryptpacket(&ping, sizeof(ping), 0);

    if (ret != -1) {
        ping_lastsent = unix_time();
        return 0;
    }

    return -1;
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
    
    result->onion_friend = onion_c->onion_addfriend(real_public_key);

    if (!result->onion_friend)
        return std::shared_ptr<Friend_Conn>();

    result->crypt_connection.reset();
    result->status = FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTING;

    // recv_tcp_relay_handler(onion_c, onion_friendnum, &tcp_relay_node_callback, this, friendcon_id); // TODO
    // onion_dht_pk_callback(onion_c, onion_friendnum, &dht_pk_callback, this, friendcon_id); // TODO

    return result;
}

Friend_Conn::~Friend_Conn()
{
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
    fr_c->onion_c->oniondata_registerhandler(CRYPTO_PACKET_FRIEND_REQ, fr_request_callback, object);
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

    if (status == FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTED && crypt_connection) {
        packet[0] = PACKET_ID_FRIEND_REQUESTS;
        return crypt_connection->write_cryptpacket(packet, sizeof(packet), 0) != -1;
    } else {
        packet[0] = CRYPTO_PACKET_FRIEND_REQ;
        int num = onion_friend->send_onion_data(packet, sizeof(packet));

        if (num <= 0)
            return -1;

        return num;
    }
}

/* Create new friend_connections instance. */
Friend_Connections::Friend_Connections(Onion_Client *onion_c, bitox::EventDispatcher *event_dispatcher) : event_dispatcher(event_dispatcher)
{
    assert(onion_c && "Onion client must not be null");

    dht = onion_c->dht;
    net_crypto = onion_c->c;
    this->onion_c = onion_c;

    event_dispatcher->set_friend_connections(this);
}

/* Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds. */
void Friend_Connections::LANdiscovery()
{
    if (last_LANdiscovery + LAN_DISCOVERY_INTERVAL < unix_time()) {
        send_LANdiscovery(htons(TOX_PORT_DEFAULT), dht);
        last_LANdiscovery = unix_time();
    }
}

/* main friend_connections loop. */
void Friend_Connections::do_friend_connections()
{
    uint64_t temp_time = unix_time();

    for (auto &kv : connections_map) {
        Friend_Conn *friend_con = kv.second;

        if (friend_con) {
            if (friend_con->status == FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTING) {
                if (friend_con->dht_pk_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    friend_con->dht_friend_link.reset();
                }

                if (friend_con->dht_ip_port_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    friend_con->dht_ip_port.ip.family = Family::FAMILY_NULL;
                }

                if (friend_con->dht_friend_link) {
                    if (friend_con->friend_new_connection() == 0 && friend_con->crypt_connection) {
                        friend_con->crypt_connection->set_direct_ip_port(friend_con->dht_ip_port, 0);
                        friend_con->connect_to_saved_tcp_relays((MAX_FRIEND_TCP_CONNECTIONS / 2)); /* Only fill it half up. */
                    }
                }

            } else if (friend_con->status == FriendConnectionStatus::FRIENDCONN_STATUS_CONNECTED) {
                if (friend_con->ping_lastsent + FRIEND_PING_INTERVAL < temp_time) {
                    friend_con->send_ping();
                }

                if (friend_con->share_relays_lastsent + SHARE_RELAYS_INTERVAL < temp_time) {
                    friend_con->send_relays();
                }

                if (friend_con->ping_lastrecv + FRIEND_CONNECTION_TIMEOUT < temp_time) {
                    /* If we stopped receiving ping packets, kill it. */
                    friend_con->crypt_connection.reset();
                    friend_con->on_status(0); /* Going offline. */
                }
            }
        }
    }

    LANdiscovery();
}

/* Free everything related with friend_connections. */
Friend_Connections::~Friend_Connections()
{
    uint32_t i;

    /*for (i = 0; i < fr_c->num_cons; ++i) { // TODO
        kill_friend_connection(fr_c, i);
    }*/
    event_dispatcher->set_friend_connections(nullptr);
}
