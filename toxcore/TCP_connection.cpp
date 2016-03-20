/* TCP_connection.c
 *
 * Handles TCP relay connections between two Tox clients.
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
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

#include "TCP_connection.hpp"
#include "util.hpp"
#include "event_dispatcher.hpp"

/* Set the size of the array to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */

using namespace bitox;
using namespace bitox::network;
using namespace bitox::dht;

/* return 1 if the tcp_connections_number is not valid.
 * return 0 if the tcp_connections_number is valid.
 */
bool TCP_Connections::tcp_connections_number_not_valid(int tcp_connections_number)
{
    if ((unsigned int)tcp_connections_number >= this->tcp_connections.size())
        return 1;

    if (this->tcp_connections[tcp_connections_number].status == TCPConnectionStatus::TCP_CONN_NONE)
        return 1;

    return 0;
}

/* Create a new empty tcp connection.
 *
 * return -1 on failure.
 * return tcp_connections_number on success.
 */
int TCP_Connections::create_tcp_connection()
{
    for (size_t i = 0; i < this->tcp_connections.size(); ++i) {
        if (this->tcp_connections[i].status == TCPConnectionStatus::TCP_CONN_NONE)
            return i;
    }

    this->tcp_connections.emplace_back();
    return this->tcp_connections.size() - 1;
}

/* Wipe a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int TCP_Connections::wipe_tcp_connection(int tcp_connections_number)
{
    if (tcp_connections_number_not_valid(tcp_connections_number))
        return -1;

    memset(&(this->tcp_connections[tcp_connections_number]), 0 , sizeof(TCP_con));

    for (size_t i = this->tcp_connections.size(); i --> 0;) {
        if (this->tcp_connections[i - 1].status != TCPConnectionStatus::TCP_CONN_NONE)
            break;
        
        this->tcp_connections.pop_back();
    }

    return 0;
}

TCP_con *TCP_Connections::get_tcp_connection(int tcp_connections_number)
{
    if (tcp_connections_number_not_valid(tcp_connections_number))
        return 0;

    return &this->tcp_connections[tcp_connections_number];
}

/* Send a packet to the TCP connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int TCP_Connection_to::send_packet_tcp_connection(const uint8_t *packet, uint16_t length)
{
    //TODO: detect and kill bad relays.
    //TODO: thread safety?
    unsigned int i;
    int ret = -1;

    bool limit_reached = false;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        uint32_t tcp_con_num = connections[i].tcp_connection;
        TCPConnectionsStatus status = connections[i].status;
        uint8_t connection_id = connections[i].connection_id;

        if (tcp_con_num && status == TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_ONLINE) {
            tcp_con_num -= 1;
            TCP_con *tcp_con = tcp_connections->get_tcp_connection(tcp_con_num);

            if (!tcp_con) {
                continue;
            }

            ret = tcp_con->connection->send_data(connection_id, packet, length);

            if (ret == 0) {
                limit_reached = true;
            }

            if (ret == 1) {
                break;
            }
        }
    }

    if (ret == 1) {
        return 0;
    } else if (!limit_reached) {
        ret = 0;

        /* Send oob packets to all relays tied to the connection. */
        for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
            uint32_t tcp_con_num = connections[i].tcp_connection;
            TCPConnectionsStatus status = connections[i].status;

            if (tcp_con_num && status == TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_REGISTERED) {
                tcp_con_num -= 1;
                TCP_con *tcp_con = tcp_connections->get_tcp_connection(tcp_con_num);

                if (!tcp_con) {
                    continue;
                }

                if (tcp_con->connection->send_oob_packet(public_key, packet, length) == 1) {
                    ret += 1;
                }
            }
        }

        if (ret >= 1) {
            return 0;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO: This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int TCP_Connections::get_random_tcp_onion_conn_number()
{
    unsigned int i, r = rand();

    for (i = 0; i < tcp_connections.size(); ++i) {
        unsigned int index = ((i + r) % tcp_connections.size());

        if (tcp_connections[index].onion && tcp_connections[index].status == TCPConnectionStatus::TCP_CONN_CONNECTED) {
            return index;
        }
    }

    return -1;
}

/* Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::tcp_send_onion_request(unsigned int tcp_connections_number, const uint8_t *data,
                           uint16_t length)
{
    if (tcp_connections_number >= tcp_connections.size()) {
        return -1;
    }

    if (tcp_connections[tcp_connections_number].status == TCPConnectionStatus::TCP_CONN_CONNECTED) {
        int ret = tcp_connections[tcp_connections_number].connection->send_onion_request(data, length);

        if (ret == 1)
            return 0;
    }

    return -1;
}

/* Send an oob packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::tcp_send_oob_packet(unsigned int tcp_connections_number, const PublicKey &public_key,
                        const uint8_t *packet, uint16_t length)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status != TCPConnectionStatus::TCP_CONN_CONNECTED)
        return -1;

    int ret = tcp_con->connection->send_oob_packet(public_key, packet, length);

    if (ret == 1)
        return 0;

    return -1;
}

/* Set the callback for TCP data packets.
 */
void set_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_data_callback)(void *object, int id,
                                        const uint8_t *data, uint16_t length), void *object)
{
    tcp_c->tcp_data_callback = tcp_data_callback;
    tcp_c->tcp_data_callback_object = object;
}

/* Set the callback for TCP onion packets.
 */
void set_oob_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_oob_callback)(void *object,
        const PublicKey &public_key, unsigned int tcp_connections_number, const uint8_t *data, uint16_t length), void *object)
{
    tcp_c->tcp_oob_callback = tcp_oob_callback;
    tcp_c->tcp_oob_callback_object = object;
}

/* Find the TCP connection with public_key.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
TCP_Connection_to *TCP_Connections::find_tcp_connection_to(const bitox::PublicKey &public_key)
{
    auto it = connections.find(public_key);
    if (it == connections.end())
        return nullptr;
    
    return it->second;
}

/* Find the TCP connection to a relay with relay_pk.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
int TCP_Connections::find_tcp_connection_relay(const PublicKey &relay_pk)
{
    unsigned int i;

    for (i = 0; i < this->tcp_connections.size(); ++i) {
        TCP_con *tcp_con = get_tcp_connection(i);

        if (tcp_con) {
            if (tcp_con->status == TCPConnectionStatus::TCP_CONN_SLEEPING) {
                if (tcp_con->relay_pk == relay_pk) {
                    return i;
                }
            } else {
                if (tcp_con->connection->public_key == relay_pk) {
                    return i;
                }
            }
        }
    }

    return -1;
}

TCP_Connection_to::TCP_Connection_to(TCP_Connections *tcp_connections, const bitox::PublicKey &public_key) : tcp_connections(tcp_connections), public_key(public_key)
{
    tcp_connections->connections[public_key] = this;
    status = TCPConnectionStatus::TCP_CONN_VALID;
}

/* Create a new TCP connection to public_key.
 *
 * public_key must be the counterpart to the secret key that the other peer used with new_tcp_connections().
 *
 * id is the id in the callbacks for that connection.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
std::unique_ptr<TCP_Connection_to> TCP_Connections::new_tcp_connection_to(const bitox::PublicKey &public_key, int id)
{
    if (find_tcp_connection_to(public_key))
        return std::unique_ptr<TCP_Connection_to>();

    std::unique_ptr<TCP_Connection_to> result = std::unique_ptr<TCP_Connection_to>(new TCP_Connection_to(this, public_key));

    return result;
}

TCP_Connection_to::~TCP_Connection_to()
{
    for (size_t i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (connections[i].tcp_connection) {
            unsigned int tcp_connections_number = connections[i].tcp_connection - 1;
            TCP_con *tcp_con = tcp_connections->get_tcp_connection(tcp_connections_number);

            if (!tcp_con)
                continue;

            if (tcp_con->status == TCPConnectionStatus::TCP_CONN_CONNECTED) {
                tcp_con->connection->send_disconnect_request(connections[i].connection_id);
            }

            if (connections[i].status == TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_ONLINE) {
                --tcp_con->lock_count;

                if (status == TCPConnectionStatus::TCP_CONN_SLEEPING) {
                    --tcp_con->sleep_count;
                }
            }
        }
    }
    
    tcp_connections->connections.erase(public_key);
}

/* Set connection status.
 *
 * status of 1 means we are using the connection.
 * status of 0 means we are not using it.
 *
 * Unused tcp connections will be disconnected from but kept in case they are needed.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connection_to::set_tcp_connection_to_status(bool status)
{
    if (status) {
        /* Conection is unsleeping. */
        if (this->status != TCPConnectionStatus::TCP_CONN_SLEEPING)
            return -1;

        unsigned int i;

        for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
            if (connections[i].tcp_connection) {
                unsigned int tcp_connections_number = connections[i].tcp_connection - 1;
                TCP_con *tcp_con = tcp_connections->get_tcp_connection(tcp_connections_number);

                if (!tcp_con)
                    continue;

                if (tcp_con->status == TCPConnectionStatus::TCP_CONN_SLEEPING) {
                    tcp_con->unsleep = true;
                }
            }
        }

        this->status = TCPConnectionStatus::TCP_CONN_VALID;
        return 0;
    } else {
        /* Conection is going to sleep. */
        if (this->status != TCPConnectionStatus::TCP_CONN_VALID)
            return -1;

        unsigned int i;

        for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
            if (connections[i].tcp_connection) {
                unsigned int tcp_connections_number = connections[i].tcp_connection - 1;
                TCP_con *tcp_con = tcp_connections->get_tcp_connection(tcp_connections_number);

                if (!tcp_con)
                    continue;

                if (connections[i].status == TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_ONLINE) {
                    ++tcp_con->sleep_count;
                }
            }
        }

        this->status = TCPConnectionStatus::TCP_CONN_SLEEPING;
        return 0;
    }
}

bool TCP_Connection_to::tcp_connection_in_conn(unsigned int tcp_connections_number)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (connections[i].tcp_connection == (tcp_connections_number + 1)) {
            return 1;
        }
    }

    return 0;
}

/* return index on success.
 * return -1 on failure.
 */
int TCP_Connection_to::add_tcp_connection_to_conn(unsigned int tcp_connections_number)
{
    unsigned int i;

    if (tcp_connection_in_conn(tcp_connections_number))
        return -1;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (connections[i].tcp_connection == 0) {
            connections[i].tcp_connection = tcp_connections_number + 1;
            connections[i].status = TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_NONE;
            connections[i].connection_id = 0;
            return i;
        }
    }

    return -1;
}

/* return index on success.
 * return -1 on failure.
 */
int TCP_Connection_to::rm_tcp_connection_from_conn(unsigned int tcp_connections_number)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (connections[i].tcp_connection == (tcp_connections_number + 1)) {
            connections[i].tcp_connection = 0;
            connections[i].status = TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_NONE;
            connections[i].connection_id = 0;
            return i;
        }
    }

    return -1;
}

/* return number of online connections on success.
 * return -1 on failure.
 */
unsigned int TCP_Connection_to::online_tcp_connection_from_conn() const
{
    unsigned int i, count = 0;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (connections[i].tcp_connection) {
            if (connections[i].status == TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_ONLINE) {
                ++count;
            }
        }
    }

    return count;
}

/* return index on success.
 * return -1 on failure.
 */
int TCP_Connection_to::set_tcp_connection_status(unsigned int tcp_connections_number,
                                     TCPConnectionsStatus status, uint8_t connection_id)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (connections[i].tcp_connection == (tcp_connections_number + 1)) {

            if (connections[i].status == status) {
                return -1;
            }

            connections[i].status = status;
            connections[i].connection_id = connection_id;
            return i;
        }
    }

    return -1;
}

/* Kill a TCP relay connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::kill_tcp_relay_connection(int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    unsigned int i;

    for (auto &kv : connections) {
        TCP_Connection_to *con_to = kv.second;
        con_to->rm_tcp_connection_from_conn(tcp_connections_number);
    }

    if (tcp_con->onion) {
        --this->onion_num_conns;
    }

    delete tcp_con->connection;

    return wipe_tcp_connection(tcp_connections_number);
}

int TCP_Connections::reconnect_tcp_relay_connection(int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status == TCPConnectionStatus::TCP_CONN_SLEEPING)
        return -1;

    IPPort ip_port = tcp_con->connection->ip_port;
    PublicKey relay_pk = tcp_con->connection->public_key;
    delete tcp_con->connection;
    tcp_con->connection = new TCP_Client_Connection(ip_port, relay_pk, this->self_public_key, this->self_secret_key,
                          &this->proxy_info);

    if (!tcp_con->connection) {
        kill_tcp_relay_connection(tcp_connections_number);
        return -1;
    }

    unsigned int i;

    for (auto &kv : connections) {
        TCP_Connection_to *con_to = kv.second;
        con_to->set_tcp_connection_status(tcp_connections_number, TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_NONE, 0);
    }

    if (tcp_con->onion) {
        --this->onion_num_conns;
        tcp_con->onion = 0;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCPConnectionStatus::TCP_CONN_VALID;
    tcp_con->unsleep = 0;

    return 0;
}

int TCP_Connections::sleep_tcp_relay_connection(int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status != TCPConnectionStatus::TCP_CONN_CONNECTED)
        return -1;

    if (tcp_con->lock_count != tcp_con->sleep_count)
        return -1;

    tcp_con->ip_port = tcp_con->connection->ip_port;
    tcp_con->relay_pk = tcp_con->connection->public_key;

    delete tcp_con->connection;
    tcp_con->connection = NULL;

    unsigned int i;

    for (auto &kv : connections) {
        TCP_Connection_to *con_to = kv.second;
        con_to->set_tcp_connection_status(tcp_connections_number, TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_NONE, 0);
    }

    if (tcp_con->onion) {
        --this->onion_num_conns;
        tcp_con->onion = 0;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCPConnectionStatus::TCP_CONN_SLEEPING;
    tcp_con->unsleep = 0;

    return 0;
}

int TCP_Connections::unsleep_tcp_relay_connection(int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status != TCPConnectionStatus::TCP_CONN_SLEEPING)
        return -1;

    tcp_con->connection = new TCP_Client_Connection(tcp_con->ip_port, tcp_con->relay_pk, this->self_public_key,
                          this->self_secret_key, &this->proxy_info);

    if (!tcp_con->connection) {
        kill_tcp_relay_connection(tcp_connections_number);
        return -1;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCPConnectionStatus::TCP_CONN_VALID;
    tcp_con->unsleep = 0;
    return 0;
}

/* Send a TCP routing request.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::send_tcp_relay_routing_request(int tcp_connections_number, const bitox::PublicKey &public_key)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status == TCPConnectionStatus::TCP_CONN_SLEEPING)
        return -1;

    if (tcp_con->connection->send_routing_request(public_key) != 1)
        return -1;

    return 0;
}

int TCP_Connections::on_response(TCP_Client_Connection *connection, uint8_t connection_id, const bitox::PublicKey &public_key)
{
    unsigned int tcp_connections_number = connection->custom_uint;
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    TCP_Connection_to *con_to = find_tcp_connection_to(public_key);

    if (con_to == NULL)
        return -1;

    if (con_to->set_tcp_connection_status(tcp_connections_number, TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_REGISTERED, connection_id) == -1)
        return -1;

    tcp_con->connection->set_tcp_connection_public_key(connection_id, public_key);

    return 0;
}

int TCP_Connections::on_status(TCP_Client_Connection *connection, const bitox::PublicKey &tcp_connection_to_public_key, uint8_t connection_id, ClientToClientConnectionStatus status)
{
    unsigned int tcp_connections_number = connection->custom_uint;
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);
    TCP_Connection_to *con_to = find_tcp_connection_to(tcp_connection_to_public_key);

    if (!con_to || !tcp_con)
        return -1;

    if (status == ClientToClientConnectionStatus::OFFLINE) {
        if (con_to->set_tcp_connection_status(tcp_connections_number, TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_REGISTERED, connection_id) == -1)
            return -1;

        --tcp_con->lock_count;

        if (con_to->status == TCPConnectionStatus::TCP_CONN_SLEEPING) {
            --tcp_con->sleep_count;
        }
    } else if (status == ClientToClientConnectionStatus::ONLINE) {
        if (con_to->set_tcp_connection_status(tcp_connections_number, TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_ONLINE, connection_id) == -1)
            return -1;

        ++tcp_con->lock_count;

        if (con_to->status == TCPConnectionStatus::TCP_CONN_SLEEPING) {
            ++tcp_con->sleep_count;
        }
    }

    return 0;
}

int TCP_Connections::on_data (TCP_Client_Connection *connection, const bitox::PublicKey &tcp_connection_to_public_key, uint8_t connection_id, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    unsigned int tcp_connections_number = connection->custom_uint;
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    TCP_Connection_to *con_to = find_tcp_connection_to(tcp_connection_to_public_key);

    if (!con_to)
        return -1;

    if (this->tcp_data_callback)
        this->tcp_data_callback(this->tcp_data_callback_object, con_to->id, data, length);

    return 0;
}

int TCP_Connections::on_oob_data(TCP_Client_Connection *connection, const bitox::PublicKey &public_key, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    unsigned int tcp_connections_number = connection->custom_uint;
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    /* TODO: optimize */
    TCP_Connection_to *con_to = find_tcp_connection_to(public_key);

    if (con_to && con_to->tcp_connection_in_conn(tcp_connections_number)) {
        return this->on_data(connection, public_key, 0, data, length);
    } else {
        if (this->tcp_oob_callback)
            this->tcp_oob_callback(this->tcp_oob_callback_object, public_key, tcp_connections_number, data, length);
    }

    return 0;
}

int TCP_Connections::on_onion(TCP_Client_Connection *connection, const uint8_t *data, uint16_t length)
{
    if (event_dispatcher)
        event_dispatcher->on_tcp_onion(data, length);
        
    return 0;
}

/* Set callbacks for the TCP relay connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::tcp_relay_set_callbacks(int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    TCP_Client_Connection *con = tcp_con->connection;

    con->custom_uint = tcp_connections_number;
    con->event_listener = this;
    
    return 0;
}

int TCP_Connections::tcp_relay_on_online(int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    unsigned int i, sent = 0;

    for (auto &kv : connections) {
        TCP_Connection_to *con_to = kv.second;
        if (con_to->tcp_connection_in_conn(tcp_connections_number)) {
            if (send_tcp_relay_routing_request(tcp_connections_number, con_to->public_key) == 0) {
                ++sent;
            }
        }
    }

    tcp_relay_set_callbacks(tcp_connections_number);
    tcp_con->status = TCPConnectionStatus::TCP_CONN_CONNECTED;

    /* If this connection isn't used by any connection, we don't need to wait for them to come online. */
    if (sent) {
        tcp_con->connected_time = unix_time();
    } else {
        tcp_con->connected_time = 0;
    }

    if (this->onion_status && this->onion_num_conns < NUM_ONION_TCP_CONNECTIONS) {
        tcp_con->onion = 1;
        ++this->onion_num_conns;
    }

    return 0;
}

int TCP_Connections::add_tcp_relay_instance(IPPort ip_port, const PublicKey &relay_pk)
{
    if (ip_port.ip.family == Family::FAMILY_TCP_INET) {
        ip_port.ip.family = Family::FAMILY_AF_INET;
    } else if (ip_port.ip.family == Family::FAMILY_TCP_INET6) {
        ip_port.ip.family = Family::FAMILY_AF_INET6;
    }

    if (ip_port.ip.family != Family::FAMILY_AF_INET && ip_port.ip.family != Family::FAMILY_AF_INET6)
        return -1;

    int tcp_connections_number = create_tcp_connection();

    TCP_con *tcp_con = &this->tcp_connections[tcp_connections_number];


    tcp_con->connection = new TCP_Client_Connection(ip_port, relay_pk, this->self_public_key, this->self_secret_key,
                          &this->proxy_info);

    if (!tcp_con->connection)
        return -1;

    tcp_con->status = TCPConnectionStatus::TCP_CONN_VALID;

    return tcp_connections_number;
}

/* Add a TCP relay to the TCP_Connections instance.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::add_tcp_relay_global(IPPort ip_port, const PublicKey &relay_pk)
{
    int tcp_connections_number = find_tcp_connection_relay(relay_pk);

    if (tcp_connections_number != -1)
        return -1;

    if (add_tcp_relay_instance(ip_port, relay_pk) == -1)
        return -1;

    return 0;
}

/* Add a TCP relay tied to a connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connection_to::add_tcp_number_relay_connection(unsigned int tcp_connections_number)
{
    TCP_con *tcp_con = tcp_connections->get_tcp_connection(tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (status != TCPConnectionStatus::TCP_CONN_SLEEPING && tcp_con->status == TCPConnectionStatus::TCP_CONN_SLEEPING) {
        tcp_con->unsleep = 1;
    }

    if (add_tcp_connection_to_conn(tcp_connections_number) == -1)
        return -1;

    if (tcp_con->status == TCPConnectionStatus::TCP_CONN_CONNECTED) {
        if (tcp_connections->send_tcp_relay_routing_request(tcp_connections_number, public_key) == 0) {
            tcp_con->connected_time = unix_time();
        }
    }

    return 0;
}

/* Add a TCP relay tied to a connection.
 *
 * This should be called with the same relay by two peers who want to create a TCP connection with each other.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connection_to::add_tcp_relay_connection(IPPort ip_port, const PublicKey &relay_pk)
{
    int tcp_connections_number = tcp_connections->find_tcp_connection_relay(relay_pk);

    if (tcp_connections_number != -1) {
        return add_tcp_number_relay_connection(tcp_connections_number);
    } else {
        if (online_tcp_connection_from_conn() >= RECOMMENDED_FRIEND_TCP_CONNECTIONS) {
            return -1;
        }

        int tcp_connections_number = tcp_connections->add_tcp_relay_instance(ip_port, relay_pk);

        TCP_con *tcp_con = tcp_connections->get_tcp_connection(tcp_connections_number);

        if (!tcp_con)
            return -1;

        if (add_tcp_connection_to_conn(tcp_connections_number) == -1) {
            return -1;
        }

        return 0;
    }
}

/* Copy a maximum of max_num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int TCP_Connections::tcp_copy_connected_relays(NodeFormat *tcp_relays, uint16_t max_num)
{
    unsigned int i, copied = 0, r = rand();

    for (i = 0; (i < tcp_connections.size()) && (copied < max_num); ++i) {
        TCP_con *tcp_con = get_tcp_connection((i + r) % tcp_connections.size());

        if (!tcp_con) {
            continue;
        }

        if (tcp_con->status == TCPConnectionStatus::TCP_CONN_CONNECTED) {
            tcp_relays[copied].public_key = tcp_con->connection->public_key;
            tcp_relays[copied].ip_port = tcp_con->connection->ip_port;

            if (tcp_relays[copied].ip_port.ip.family == Family::FAMILY_AF_INET) {
                tcp_relays[copied].ip_port.ip.family = Family::FAMILY_TCP_INET;
            } else if (tcp_relays[copied].ip_port.ip.family == Family::FAMILY_AF_INET6) {
                tcp_relays[copied].ip_port.ip.family = Family::FAMILY_TCP_INET6;
            }

            ++copied;
        }
    }

    return copied;
}

/* Set if we want TCP_connection to allocate some connection for onion use.
 *
 * If status is 1, allocate some connections. if status is 0, don't.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::set_tcp_onion_status(bool status)
{
    if (onion_status == status)
        return -1;

    if (status) {
        unsigned int i;

        for (i = 0; i < tcp_connections.size(); ++i) {
            TCP_con *tcp_con = get_tcp_connection(i);

            if (tcp_con) {
                if (tcp_con->status == TCPConnectionStatus::TCP_CONN_CONNECTED && !tcp_con->onion) {
                    ++onion_num_conns;
                    tcp_con->onion = 1;
                }
            }

            if (onion_num_conns >= NUM_ONION_TCP_CONNECTIONS)
                break;
        }

        if (onion_num_conns < NUM_ONION_TCP_CONNECTIONS) {
            unsigned int wakeup = NUM_ONION_TCP_CONNECTIONS - onion_num_conns;

            for (i = 0; i < tcp_connections.size(); ++i) {
                TCP_con *tcp_con = get_tcp_connection(i);

                if (tcp_con) {
                    if (tcp_con->status == TCPConnectionStatus::TCP_CONN_SLEEPING) {
                        tcp_con->unsleep = 1;
                    }
                }

                if (!wakeup)
                    break;
            }
        }

        onion_status = 1;
    } else {
        unsigned int i;

        for (i = 0; i < tcp_connections.size(); ++i) {
            TCP_con *tcp_con = get_tcp_connection(i);

            if (tcp_con) {
                if (tcp_con->onion) {
                    --onion_num_conns;
                    tcp_con->onion = 0;
                }
            }
        }

        onion_status = 0;
    }

    return 0;
}

/* Returns a new TCP_Connections object associated with the secret_key.
 *
 * In order for others to connect to this instance new_tcp_connection_to() must be called with the
 * public_key associated with secret_key.
 */
TCP_Connections::TCP_Connections(const SecretKey &secret_key, TCP_Proxy_Info *proxy_info, EventDispatcher *event_dispatcher) : event_dispatcher(event_dispatcher)
{
    this->self_secret_key = secret_key;
    crypto_scalarmult_curve25519_base(this->self_public_key.data.data(), this->self_secret_key.data.data());
    this->proxy_info = *proxy_info;
}

void TCP_Connections::do_tcp_conns()
{
    unsigned int i;

    for (i = 0; i < this->tcp_connections.size(); ++i) {
        TCP_con *tcp_con = get_tcp_connection(i);

        if (tcp_con) {
            if (tcp_con->status != TCPConnectionStatus::TCP_CONN_SLEEPING) {
                tcp_con->connection->do_TCP_connection();

                /* callbacks can change TCP connection address. */
                tcp_con = get_tcp_connection(i);

                if (tcp_con->connection->status == ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED) {
                    if (tcp_con->status == TCPConnectionStatus::TCP_CONN_CONNECTED) {
                        reconnect_tcp_relay_connection(i);
                    } else {
                        kill_tcp_relay_connection(i);
                    }

                    continue;
                }

                if (tcp_con->status == TCPConnectionStatus::TCP_CONN_VALID && tcp_con->connection->status == ClientToServerConnectionStatus::TCP_CLIENT_CONFIRMED) {
                    tcp_relay_on_online(i);
                }

                if (tcp_con->status == TCPConnectionStatus::TCP_CONN_CONNECTED && !tcp_con->onion && tcp_con->lock_count
                        && tcp_con->lock_count == tcp_con->sleep_count
                        && is_timeout(tcp_con->connected_time, TCP_CONNECTION_ANNOUNCE_TIMEOUT)) {
                    sleep_tcp_relay_connection(i);
                }
            }

            if (tcp_con->status == TCPConnectionStatus::TCP_CONN_SLEEPING && tcp_con->unsleep) {
                unsleep_tcp_relay_connection(i);
            }
        }
    }
}

void TCP_Connections::kill_nonused_tcp()
{
    if (this->tcp_connections.size() == 0)
        return;

    unsigned int i, num_online = 0, num_kill = 0, to_kill[this->tcp_connections.size()];

    for (i = 0; i < this->tcp_connections.size(); ++i) {
        TCP_con *tcp_con = get_tcp_connection(i);

        if (tcp_con) {
            if (tcp_con->status == TCPConnectionStatus::TCP_CONN_CONNECTED) {
                if (!tcp_con->onion && !tcp_con->lock_count && is_timeout(tcp_con->connected_time, TCP_CONNECTION_ANNOUNCE_TIMEOUT)) {
                    to_kill[num_kill] = i;
                    ++num_kill;
                }

                ++num_online;
            }
        }
    }

    if (num_online <= RECOMMENDED_FRIEND_TCP_CONNECTIONS) {
        return;
    } else {
        unsigned int n = num_online - RECOMMENDED_FRIEND_TCP_CONNECTIONS;

        if (n < num_kill)
            num_kill = n;
    }

    for (i = 0; i < num_kill; ++i) {
        kill_tcp_relay_connection(to_kill[i]);
    }
}

void TCP_Connections::do_tcp_connections()
{
    do_tcp_conns();
    kill_nonused_tcp();
}

TCP_Connections::~TCP_Connections()
{
    for (size_t i = 0; i < tcp_connections.size(); ++i) {
        delete tcp_connections[i].connection;
    }
}


