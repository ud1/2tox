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

/* Set the size of the array to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */

using namespace bitox;
using namespace bitox::network;
using namespace bitox::dht;

template <typename T>
bool realloc_tox_array(T *&array, size_t num)
{
	if (num)
	{
		T * result = (T *) realloc(array, num * sizeof(T));
		if (result)
		{
			array = result;
			return true;
		}
		return false;
	}
	
	free(array);
	return true;
}

/* return 1 if the connections_number is not valid.
 * return 0 if the connections_number is valid.
 */
static bool connections_number_not_valid(const TCP_Connections *tcp_c, int connections_number)
{
    if ((unsigned int)connections_number >= tcp_c->connections.size())
        return 1;

    if (tcp_c->connections[connections_number].status == TCP_CONN_NONE)
        return 1;

    return 0;
}

/* return 1 if the tcp_connections_number is not valid.
 * return 0 if the tcp_connections_number is valid.
 */
static bool tcp_connections_number_not_valid(const TCP_Connections *tcp_c, int tcp_connections_number)
{
    if ((unsigned int)tcp_connections_number >= tcp_c->tcp_connections.size())
        return 1;

    if (tcp_c->tcp_connections[tcp_connections_number].status == TCP_CONN_NONE)
        return 1;

    return 0;
}

/* Create a new empty connection.
 *
 * return -1 on failure.
 * return connections_number on success.
 */
static int create_connection(TCP_Connections *tcp_c)
{
    for (size_t i = 0; i < tcp_c->connections.size(); ++i) {
        if (tcp_c->connections[i].status == TCP_CONN_NONE)
            return i;
    }

    tcp_c->connections.emplace_back();
    return tcp_c->connections.size() - 1;
}

/* Create a new empty tcp connection.
 *
 * return -1 on failure.
 * return tcp_connections_number on success.
 */
static int create_tcp_connection(TCP_Connections *tcp_c)
{
    uint32_t i;

    for (i = 0; i < tcp_c->tcp_connections.size(); ++i) {
        if (tcp_c->tcp_connections[i].status == TCP_CONN_NONE)
            return i;
    }

    tcp_c->tcp_connections.emplace_back();
    return tcp_c->tcp_connections.size() - 1;
}

/* Wipe a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_connection(TCP_Connections *tcp_c, int connections_number)
{
    if (connections_number_not_valid(tcp_c, connections_number))
        return -1;

    memset(&(tcp_c->connections[connections_number]), 0 , sizeof(TCP_Connection_to));

    for (size_t i = tcp_c->connections.size(); i --> 0;) {
        if (tcp_c->connections[i].status != TCP_CONN_NONE)
            break;
        
        tcp_c->connections.pop_back();
    }

    return 0;
}

/* Wipe a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_tcp_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    if (tcp_connections_number_not_valid(tcp_c, tcp_connections_number))
        return -1;

    memset(&(tcp_c->tcp_connections[tcp_connections_number]), 0 , sizeof(TCP_con));

    for (size_t i = tcp_c->tcp_connections.size(); i --> 0;) {
        if (tcp_c->tcp_connections[i - 1].status != TCP_CONN_NONE)
            break;
        
        tcp_c->tcp_connections.pop_back();
    }

    return 0;
}

static TCP_Connection_to *get_connection(TCP_Connections *tcp_c, int connections_number)
{
    if (connections_number_not_valid(tcp_c, connections_number))
        return 0;

    return &tcp_c->connections[connections_number];
}

static TCP_con *get_tcp_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    if (tcp_connections_number_not_valid(tcp_c, tcp_connections_number))
        return 0;

    return &tcp_c->tcp_connections[tcp_connections_number];
}

/* Send a packet to the TCP connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int TCP_Connections::send_packet_tcp_connection(int connections_number, const uint8_t *packet, uint16_t length)
{
    const TCP_Connection_to *con_to = get_connection(this, connections_number);

    if (!con_to) {
        return -1;
    }

    //TODO: detect and kill bad relays.
    //TODO: thread safety?
    unsigned int i;
    int ret = -1;

    bool limit_reached = false;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        uint32_t tcp_con_num = con_to->connections[i].tcp_connection;
        uint8_t status = con_to->connections[i].status;
        uint8_t connection_id = con_to->connections[i].connection_id;

        if (tcp_con_num && status == TCP_CONNECTIONS_STATUS_ONLINE) {
            tcp_con_num -= 1;
            TCP_con *tcp_con = get_tcp_connection(this, tcp_con_num);

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
            uint32_t tcp_con_num = con_to->connections[i].tcp_connection;
            uint8_t status = con_to->connections[i].status;

            if (tcp_con_num && status == TCP_CONNECTIONS_STATUS_REGISTERED) {
                tcp_con_num -= 1;
                TCP_con *tcp_con = get_tcp_connection(this, tcp_con_num);

                if (!tcp_con) {
                    continue;
                }

                if (tcp_con->connection->send_oob_packet(con_to->public_key, packet, length) == 1) {
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

        if (tcp_connections[index].onion && tcp_connections[index].status == TCP_CONN_CONNECTED) {
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

    if (tcp_connections[tcp_connections_number].status == TCP_CONN_CONNECTED) {
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
    TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status != TCP_CONN_CONNECTED)
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

/* Set the callback for TCP oob data packets.
 */
void set_onion_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_onion_callback)(void *object,
        const uint8_t *data, uint16_t length), void *object)
{
    tcp_c->tcp_onion_callback = tcp_onion_callback;
    tcp_c->tcp_onion_callback_object = object;
}


/* Find the TCP connection with public_key.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
static int find_tcp_connection_to(TCP_Connections *tcp_c, const bitox::PublicKey &public_key)
{
    unsigned int i;

    for (i = 0; i < tcp_c->connections.size(); ++i) {
        const TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            if (con_to->public_key == public_key) {
                return i;
            }
        }
    }

    return -1;
}

/* Find the TCP connection to a relay with relay_pk.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
static int find_tcp_connection_relay(TCP_Connections *tcp_c, const PublicKey &relay_pk)
{
    unsigned int i;

    for (i = 0; i < tcp_c->tcp_connections.size(); ++i) {
        TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con) {
            if (tcp_con->status == TCP_CONN_SLEEPING) {
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

/* Create a new TCP connection to public_key.
 *
 * public_key must be the counterpart to the secret key that the other peer used with new_tcp_connections().
 *
 * id is the id in the callbacks for that connection.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
int TCP_Connections::new_tcp_connection_to(const bitox::PublicKey &public_key, int id)
{
    if (find_tcp_connection_to(this, public_key) != -1)
        return -1;

    int connections_number = create_connection(this);

    if (connections_number == -1)
        return -1;

    TCP_Connection_to *con_to = &connections[connections_number];

    con_to->status = TCP_CONN_VALID;
    con_to->public_key = public_key;
    con_to->id = id;

    return connections_number;
}

/* return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::kill_tcp_connection_to(int connections_number)
{
    const TCP_Connection_to *con_to = get_connection(this, connections_number);

    if (!con_to)
        return -1;

    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection) {
            unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
            TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

            if (!tcp_con)
                continue;

            if (tcp_con->status == TCP_CONN_CONNECTED) {
                tcp_con->connection->send_disconnect_request(con_to->connections[i].connection_id);
            }

            if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
                --tcp_con->lock_count;

                if (con_to->status == TCP_CONN_SLEEPING) {
                    --tcp_con->sleep_count;
                }
            }
        }
    }

    return wipe_connection(this, connections_number);
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
int TCP_Connections::set_tcp_connection_to_status(int connections_number, bool status)
{
    TCP_Connection_to *con_to = get_connection(this, connections_number);

    if (!con_to)
        return -1;

    if (status) {
        /* Conection is unsleeping. */
        if (con_to->status != TCP_CONN_SLEEPING)
            return -1;

        unsigned int i;

        for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
            if (con_to->connections[i].tcp_connection) {
                unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
                TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

                if (!tcp_con)
                    continue;

                if (tcp_con->status == TCP_CONN_SLEEPING) {
                    tcp_con->unsleep = 1;
                }
            }
        }

        con_to->status = TCP_CONN_VALID;
        return 0;
    } else {
        /* Conection is going to sleep. */
        if (con_to->status != TCP_CONN_VALID)
            return -1;

        unsigned int i;

        for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
            if (con_to->connections[i].tcp_connection) {
                unsigned int tcp_connections_number = con_to->connections[i].tcp_connection - 1;
                TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

                if (!tcp_con)
                    continue;

                if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
                    ++tcp_con->sleep_count;
                }
            }
        }

        con_to->status = TCP_CONN_SLEEPING;
        return 0;
    }
}

static bool tcp_connection_in_conn(TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {
            return 1;
        }
    }

    return 0;
}

/* return index on success.
 * return -1 on failure.
 */
static int add_tcp_connection_to_conn(TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    unsigned int i;

    if (tcp_connection_in_conn(con_to, tcp_connections_number))
        return -1;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == 0) {
            con_to->connections[i].tcp_connection = tcp_connections_number + 1;
            con_to->connections[i].status = TCP_CONNECTIONS_STATUS_NONE;
            con_to->connections[i].connection_id = 0;
            return i;
        }
    }

    return -1;
}

/* return index on success.
 * return -1 on failure.
 */
static int rm_tcp_connection_from_conn(TCP_Connection_to *con_to, unsigned int tcp_connections_number)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {
            con_to->connections[i].tcp_connection = 0;
            con_to->connections[i].status = TCP_CONNECTIONS_STATUS_NONE;
            con_to->connections[i].connection_id = 0;
            return i;
        }
    }

    return -1;
}

/* return number of online connections on success.
 * return -1 on failure.
 */
static unsigned int online_tcp_connection_from_conn(TCP_Connection_to *con_to)
{
    unsigned int i, count = 0;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection) {
            if (con_to->connections[i].status == TCP_CONNECTIONS_STATUS_ONLINE) {
                ++count;
            }
        }
    }

    return count;
}

/* return index on success.
 * return -1 on failure.
 */
static int set_tcp_connection_status(TCP_Connection_to *con_to, unsigned int tcp_connections_number,
                                     unsigned int status, uint8_t connection_id)
{
    unsigned int i;

    for (i = 0; i < MAX_FRIEND_TCP_CONNECTIONS; ++i) {
        if (con_to->connections[i].tcp_connection == (tcp_connections_number + 1)) {

            if (con_to->connections[i].status == status) {
                return -1;
            }

            con_to->connections[i].status = status;
            con_to->connections[i].connection_id = connection_id;
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
static int kill_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con)
        return -1;

    unsigned int i;

    for (i = 0; i < tcp_c->connections.size(); ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            rm_tcp_connection_from_conn(con_to, tcp_connections_number);
        }
    }

    if (tcp_con->onion) {
        --tcp_c->onion_num_conns;
    }

    delete tcp_con->connection;

    return wipe_tcp_connection(tcp_c, tcp_connections_number);
}

static int reconnect_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status == TCP_CONN_SLEEPING)
        return -1;

    IPPort ip_port = tcp_con->connection->ip_port;
    PublicKey relay_pk = tcp_con->connection->public_key;
    delete tcp_con->connection;
    tcp_con->connection = new TCP_Client_Connection(ip_port, relay_pk, tcp_c->self_public_key, tcp_c->self_secret_key,
                          &tcp_c->proxy_info);

    if (!tcp_con->connection) {
        kill_tcp_relay_connection(tcp_c, tcp_connections_number);
        return -1;
    }

    unsigned int i;

    for (i = 0; i < tcp_c->connections.size(); ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_NONE, 0);
        }
    }

    if (tcp_con->onion) {
        --tcp_c->onion_num_conns;
        tcp_con->onion = 0;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCP_CONN_VALID;
    tcp_con->unsleep = 0;

    return 0;
}

static int sleep_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status != TCP_CONN_CONNECTED)
        return -1;

    if (tcp_con->lock_count != tcp_con->sleep_count)
        return -1;

    tcp_con->ip_port = tcp_con->connection->ip_port;
    tcp_con->relay_pk = tcp_con->connection->public_key;

    delete tcp_con->connection;
    tcp_con->connection = NULL;

    unsigned int i;

    for (i = 0; i < tcp_c->connections.size(); ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_NONE, 0);
        }
    }

    if (tcp_con->onion) {
        --tcp_c->onion_num_conns;
        tcp_con->onion = 0;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCP_CONN_SLEEPING;
    tcp_con->unsleep = 0;

    return 0;
}

static int unsleep_tcp_relay_connection(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status != TCP_CONN_SLEEPING)
        return -1;

    tcp_con->connection = new TCP_Client_Connection(tcp_con->ip_port, tcp_con->relay_pk, tcp_c->self_public_key,
                          tcp_c->self_secret_key, &tcp_c->proxy_info);

    if (!tcp_con->connection) {
        kill_tcp_relay_connection(tcp_c, tcp_connections_number);
        return -1;
    }

    tcp_con->lock_count = 0;
    tcp_con->sleep_count = 0;
    tcp_con->connected_time = 0;
    tcp_con->status = TCP_CONN_VALID;
    tcp_con->unsleep = 0;
    return 0;
}

/* Send a TCP routing request.
 *
 * return 0 on success.
 * return -1 on failure.
 */
static int send_tcp_relay_routing_request(TCP_Connections *tcp_c, int tcp_connections_number, bitox::PublicKey &public_key)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (tcp_con->status == TCP_CONN_SLEEPING)
        return -1;

    if (tcp_con->connection->send_routing_request(public_key) != 1)
        return -1;

    return 0;
}

int TCP_Connections::on_response(TCP_Client_Connection *connection, uint8_t connection_id, const bitox::PublicKey &public_key)
{
    unsigned int tcp_connections_number = connection->custom_uint;
    TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

    if (!tcp_con)
        return -1;

    int connections_number = find_tcp_connection_to(this, public_key);

    if (connections_number == -1)
        return -1;

    TCP_Connection_to *con_to = get_connection(this, connections_number);

    if (con_to == NULL)
        return -1;

    if (set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_REGISTERED, connection_id) == -1)
        return -1;

    tcp_con->connection->set_tcp_connection_number(connection_id, connections_number);

    return 0;
}

int TCP_Connections::on_status(TCP_Client_Connection *connection, uint32_t number, uint8_t connection_id, ClientToClientConnectionStatus status)
{
    unsigned int tcp_connections_number = connection->custom_uint;
    TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);
    TCP_Connection_to *con_to = get_connection(this, number);

    if (!con_to || !tcp_con)
        return -1;

    if (status == ClientToClientConnectionStatus::OFFLINE) {
        if (set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_REGISTERED, connection_id) == -1)
            return -1;

        --tcp_con->lock_count;

        if (con_to->status == TCP_CONN_SLEEPING) {
            --tcp_con->sleep_count;
        }
    } else if (status == ClientToClientConnectionStatus::ONLINE) {
        if (set_tcp_connection_status(con_to, tcp_connections_number, TCP_CONNECTIONS_STATUS_ONLINE, connection_id) == -1)
            return -1;

        ++tcp_con->lock_count;

        if (con_to->status == TCP_CONN_SLEEPING) {
            ++tcp_con->sleep_count;
        }
    }

    return 0;
}

int TCP_Connections::on_data (TCP_Client_Connection *connection, uint32_t number, uint8_t connection_id, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    unsigned int tcp_connections_number = connection->custom_uint;
    TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

    if (!tcp_con)
        return -1;

    TCP_Connection_to *con_to = get_connection(this, number);

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
    TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

    if (!tcp_con)
        return -1;

    /* TODO: optimize */
    int connections_number = find_tcp_connection_to(this, public_key);

    TCP_Connection_to *con_to = get_connection(this, connections_number);

    if (con_to && tcp_connection_in_conn(con_to, tcp_connections_number)) {
        return this->on_data(connection, connections_number, 0, data, length);
    } else {
        if (this->tcp_oob_callback)
            this->tcp_oob_callback(this->tcp_oob_callback_object, public_key, tcp_connections_number, data, length);
    }

    return 0;
}

int TCP_Connections::on_onion(TCP_Client_Connection *connection, const uint8_t *data, uint16_t length)
{
    if (tcp_onion_callback)
        tcp_onion_callback(tcp_onion_callback_object, data, length);

    return 0;
}

/* Set callbacks for the TCP relay connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
static int tcp_relay_set_callbacks(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con)
        return -1;

    TCP_Client_Connection *con = tcp_con->connection;

    con->custom_uint = tcp_connections_number;
    con->event_listener = tcp_c;
    
    return 0;
}

static int tcp_relay_on_online(TCP_Connections *tcp_c, int tcp_connections_number)
{
    TCP_con *tcp_con = get_tcp_connection(tcp_c, tcp_connections_number);

    if (!tcp_con)
        return -1;

    unsigned int i, sent = 0;

    for (i = 0; i < tcp_c->connections.size(); ++i) {
        TCP_Connection_to *con_to = get_connection(tcp_c, i);

        if (con_to) {
            if (tcp_connection_in_conn(con_to, tcp_connections_number)) {
                if (send_tcp_relay_routing_request(tcp_c, tcp_connections_number, con_to->public_key) == 0) {
                    ++sent;
                }
            }
        }
    }

    tcp_relay_set_callbacks(tcp_c, tcp_connections_number);
    tcp_con->status = TCP_CONN_CONNECTED;

    /* If this connection isn't used by any connection, we don't need to wait for them to come online. */
    if (sent) {
        tcp_con->connected_time = unix_time();
    } else {
        tcp_con->connected_time = 0;
    }

    if (tcp_c->onion_status && tcp_c->onion_num_conns < NUM_ONION_TCP_CONNECTIONS) {
        tcp_con->onion = 1;
        ++tcp_c->onion_num_conns;
    }

    return 0;
}

static int add_tcp_relay_instance(TCP_Connections *tcp_c, IPPort ip_port, const PublicKey &relay_pk)
{
    if (ip_port.ip.family == Family::FAMILY_TCP_INET) {
        ip_port.ip.family = Family::FAMILY_AF_INET;
    } else if (ip_port.ip.family == Family::FAMILY_TCP_INET6) {
        ip_port.ip.family = Family::FAMILY_AF_INET6;
    }

    if (ip_port.ip.family != Family::FAMILY_AF_INET && ip_port.ip.family != Family::FAMILY_AF_INET6)
        return -1;

    int tcp_connections_number = create_tcp_connection(tcp_c);

    if (tcp_connections_number == -1)
        return -1;

    TCP_con *tcp_con = &tcp_c->tcp_connections[tcp_connections_number];


    tcp_con->connection = new TCP_Client_Connection(ip_port, relay_pk, tcp_c->self_public_key, tcp_c->self_secret_key,
                          &tcp_c->proxy_info);

    if (!tcp_con->connection)
        return -1;

    tcp_con->status = TCP_CONN_VALID;

    return tcp_connections_number;
}

/* Add a TCP relay to the TCP_Connections instance.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::add_tcp_relay_global(IPPort ip_port, const PublicKey &relay_pk)
{
    int tcp_connections_number = find_tcp_connection_relay(this, relay_pk);

    if (tcp_connections_number != -1)
        return -1;

    if (add_tcp_relay_instance(this, ip_port, relay_pk) == -1)
        return -1;

    return 0;
}

/* Add a TCP relay tied to a connection.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Connections::add_tcp_number_relay_connection(int connections_number, unsigned int tcp_connections_number)
{
    TCP_Connection_to *con_to = get_connection(this, connections_number);

    if (!con_to)
        return -1;

    TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

    if (!tcp_con)
        return -1;

    if (con_to->status != TCP_CONN_SLEEPING && tcp_con->status == TCP_CONN_SLEEPING) {
        tcp_con->unsleep = 1;
    }

    if (add_tcp_connection_to_conn(con_to, tcp_connections_number) == -1)
        return -1;

    if (tcp_con->status == TCP_CONN_CONNECTED) {
        if (send_tcp_relay_routing_request(this, tcp_connections_number, con_to->public_key) == 0) {
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
int TCP_Connections::add_tcp_relay_connection(int connections_number, IPPort ip_port, const PublicKey &relay_pk)
{
    TCP_Connection_to *con_to = get_connection(this, connections_number);

    if (!con_to)
        return -1;

    int tcp_connections_number = find_tcp_connection_relay(this, relay_pk);

    if (tcp_connections_number != -1) {
        return add_tcp_number_relay_connection(connections_number, tcp_connections_number);
    } else {
        if (online_tcp_connection_from_conn(con_to) >= RECOMMENDED_FRIEND_TCP_CONNECTIONS) {
            return -1;
        }

        int tcp_connections_number = add_tcp_relay_instance(this, ip_port, relay_pk);

        TCP_con *tcp_con = get_tcp_connection(this, tcp_connections_number);

        if (!tcp_con)
            return -1;

        if (add_tcp_connection_to_conn(con_to, tcp_connections_number) == -1) {
            return -1;
        }

        return 0;
    }
}

/* return number of online tcp relays tied to the connection on success.
 * return 0 on failure.
 */
unsigned int TCP_Connections::tcp_connection_to_online_tcp_relays(int connections_number)
{
    TCP_Connection_to *con_to = get_connection(this, connections_number);

    if (!con_to)
        return 0;

    return online_tcp_connection_from_conn(con_to);
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
        TCP_con *tcp_con = get_tcp_connection(this, (i + r) % tcp_connections.size());

        if (!tcp_con) {
            continue;
        }

        if (tcp_con->status == TCP_CONN_CONNECTED) {
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
            TCP_con *tcp_con = get_tcp_connection(this, i);

            if (tcp_con) {
                if (tcp_con->status == TCP_CONN_CONNECTED && !tcp_con->onion) {
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
                TCP_con *tcp_con = get_tcp_connection(this, i);

                if (tcp_con) {
                    if (tcp_con->status == TCP_CONN_SLEEPING) {
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
            TCP_con *tcp_con = get_tcp_connection(this, i);

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
 *
 * Returns NULL on failure.
 */
TCP_Connections *new_tcp_connections(const SecretKey &secret_key, TCP_Proxy_Info *proxy_info)
{
    TCP_Connections *temp = (TCP_Connections *) calloc(1, sizeof(TCP_Connections));

    if (temp == NULL)
        return NULL;

    temp->self_secret_key = secret_key;
    crypto_scalarmult_curve25519_base(temp->self_public_key.data.data(), temp->self_secret_key.data.data());
    temp->proxy_info = *proxy_info;

    return temp;
}

static void do_tcp_conns(TCP_Connections *tcp_c)
{
    unsigned int i;

    for (i = 0; i < tcp_c->tcp_connections.size(); ++i) {
        TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con) {
            if (tcp_con->status != TCP_CONN_SLEEPING) {
                tcp_con->connection->do_TCP_connection();

                /* callbacks can change TCP connection address. */
                tcp_con = get_tcp_connection(tcp_c, i);

                if (tcp_con->connection->status == ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED) {
                    if (tcp_con->status == TCP_CONN_CONNECTED) {
                        reconnect_tcp_relay_connection(tcp_c, i);
                    } else {
                        kill_tcp_relay_connection(tcp_c, i);
                    }

                    continue;
                }

                if (tcp_con->status == TCP_CONN_VALID && tcp_con->connection->status == ClientToServerConnectionStatus::TCP_CLIENT_CONFIRMED) {
                    tcp_relay_on_online(tcp_c, i);
                }

                if (tcp_con->status == TCP_CONN_CONNECTED && !tcp_con->onion && tcp_con->lock_count
                        && tcp_con->lock_count == tcp_con->sleep_count
                        && is_timeout(tcp_con->connected_time, TCP_CONNECTION_ANNOUNCE_TIMEOUT)) {
                    sleep_tcp_relay_connection(tcp_c, i);
                }
            }

            if (tcp_con->status == TCP_CONN_SLEEPING && tcp_con->unsleep) {
                unsleep_tcp_relay_connection(tcp_c, i);
            }
        }
    }
}

static void kill_nonused_tcp(TCP_Connections *tcp_c)
{
    if (tcp_c->tcp_connections.size() == 0)
        return;

    unsigned int i, num_online = 0, num_kill = 0, to_kill[tcp_c->tcp_connections.size()];

    for (i = 0; i < tcp_c->tcp_connections.size(); ++i) {
        TCP_con *tcp_con = get_tcp_connection(tcp_c, i);

        if (tcp_con) {
            if (tcp_con->status == TCP_CONN_CONNECTED) {
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
        kill_tcp_relay_connection(tcp_c, to_kill[i]);
    }
}

void TCP_Connections::do_tcp_connections()
{
    do_tcp_conns(this);
    kill_nonused_tcp(this);
}

void kill_tcp_connections(TCP_Connections *tcp_c)
{
    unsigned int i;

    for (i = 0; i < tcp_c->tcp_connections.size(); ++i) {
        delete tcp_c->tcp_connections[i].connection;
    }

    free(tcp_c);
}


