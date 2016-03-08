/* TCP_connection.h
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

#ifndef TCP_CONNECTION_H
#define TCP_CONNECTION_H

#include "TCP_client.hpp"
#include <vector>

enum class TCPConnectionStatus
{
    TCP_CONN_NONE = 0,
    TCP_CONN_VALID = 1,
    
    //NOTE: only used by TCP_con
    TCP_CONN_CONNECTED = 2,
    
    // Connection is not connected but can be quickly reconnected in case it is needed
    TCP_CONN_SLEEPING = 3
};

enum class TCPConnectionsStatus
{
    TCP_CONNECTIONS_STATUS_NONE = 0,
    TCP_CONNECTIONS_STATUS_REGISTERED = 1,
    TCP_CONNECTIONS_STATUS_ONLINE = 2
};

constexpr unsigned MAX_FRIEND_TCP_CONNECTIONS = 6;

/* Time until connection to friend gets killed (if it doesn't get locked withing that time) */
constexpr long TCP_CONNECTION_ANNOUNCE_TIMEOUT = TCP_CONNECTION_TIMEOUT;

/* The amount of recommended connections for each friend
   NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2) */
constexpr unsigned RECOMMENDED_FRIEND_TCP_CONNECTIONS = MAX_FRIEND_TCP_CONNECTIONS / 2;

/* Number of TCP connections used for onion purposes. */
constexpr unsigned NUM_ONION_TCP_CONNECTIONS = RECOMMENDED_FRIEND_TCP_CONNECTIONS;

struct TCP_Connection_to
{
    TCPConnectionStatus status = TCPConnectionStatus::TCP_CONN_NONE;
    bitox::PublicKey public_key; /* The dht public key of the peer */

    struct {
        uint32_t tcp_connection = 0;
        TCPConnectionsStatus status = TCPConnectionsStatus::TCP_CONNECTIONS_STATUS_NONE;
        unsigned int connection_id = 0;
    } connections[MAX_FRIEND_TCP_CONNECTIONS];

    int id = 0; /* id used in callbacks. */
    
private:
    friend struct TCP_Connections;
    
    bool tcp_connection_in_conn(unsigned int tcp_connections_number);
    
    /* return index on success.
    * return -1 on failure.
    */
    int add_tcp_connection_to_conn(unsigned int tcp_connections_number);
    
    /* return index on success.
    * return -1 on failure.
    */
    int rm_tcp_connection_from_conn(unsigned int tcp_connections_number);
    
    /* return number of online connections on success.
    * return -1 on failure.
    */
    unsigned int online_tcp_connection_from_conn() const;
    
    /* return index on success.
    * return -1 on failure.
    */
    int set_tcp_connection_status(unsigned int tcp_connections_number,
                                        TCPConnectionsStatus status, uint8_t connection_id);
};

struct TCP_con
{
    TCPConnectionStatus status = TCPConnectionStatus::TCP_CONN_NONE;
    TCP_Client_Connection *connection = nullptr;
    uint64_t connected_time = 0;
    uint32_t lock_count = 0;
    uint32_t sleep_count = 0;
    bool onion = false;

    /* Only used when connection is sleeping. */
    bitox::network::IPPort ip_port;
    bitox::PublicKey relay_pk;
    bool unsleep = false; /* set to true to unsleep connection. */
};

struct TCP_Connections : TCPClientEventListener
{
    /* Returns a new TCP_Connections object associated with the secret_key.
    *
    * In order for others to connect to this instance new_tcp_connection_to() must be called with the
    * public_key associated with secret_key.
    */
    TCP_Connections(const bitox::SecretKey &secret_key, TCP_Proxy_Info *proxy_info);
    
    ~TCP_Connections();

    /* Send a packet to the TCP connection.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int send_packet_tcp_connection(int connections_number, const uint8_t *packet, uint16_t length);
    
    /* Return a random TCP connection number for use in send_tcp_onion_request.
    *
    * TODO: This number is just the index of an array that the elements can
    * change without warning.
    *
    * return TCP connection number on success.
    * return -1 on failure.
    */
    int get_random_tcp_onion_conn_number();
    
    /* Send an onion packet via the TCP relay corresponding to tcp_connections_number.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int tcp_send_onion_request(unsigned int tcp_connections_number, const uint8_t *data,
                            uint16_t length);
    
    /* Set if we want TCP_connection to allocate some connection for onion use.
    *
    * If status is 1, allocate some connections. if status is 0, don't.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int set_tcp_onion_status(bool status);
    
    /* Send an oob packet via the TCP relay corresponding to tcp_connections_number.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int tcp_send_oob_packet(unsigned int tcp_connections_number, const bitox::PublicKey &public_key,
                            const uint8_t *packet, uint16_t length);
    
    /* Create a new TCP connection to public_key.
    *
    * public_key must be the counterpart to the secret key that the other peer used with new_tcp_connections().
    *
    * id is the id in the callbacks for that connection.
    *
    * return connections_number on success.
    * return -1 on failure.
    */
    int new_tcp_connection_to(const bitox::PublicKey &public_key, int id);
    
    /* return 0 on success.
    * return -1 on failure.
    */
    int kill_tcp_connection_to(int connections_number);
    
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
    int set_tcp_connection_to_status(int connections_number, bool status);
    
    /* return number of online tcp relays tied to the connection on success.
    * return 0 on failure.
    */
    unsigned int tcp_connection_to_online_tcp_relays(int connections_number) const;
    
    /* Add a TCP relay tied to a connection.
    *
    * NOTE: This can only be used during the tcp_oob_callback.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int add_tcp_number_relay_connection(int connections_number,
                                        unsigned int tcp_connections_number);
    
    /* Add a TCP relay tied to a connection.
    *
    * This should be called with the same relay by two peers who want to create a TCP connection with each other.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int add_tcp_relay_connection(int connections_number, bitox::network::IPPort ip_port, const bitox::PublicKey &relay_pk);
    
    /* Add a TCP relay to the instance.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int add_tcp_relay_global(bitox::network::IPPort ip_port, const bitox::PublicKey &relay_pk);
    
    /* Copy a maximum of max_num TCP relays we are connected to to tcp_relays.
    * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
    *
    * return number of relays copied to tcp_relays on success.
    * return 0 on failure.
    */
    unsigned int tcp_copy_connected_relays(bitox::dht::NodeFormat *tcp_relays, uint16_t max_num);
    
    void do_tcp_connections();
    
    DHT *dht;

    bitox::PublicKey self_public_key;
    bitox::SecretKey self_secret_key;

    std::vector<TCP_Connection_to> connections;
    std::vector<TCP_con> tcp_connections;

    int (*tcp_data_callback)(void *object, int id, const uint8_t *data, uint16_t length);
    void *tcp_data_callback_object;

    int (*tcp_oob_callback)(void *object, const bitox::PublicKey &public_key, unsigned int tcp_connections_number,
                            const uint8_t *data, uint16_t length);
    void *tcp_oob_callback_object;

    int (*tcp_onion_callback)(void *object, const uint8_t *data, uint16_t length);
    void *tcp_onion_callback_object;

    TCP_Proxy_Info proxy_info;

    bool onion_status;
    uint16_t onion_num_conns;
    
    virtual int on_response(TCP_Client_Connection *connection, uint8_t connection_id, const bitox::PublicKey &public_key) override;
    virtual int on_status(TCP_Client_Connection *connection, uint32_t number, uint8_t connection_id, ClientToClientConnectionStatus status) override;
    virtual int on_data (TCP_Client_Connection *connection, uint32_t number, uint8_t connection_id, const uint8_t *data, uint16_t length) override;
    virtual int on_oob_data(TCP_Client_Connection *connection, const bitox::PublicKey &public_key, const uint8_t *data, uint16_t length) override;
    virtual int on_onion(TCP_Client_Connection *connection, const uint8_t *data, uint16_t length) override;
    
private:
    friend TCP_Connection_to;
    /* return 1 if the connections_number is not valid.
    * return 0 if the connections_number is valid.
    */
    bool connections_number_not_valid(int connections_number) const;
    
    /* return 1 if the tcp_connections_number is not valid.
    * return 0 if the tcp_connections_number is valid.
    */
    bool tcp_connections_number_not_valid(int tcp_connections_number);
    
    /* Create a new empty connection.
    *
    * return -1 on failure.
    * return connections_number on success.
    */
    int create_connection();
    
    /* Create a new empty tcp connection.
    *
    * return -1 on failure.
    * return tcp_connections_number on success.
    */
    int create_tcp_connection();
    
    /* Wipe a connection.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int wipe_connection(int connections_number);
    
    /* Wipe a connection.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int wipe_tcp_connection(int tcp_connections_number);
    
    TCP_Connection_to *get_connection(int connections_number);
    
    TCP_con *get_tcp_connection(int tcp_connections_number);
    
    /* Find the TCP connection with public_key.
    *
    * return connections_number on success.
    * return -1 on failure.
    */
    int find_tcp_connection_to(const bitox::PublicKey &public_key);
    
    /* Find the TCP connection to a relay with relay_pk.
    *
    * return connections_number on success.
    * return -1 on failure.
    */
    int find_tcp_connection_relay(const bitox::PublicKey &relay_pk);
    
    /* Kill a TCP relay connection.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int kill_tcp_relay_connection(int tcp_connections_number);
    
    int reconnect_tcp_relay_connection(int tcp_connections_number);
    int sleep_tcp_relay_connection(int tcp_connections_number);
    int unsleep_tcp_relay_connection(int tcp_connections_number);
    /* Send a TCP routing request.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int send_tcp_relay_routing_request(int tcp_connections_number, bitox::PublicKey &public_key);

    /* Set callbacks for the TCP relay connection.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int tcp_relay_set_callbacks(int tcp_connections_number);
    int tcp_relay_on_online(int tcp_connections_number);
    int add_tcp_relay_instance(bitox::network::IPPort ip_port, const bitox::PublicKey &relay_pk);
    void do_tcp_conns();
    void kill_nonused_tcp();
};


/* Set the callback for TCP data packets.
 */
void set_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_data_callback)(void *object, int id,
                                        const uint8_t *data, uint16_t length), void *object);

/* Set the callback for TCP onion packets.
 */
void set_onion_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_onion_callback)(void *object,
        const uint8_t *data, uint16_t length), void *object);

/* Set the callback for TCP oob data packets.
 */
void set_oob_packet_tcp_connection_callback(TCP_Connections *tcp_c, int (*tcp_oob_callback)(void *object,
        const bitox::PublicKey &public_key, unsigned int tcp_connections_number, const uint8_t *data, uint16_t length), void *object);

#endif

