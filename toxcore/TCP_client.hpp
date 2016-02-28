/*
* TCP_client.h -- Implementation of the TCP relay client part of Tox.
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


#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include "crypto_core.hpp"
#include "TCP_server.hpp"

#define TCP_CONNECTION_TIMEOUT 10

typedef enum {
    TCP_PROXY_NONE,
    TCP_PROXY_HTTP,
    TCP_PROXY_SOCKS5
} TCP_PROXY_TYPE;

typedef struct {
    bitox::network::IPPort ip_port;
    uint8_t proxy_type; // a value from TCP_PROXY_TYPE
} TCP_Proxy_Info;

enum {
    TCP_CLIENT_NO_STATUS,
    TCP_CLIENT_PROXY_HTTP_CONNECTING,
    TCP_CLIENT_PROXY_SOCKS5_CONNECTING,
    TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED,
    TCP_CLIENT_CONNECTING,
    TCP_CLIENT_UNCONFIRMED,
    TCP_CLIENT_CONFIRMED,
    TCP_CLIENT_DISCONNECTED,
};
struct TCP_Client_Connection
{
    bool send_pending_data();
    void add_priority(const uint8_t *packet, uint16_t size, uint16_t sent);
    
    uint8_t status;
    bitox::network::sock_t  sock;
    bitox::PublicKey self_public_key; /* our public key */
    bitox::PublicKey public_key; /* public key of the server */
    bitox::network::IPPort ip_port; /* The ip and port of the server */
    TCP_Proxy_Info proxy_info;
    bitox::Nonce recv_nonce; /* Nonce of received packets. */
    bitox::Nonce sent_nonce; /* Nonce of sent packets. */
    bitox::SharedKey shared_key;
    uint16_t next_packet_length;

    bitox::SecretKey temp_secret_key;

    uint8_t last_packet[2 + MAX_PACKET_SIZE];
    uint16_t last_packet_length;
    uint16_t last_packet_sent;

    //TCP_Priority_List *priority_queue_start, *priority_queue_end;
    std::deque<DataToSend> priority_queue;

    uint64_t kill_at;

    uint64_t last_pinged;
    uint64_t ping_id;

    uint64_t ping_response_id;
    uint64_t ping_request_id;

    struct {
        uint8_t status; /* 0 if not used, 1 if other is offline, 2 if other is online. */
        bitox::PublicKey public_key;
        uint32_t number;
    } connections[NUM_CLIENT_CONNECTIONS];
    int (*response_callback)(void *object, uint8_t connection_id, const bitox::PublicKey &public_key);
    void *response_callback_object;
    int (*status_callback)(void *object, uint32_t number, uint8_t connection_id, uint8_t status);
    void *status_callback_object;
    int (*data_callback)(void *object, uint32_t number, uint8_t connection_id, const uint8_t *data, uint16_t length);
    void *data_callback_object;
    int (*oob_data_callback)(void *object, const bitox::PublicKey &public_key, const uint8_t *data, uint16_t length);
    void *oob_data_callback_object;

    int (*onion_callback)(void *object, const uint8_t *data, uint16_t length);
    void *onion_callback_object;

    /* Can be used by user. */
    void *custom_object;
    uint32_t custom_uint;
};

/* Create new TCP connection to ip_port/public_key
 */
TCP_Client_Connection *new_TCP_connection(bitox::network::IPPort ip_port, const bitox::PublicKey &public_key, const bitox::PublicKey &self_public_key,
        const bitox::SecretKey &self_secret_key, TCP_Proxy_Info *proxy_info);

/* Run the TCP connection
 */
void do_TCP_connection(TCP_Client_Connection *TCP_connection);

/* Kill the TCP connection
 */
void kill_TCP_connection(TCP_Client_Connection *TCP_connection);

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int send_onion_request(TCP_Client_Connection *con, const uint8_t *data, uint16_t length);
void onion_response_handler(TCP_Client_Connection *con, int (*onion_callback)(void *object, const uint8_t *data,
                            uint16_t length), void *object);

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int send_routing_request(TCP_Client_Connection *con, bitox::PublicKey &public_key);
void routing_response_handler(TCP_Client_Connection *con, int (*response_callback)(void *object, uint8_t connection_id,
                              const bitox::PublicKey &public_key), void *object);
void routing_status_handler(TCP_Client_Connection *con, int (*status_callback)(void *object, uint32_t number,
                            uint8_t connection_id, uint8_t status), void *object);

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int send_disconnect_request(TCP_Client_Connection *con, uint8_t con_id);

/* Set the number that will be used as an argument in the callbacks related to con_id.
 *
 * When not set by this function, the number is ~0.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_connection_number(TCP_Client_Connection *con, uint8_t con_id, uint32_t number);

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure.
 */
int send_data(TCP_Client_Connection *con, uint8_t con_id, const uint8_t *data, uint16_t length);
void routing_data_handler(TCP_Client_Connection *con, int (*data_callback)(void *object, uint32_t number,
                          uint8_t connection_id, const uint8_t *data, uint16_t length), void *object);

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure.
 */
int send_oob_packet(TCP_Client_Connection *con, const bitox::PublicKey &public_key, const uint8_t *data, uint16_t length);
void oob_data_handler(TCP_Client_Connection *con, int (*oob_data_callback)(void *object, const bitox::PublicKey &public_key,
                      const uint8_t *data, uint16_t length), void *object);


#endif
