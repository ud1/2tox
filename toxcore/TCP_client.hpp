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

constexpr long TCP_CONNECTION_TIMEOUT = 10;

enum class TCP_PROXY_TYPE
{
    TCP_PROXY_NONE,
    TCP_PROXY_HTTP,
    TCP_PROXY_SOCKS5
};

struct TCP_Proxy_Info
{
    bitox::network::IPPort ip_port;
    TCP_PROXY_TYPE proxy_type;
};

enum class ClientToServerConnectionStatus
{
    TCP_CLIENT_NO_STATUS,
    TCP_CLIENT_PROXY_HTTP_CONNECTING,
    TCP_CLIENT_PROXY_SOCKS5_CONNECTING,
    TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED,
    TCP_CLIENT_CONNECTING,
    TCP_CLIENT_UNCONFIRMED,
    TCP_CLIENT_CONFIRMED,
    TCP_CLIENT_DISCONNECTED,
};

struct TCP_Client_Connection;

class TCPClientEventListener
{
public:
    virtual int on_response(TCP_Client_Connection *connection, uint8_t connection_id, const bitox::PublicKey &public_key) = 0;
    virtual int on_status(TCP_Client_Connection *connection, uint32_t number, uint8_t connection_id, ClientToClientConnectionStatus status) = 0;
    virtual int on_data (TCP_Client_Connection *connection, uint32_t number, uint8_t connection_id, const uint8_t *data, uint16_t length) = 0;
    virtual int on_oob_data(TCP_Client_Connection *connection, const bitox::PublicKey &public_key, const uint8_t *data, uint16_t length) = 0;
    virtual int on_onion(TCP_Client_Connection *connection, const uint8_t *data, uint16_t length) = 0;
};

struct TCP_Client_Connection
{
    /* Create new TCP connection to ip_port/public_key
    */
    TCP_Client_Connection(bitox::network::IPPort ip_port, const bitox::PublicKey &public_key, const bitox::PublicKey &self_public_key,
            const bitox::SecretKey &self_secret_key, TCP_Proxy_Info *proxy_info);
    
    ~TCP_Client_Connection();

    bool send_pending_data();
    void add_priority(const uint8_t *packet, uint16_t size, uint16_t sent);
    
    /* Run the TCP connection
    */
    void do_TCP_connection();
    
    /* return 1 on success.
    * return 0 if could not send packet.
    * return -1 on failure (connection must be killed).
    */
    int send_onion_request(const uint8_t *data, uint16_t length);
    
    /* return 1 on success.
    * return 0 if could not send packet.
    * return -1 on failure (connection must be killed).
    */
    int send_disconnect_request(uint8_t con_id);
    
    /* Set the number that will be used as an argument in the callbacks related to con_id.
    *
    * When not set by this function, the number is ~0.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int set_tcp_connection_number(uint8_t con_id, uint32_t number);
    
    /* return 1 on success.
    * return 0 if could not send packet.
    * return -1 on failure.
    */
    int send_data(uint8_t con_id, const uint8_t *data, uint16_t length);
    
    /* return 1 on success.
    * return 0 if could not send packet.
    * return -1 on failure.
    */
    int send_oob_packet(const bitox::PublicKey &public_key, const uint8_t *data, uint16_t length);
    
    /* return 1 on success.
    * return 0 if could not send packet.
    * return -1 on failure (connection must be killed).
    */
    int send_routing_request(bitox::PublicKey &public_key);
    
    ClientToServerConnectionStatus status;
    bitox::network::sock_t  sock;
    bitox::PublicKey self_public_key; /* our public key */
    bitox::PublicKey public_key; /* public key of the server */
    bitox::network::IPPort ip_port; /* The ip and port of the server */
    TCP_Proxy_Info proxy_info;
    bitox::Nonce recv_nonce = bitox::Nonce::create_empty(); /* Nonce of received packets. */
    bitox::Nonce sent_nonce = bitox::Nonce::create_empty(); /* Nonce of sent packets. */
    bitox::SharedKey shared_key;
    uint16_t next_packet_length;

    bitox::SecretKey temp_secret_key;

    uint8_t last_packet[2 + MAX_PACKET_SIZE];
    uint16_t last_packet_length;
    uint16_t last_packet_sent;

    std::deque<DataToSend> priority_queue;

    uint64_t kill_at;

    uint64_t last_pinged;
    uint64_t ping_id;

    uint64_t ping_response_id;
    uint64_t ping_request_id;

    struct {
        ClientToClientConnectionStatus status;
        bitox::PublicKey public_key;
        uint32_t number;
    } connections[NUM_CLIENT_CONNECTIONS];
    
    TCPClientEventListener *event_listener = nullptr;
    
    /* Can be used by user. */
    uint32_t custom_uint;
    
private:
    /* return 1 on success.
    * return 0 on failure.
    */
    int proxy_http_generate_connection_request();
    
    /* return 1 on success.
    * return 0 if no data received.
    * return -1 on failure (connection refused).
    */
    int proxy_http_read_connection_response();
    
    void proxy_socks5_generate_handshake();
    
    /* return 1 on success.
    * return 0 if no data received.
    * return -1 on failure (connection refused).
    */
    int socks5_read_handshake_response();
    
    void proxy_socks5_generate_connection_request();
    
    /* return 1 on success.
    * return 0 if no data received.
    * return -1 on failure (connection refused).
    */
    int proxy_socks5_read_connection_response();
    
    /* return 0 on success.
    * return -1 on failure.
    */
    int generate_handshake();
    
    /* data must be of length TCP_SERVER_HANDSHAKE_SIZE
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int handle_handshake(const uint8_t *data);
    
    /* return 0 if pending data was sent completely
    * return -1 if it wasn't
    */
    int send_pending_data_nonpriority();
    
    /* return 1 on success.
    * return 0 if could not send packet.
    * return -1 on failure (connection must be killed).
    */
    int write_packet_TCP_secure_connection(const uint8_t *data, uint16_t length, bool priority);
    
    /* return 1 on success.
    * return 0 if could not send packet.
    * return -1 on failure (connection must be killed).
    */
    int send_ping_request();
    
    /* return 1 on success.
    * return 0 if could not send packet.
    * return -1 on failure (connection must be killed).
    */
    int send_ping_response();
    
    /* return 0 on success
    * return -1 on failure
    */
    int handle_TCP_packet(const uint8_t *data, uint16_t length);
    
    int do_confirmed_TCP();
};

#endif
