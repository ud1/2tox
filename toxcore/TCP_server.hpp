/*
* TCP_server.h -- Implementation of the TCP relay server part of Tox.
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

#ifndef TCP_SERVER_H
#define TCP_SERVER_H

#include "crypto_core.hpp"
#include "onion.hpp"
#include <map>
#include <vector>
#include <deque>

#ifdef TCP_SERVER_USE_EPOLL
#include "sys/epoll.h"
#endif

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32) || defined(__MACH__)
#define MSG_NOSIGNAL 0
#endif

#define MAX_INCOMMING_CONNECTIONS 256

#define TCP_MAX_BACKLOG MAX_INCOMMING_CONNECTIONS

#define MAX_PACKET_SIZE 2048

#define TCP_HANDSHAKE_PLAIN_SIZE (crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES)
#define TCP_SERVER_HANDSHAKE_SIZE (crypto_box_NONCEBYTES + TCP_HANDSHAKE_PLAIN_SIZE + crypto_box_MACBYTES)
#define TCP_CLIENT_HANDSHAKE_SIZE (crypto_box_PUBLICKEYBYTES + TCP_SERVER_HANDSHAKE_SIZE)
#define TCP_MAX_OOB_DATA_LENGTH 1024

#define NUM_RESERVED_PORTS 16
#define NUM_CLIENT_CONNECTIONS (256 - NUM_RESERVED_PORTS)

enum TCPPacketType
{
    TCP_PACKET_ROUTING_REQUEST = 0,
    TCP_PACKET_ROUTING_RESPONSE = 1,
    TCP_PACKET_CONNECTION_NOTIFICATION = 2,
    TCP_PACKET_DISCONNECT_NOTIFICATION = 3,
    TCP_PACKET_PING = 4,
    TCP_PACKET_PONG = 5,
    TCP_PACKET_OOB_SEND = 6,
    TCP_PACKET_OOB_RECV = 7,
    TCP_PACKET_ONION_REQUEST = 8,
    TCP_PACKET_ONION_RESPONSE = 9,
};

#define ARRAY_ENTRY_SIZE 6

/* frequency to ping connected nodes and timeout in seconds */
#define TCP_PING_FREQUENCY 30
#define TCP_PING_TIMEOUT 10

#ifdef TCP_SERVER_USE_EPOLL
#define TCP_SOCKET_LISTENING 0
#define TCP_SOCKET_INCOMING 1
#define TCP_SOCKET_UNCONFIRMED 2
#define TCP_SOCKET_CONFIRMED 3
#endif

enum class TCP_Secure_Connection_Status
{
    TCP_STATUS_NO_STATUS,
    TCP_STATUS_CONNECTED,
    TCP_STATUS_UNCONFIRMED,
    TCP_STATUS_CONFIRMED,
};

struct DataToSend
{
    DataToSend(const uint8_t *data, size_t size, size_t bytes_sent) : data(data, data + size), bytes_sent(bytes_sent) {}
    
    std::vector<uint8_t> data;
    size_t bytes_sent;
};

enum class TCPClientConnectionStatus
{
    NOT_USED,
    OFFLINE,
    ONLINE
};

struct TCP_Secure_Connection
{
    bool send_pending_data();
    void add_priority(const uint8_t *packet, size_t size, size_t sent);
    
    TCP_Secure_Connection_Status status = TCP_Secure_Connection_Status::TCP_STATUS_NO_STATUS;
    bitox::network::sock_t  sock;
    bitox::PublicKey public_key;
    bitox::Nonce recv_nonce = bitox::Nonce::create_empty(); /* Nonce of received packets. */
    bitox::Nonce sent_nonce = bitox::Nonce::create_empty(); /* Nonce of sent packets. */
    bitox::SharedKey shared_key;
    uint16_t next_packet_length;
    struct {
        TCPClientConnectionStatus status = TCPClientConnectionStatus::NOT_USED;
        bitox::PublicKey public_key;
        uint32_t index;
        uint8_t other_id;
    } connections[NUM_CLIENT_CONNECTIONS];
    uint8_t last_packet[2 + MAX_PACKET_SIZE];
    uint16_t last_packet_length;
    uint16_t last_packet_sent;

    std::deque<DataToSend> priority_queue;

    uint64_t identifier;

    uint64_t last_pinged;
    uint64_t ping_id;
    
// private:
    bool send_pending_data_nonpriority();
    int write_packet_TCP_secure_connection(const uint8_t *data, uint16_t length, bool priority);
    int send_disconnect_notification(uint8_t id);
    int send_connect_notification(uint8_t id);
    int send_routing_response(uint8_t rpid, const bitox::PublicKey &public_key);
    int read_connection_handshake(const bitox::SecretKey &self_secret_key);
    int handle_TCP_handshake(const uint8_t *data, uint16_t length, const bitox::SecretKey &self_secret_key);
};


struct TCP_Server
{
    TCP_Server(uint8_t ipv6_enabled, uint16_t num_sockets, const uint16_t *ports, const bitox::SecretKey &secret_key, Onion *onion);
    ~TCP_Server();
    
    // Run the TCP_server
    void do_TCP_server();
    
    Onion *onion;

#ifdef TCP_SERVER_USE_EPOLL
    int efd;
    uint64_t last_run_pinged;
#endif
    std::vector<bitox::network::sock_t> socks_listening;

    bitox::PublicKey public_key;
    bitox::SecretKey secret_key;
    TCP_Secure_Connection incomming_connection_queue[MAX_INCOMMING_CONNECTIONS];
    uint16_t incomming_connection_queue_index;
    TCP_Secure_Connection unconfirmed_connection_queue[MAX_INCOMMING_CONNECTIONS];
    uint16_t unconfirmed_connection_queue_index;

    std::vector<TCP_Secure_Connection> accepted_connection_array;
    uint32_t num_accepted_connections;

    uint64_t counter;

    std::map<bitox::PublicKey, int> accepted_key_list;
    
// private::
    void do_TCP_accept_new();
    int do_incoming(uint32_t i);
    int do_unconfirmed(uint32_t i);
    void do_confirmed_recv(uint32_t i);
    void do_TCP_incomming();
    void do_TCP_unconfirmed();
    void do_TCP_confirmed();
    int accept_connection(bitox::network::sock_t sock);
    int confirm_TCP_connection(TCP_Secure_Connection *con, const uint8_t *data, uint16_t length);
    int add_accepted(const TCP_Secure_Connection *con);
    int kill_accepted(int index);
    int get_TCP_connection_index(const bitox::PublicKey &public_key);
    int del_accepted(int index);
    int rm_connection_index(TCP_Secure_Connection *con, uint8_t con_number);
    int handle_TCP_routing_req(uint32_t con_id, const bitox::PublicKey &public_key);
    int handle_TCP_oob_send(uint32_t con_id, const bitox::PublicKey &public_key, const uint8_t *data, uint16_t length);
    int handle_TCP_packet(uint32_t con_id, const uint8_t *data, uint16_t length);
#ifdef TCP_SERVER_USE_EPOLL
    void do_TCP_epoll();
#endif
};

/* return the amount of data in the tcp recv buffer.
 * return 0 on failure.
 */
unsigned int TCP_socket_data_recv_buffer(bitox::network::sock_t sock);

/* Read the next two bytes in TCP stream then convert them to
 * length (host byte order).
 *
 * return length on success
 * return 0 if nothing has been read from socket.
 * return ~0 on failure.
 */
uint16_t read_TCP_length(bitox::network::sock_t sock);

/* Read length bytes from socket.
 *
 * return length on success
 * return -1 on failure/no data in buffer.
 */
int read_TCP_packet(bitox::network::sock_t sock, uint8_t *data, uint16_t length);

/* return length of received packet on success.
 * return 0 if could not read any packet.
 * return -1 on failure (connection must be killed).
 */
int read_packet_TCP_secure_connection(bitox::network::sock_t sock, uint16_t *next_packet_length, const bitox::SharedKey &shared_key,
                                      bitox::Nonce &recv_nonce, uint8_t *data, uint16_t max_len);


#endif
