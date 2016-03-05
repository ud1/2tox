/*
* TCP_client.c -- Implementation of the TCP relay client part of Tox.
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

#include "TCP_client.hpp"
#include "protocol_impl.hpp"

#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <sys/ioctl.h>
#endif

#include "util.hpp"

using namespace bitox;
using namespace bitox::network;
using namespace bitox::impl;

/* return 1 on success
 * return 0 on failure
 */
static int connect_sock_to(sock_t sock, IPPort ip_port, TCP_Proxy_Info *proxy_info)
{
    if (proxy_info->proxy_type != TCP_PROXY_TYPE::TCP_PROXY_NONE) {
        ip_port = proxy_info->ip_port;
    }

    struct sockaddr_storage addr = {0};

    size_t addrsize;

    if (ip_port.ip.family == Family::FAMILY_AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_addr = ip_port.ip.to_in_addr();
        addr4->sin_port = ip_port.port;
    } else if (ip_port.ip.family == Family::FAMILY_AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_addr = ip_port.ip.to_in6_addr();
        addr6->sin6_port = ip_port.port;
    } else {
        return 0;
    }

    /* nonblocking socket, connect will never return success */
    connect(sock, (struct sockaddr *)&addr, addrsize);
    return 1;
}

/* return 1 on success.
 * return 0 on failure.
 */
int TCP_Client_Connection::proxy_http_generate_connection_request()
{
    char one[] = "CONNECT ";
    char two[] = " HTTP/1.1\nHost: ";
    char three[] = "\r\n\r\n";

    char ip[INET6_ADDRSTRLEN];

    if (!ip_parse_addr(&ip_port.ip, ip, sizeof(ip))) {
        return 0;
    }

    const uint16_t port = ntohs(ip_port.port);
    const int written = snprintf((char *)last_packet, MAX_PACKET_SIZE, "%s%s:%hu%s%s:%hu%s", one, ip, port, two,
                                 ip, port, three);

    if (written < 0 || MAX_PACKET_SIZE < written) {
        return 0;
    }

    last_packet_length = written;
    last_packet_sent = 0;

    return 1;
}

/* return 1 on success.
 * return 0 if no data received.
 * return -1 on failure (connection refused).
 */
int TCP_Client_Connection::proxy_http_read_connection_response()
{
    char success[] = "200";
    uint8_t data[16]; // draining works the best if the length is a power of 2

    int ret = read_TCP_packet(sock, data, sizeof(data) - 1);

    if (ret == -1) {
        return 0;
    }

    data[sizeof(data) - 1] = 0;

    if (strstr((char *)data, success)) {
        // drain all data
        unsigned int data_left = TCP_socket_data_recv_buffer(sock);

        if (data_left) {
            uint8_t temp_data[data_left];
            read_TCP_packet(sock, temp_data, data_left);
        }

        return 1;
    }

    return -1;
}

void TCP_Client_Connection::proxy_socks5_generate_handshake()
{
    last_packet[0] = 5; /* SOCKSv5 */
    last_packet[1] = 1; /* number of authentication methods supported */
    last_packet[2] = 0; /* No authentication */

    last_packet_length = 3;
    last_packet_sent = 0;
}

/* return 1 on success.
 * return 0 if no data received.
 * return -1 on failure (connection refused).
 */
int TCP_Client_Connection::socks5_read_handshake_response()
{
    uint8_t data[2];
    int ret = read_TCP_packet(sock, data, sizeof(data));

    if (ret == -1)
        return 0;

    if (data[0] == 5 && data[1] == 0) // FIXME magic numbers
        return 1;

    return -1;
}

void TCP_Client_Connection::proxy_socks5_generate_connection_request()
{
    last_packet[0] = 5; /* SOCKSv5 */
    last_packet[1] = 1; /* command code: establish a TCP/IP stream connection */
    last_packet[2] = 0; /* reserved, must be 0 */
    uint16_t length = 3;

    if (ip_port.ip.family == Family::FAMILY_AF_INET) {
        last_packet[3] = 1; /* IPv4 address */
        ++length;
        memcpy(last_packet + length, ip_port.ip.address.to_v4().to_bytes().data(), 4);
        length += 4;
    } else {
        last_packet[3] = 4; /* IPv6 address */
        ++length;
        memcpy(last_packet + length, ip_port.ip.address.to_v6().to_bytes().data(), 16);
        length += 16;
    }

    memcpy(last_packet + length, &ip_port.port, sizeof(uint16_t));
    length += sizeof(uint16_t);

    last_packet_length = length;
    last_packet_sent = 0;
}

/* return 1 on success.
 * return 0 if no data received.
 * return -1 on failure (connection refused).
 */
int TCP_Client_Connection::proxy_socks5_read_connection_response()
{
    if (ip_port.ip.family == Family::FAMILY_AF_INET) {
        uint8_t data[4 + 4 + sizeof(uint16_t)];
        int ret = read_TCP_packet(sock, data, sizeof(data));

        if (ret == -1)
            return 0;

        if (data[0] == 5 && data[1] == 0)
            return 1;

    } else {
        uint8_t data[4 + 16 + sizeof(uint16_t)];
        int ret = read_TCP_packet(sock, data, sizeof(data));

        if (ret == -1)
            return 0;

        if (data[0] == 5 && data[1] == 0)
            return 1;
    }

    return -1;
}

/* return 0 on success.
 * return -1 on failure.
 */
int TCP_Client_Connection::generate_handshake()
{
    PublicKey temp_public_key;
    std::tie(temp_public_key, temp_secret_key) = generate_keys();
    sent_nonce = Nonce::create_random();
    
    OutputBuffer packet;
    packet << temp_public_key << sent_nonce;
    
    memcpy(last_packet, self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    new_nonce(last_packet + crypto_box_PUBLICKEYBYTES);
    int len = encrypt_data_symmetric(shared_key.data.data(), last_packet + crypto_box_PUBLICKEYBYTES, packet.begin(),
                                     packet.size(), last_packet + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);

    if (len != packet.size() + crypto_box_MACBYTES)
        return -1;

    last_packet_length = crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + packet.size() + crypto_box_MACBYTES;
    last_packet_sent = 0;
    return 0;
}

/* data must be of length TCP_SERVER_HANDSHAKE_SIZE
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Client_Connection::handle_handshake(const uint8_t *data)
{
    InputBuffer packet(data, TCP_SERVER_HANDSHAKE_SIZE);
    Nonce nonce = Nonce::create_empty();
    if ((packet >> nonce).fail())
        return -1;
    
    Buffer decrypted_data;
    
    if (!decrypt_buffer(packet.get_buffer_data(), shared_key, nonce, decrypted_data))
        return -1;

    InputBuffer decrypted_buffer(std::move(decrypted_data));

    PublicKey temp_public_key;
    if ((decrypted_buffer >> temp_public_key >> recv_nonce).fail())
        return -1;
    
    shared_key = compute_shared_key(temp_public_key, temp_secret_key);
    sodium_memzero(temp_secret_key.data.data(), crypto_box_SECRETKEYBYTES);
    return 0;
}

/* return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
int TCP_Client_Connection::send_pending_data_nonpriority()
{
    if (last_packet_length == 0) {
        return 0;
    }

    uint16_t left = last_packet_length - last_packet_sent;
    int len = send(sock, last_packet + last_packet_sent, left, MSG_NOSIGNAL);

    if (len <= 0)
        return -1;

    if (len == left) {
        last_packet_length = 0;
        last_packet_sent = 0;
        return 0;
    }

    last_packet_sent += len;
    return -1;
}

/* return true if pending data was sent completely
 * return false if it wasn't
 */
bool TCP_Client_Connection::send_pending_data()
{
    /* finish sending current non-priority packet */
    if (send_pending_data_nonpriority() == -1) {
        return -1;
    }

    while (!priority_queue.empty())
    {
        DataToSend &entry = priority_queue.front();
        int left = entry.data.size() - entry.bytes_sent;
        int len = send(sock, entry.data.data() + entry.bytes_sent, left, MSG_NOSIGNAL);

        if (len != left)
        {
            if (len > 0)
                entry.bytes_sent += len;

            break;
        }

        priority_queue.pop_front();
    }

    return priority_queue.empty();
}

void TCP_Client_Connection::add_priority(const uint8_t *packet, uint16_t size, uint16_t sent)
{
    assert(size && "Size must not be 0");
    assert((sent < size) && "sent must be less than size");
    
    priority_queue.emplace_back(packet, size, sent);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Client_Connection::write_packet_TCP_secure_connection(const uint8_t *data, uint16_t length, bool priority)
{
    if (length + crypto_box_MACBYTES > MAX_PACKET_SIZE)
        return -1;

    bool sendpriority = 1;

    if (!send_pending_data()) {
        if (priority) {
            sendpriority = 0;
        } else {
            return 0;
        }
    }

    uint8_t packet[sizeof(uint16_t) + length + crypto_box_MACBYTES];

    uint16_t c_length = htons(length + crypto_box_MACBYTES);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_symmetric(shared_key.data.data(), sent_nonce.data.data(), data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (sizeof(packet) - sizeof(uint16_t)))
        return -1;

    if (priority) {
        len = sendpriority ? send(sock, packet, sizeof(packet), MSG_NOSIGNAL) : 0;

        if (len <= 0) {
            len = 0;
        }

        ++sent_nonce;

        if ((unsigned int)len == sizeof(packet)) {
            return 1;
        }

        add_priority(packet, sizeof(packet), len);
        return 1;
    }

    len = send(sock, packet, sizeof(packet), MSG_NOSIGNAL);

    if (len <= 0)
        return 0;

    ++sent_nonce;

    if ((unsigned int)len == sizeof(packet))
        return 1;

    memcpy(last_packet, packet, sizeof(packet));
    last_packet_length = sizeof(packet);
    last_packet_sent = len;
    return 1;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Client_Connection::send_routing_request(bitox::PublicKey &public_key)
{
    OutputBuffer packet;
    packet.write_byte(TCP_PACKET_ROUTING_REQUEST);
    packet << public_key;
    
    return write_packet_TCP_secure_connection(packet.begin(), packet.size(), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure.
 */
int TCP_Client_Connection::send_data(uint8_t con_id, const uint8_t *data, uint16_t length)
{
    if (con_id >= NUM_CLIENT_CONNECTIONS)
        return -1;

    if (connections[con_id].status != ClientToClientConnectionStatus::ONLINE)
        return -1;

    if (send_ping_response() == 0 || send_ping_request() == 0)
        return 0;

    uint8_t packet[1 + length];
    packet[0] = con_id + NUM_RESERVED_PORTS;
    memcpy(packet + 1, data, length);
    return write_packet_TCP_secure_connection(packet, sizeof(packet), 0);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure.
 */
int TCP_Client_Connection::send_oob_packet(const bitox::PublicKey &public_key, const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH)
        return -1;

    OutputBuffer packet;
    packet.write_byte(TCP_PACKET_OOB_SEND);
    packet << public_key;
    packet.write_bytes(data, data + length);
    
    return write_packet_TCP_secure_connection(packet.begin(), packet.size(), 0);
}


/* Set the number that will be used as an argument in the callbacks related to con_id.
 *
 * When not set by this function, the number is ~0.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int TCP_Client_Connection::set_tcp_connection_number(uint8_t con_id, uint32_t number)
{
    if (con_id >= NUM_CLIENT_CONNECTIONS)
        return -1;

    if (connections[con_id].status == ClientToClientConnectionStatus::NOT_USED)
        return -1;

    connections[con_id].number = number;
    return 0;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Client_Connection::send_ping_request()
{
    if (!ping_request_id)
        return 1;

    uint8_t packet[1 + sizeof(uint64_t)];
    packet[0] = TCP_PACKET_PING;
    memcpy(packet + 1, &ping_request_id, sizeof(uint64_t));
    int ret;

    if ((ret = write_packet_TCP_secure_connection(packet, sizeof(packet), 1)) == 1) {
        ping_request_id = 0;
    }

    return ret;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Client_Connection::send_ping_response()
{
    if (!ping_response_id)
        return 1;

    uint8_t packet[1 + sizeof(uint64_t)];
    packet[0] = TCP_PACKET_PONG;
    memcpy(packet + 1, &ping_response_id, sizeof(uint64_t));
    int ret;

    if ((ret = write_packet_TCP_secure_connection(packet, sizeof(packet), 1)) == 1) {
        ping_response_id = 0;
    }

    return ret;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Client_Connection::send_disconnect_request(uint8_t con_id)
{
    if (con_id >= NUM_CLIENT_CONNECTIONS)
        return -1;

    connections[con_id].status = ClientToClientConnectionStatus::NOT_USED;
    connections[con_id].number = 0;
    
    uint8_t packet[1 + 1];
    packet[0] = TCP_PACKET_DISCONNECT_NOTIFICATION;
    packet[1] = con_id + NUM_RESERVED_PORTS;
    return write_packet_TCP_secure_connection(packet, sizeof(packet), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Client_Connection::send_onion_request(const uint8_t *data, uint16_t length)
{
    OutputBuffer packet;
    packet.write_byte(TCP_PACKET_ONION_REQUEST);
    packet.write_bytes(data, data + length);
    
    return write_packet_TCP_secure_connection(packet.begin(), packet.size(), 0);
}

/* Create new TCP connection to ip_port/public_key
 */
TCP_Client_Connection::TCP_Client_Connection(IPPort ip_port, const PublicKey &public_key, const PublicKey &self_public_key,
        const SecretKey &self_secret_key, TCP_Proxy_Info *proxy_info)
{
    if (networking_at_startup() != 0) {
        throw std::runtime_error("Network startup error");
    }

    if (ip_port.ip.family != Family::FAMILY_AF_INET && ip_port.ip.family != Family::FAMILY_AF_INET6)
    {
        throw std::runtime_error("Invalid IP family");
    }

    Family family = ip_port.ip.family;

    TCP_Proxy_Info default_proxyinfo;

    if (proxy_info == NULL) {
        default_proxyinfo.proxy_type = TCP_PROXY_TYPE::TCP_PROXY_NONE;
        proxy_info = &default_proxyinfo;
    }

    if (proxy_info->proxy_type != TCP_PROXY_TYPE::TCP_PROXY_NONE) {
        family = proxy_info->ip_port.ip.family;
    }

    sock = socket((int) family, SOCK_STREAM, IPPROTO_TCP);

    if (!sock_valid(sock)) {
        throw std::runtime_error("Open socket error");
    }

    if (!set_socket_nosigpipe(sock)) {
        kill_sock(sock);
        throw std::runtime_error("Set socket nosigpipe error");
    }

    if (!(set_socket_nonblock(sock) && connect_sock_to(sock, ip_port, proxy_info))) {
        kill_sock(sock);
        throw std::runtime_error("Set socket nonblock or connect error");
    }

    this->public_key = public_key;
    this->self_public_key = self_public_key;
    this->shared_key = compute_shared_key(public_key, self_secret_key);
    this->ip_port = ip_port;
    this->proxy_info = *proxy_info;

    switch (proxy_info->proxy_type) {
        case TCP_PROXY_TYPE::TCP_PROXY_HTTP:
            this->status = ClientToServerConnectionStatus::TCP_CLIENT_PROXY_HTTP_CONNECTING;
            proxy_http_generate_connection_request();
            break;

        case TCP_PROXY_TYPE::TCP_PROXY_SOCKS5:
            this->status = ClientToServerConnectionStatus::TCP_CLIENT_PROXY_SOCKS5_CONNECTING;
            proxy_socks5_generate_handshake();
            break;

        case TCP_PROXY_TYPE::TCP_PROXY_NONE:
            this->status = ClientToServerConnectionStatus::TCP_CLIENT_CONNECTING;

            if (generate_handshake() == -1) {
                kill_sock(sock);
                throw std::runtime_error("Generate handshake error");
            }

            break;
    }

    this->kill_at = unix_time() + TCP_CONNECTION_TIMEOUT;
}

/* return 0 on success
 * return -1 on failure
 */
int TCP_Client_Connection::handle_TCP_packet(const uint8_t *data, uint16_t length)
{
    if (length <= 1)
        return -1;

    switch (data[0]) {
        case TCP_PACKET_ROUTING_RESPONSE: {
            if (length != 1 + 1 + crypto_box_PUBLICKEYBYTES)
                return -1;

            if (data[1] < NUM_RESERVED_PORTS)
                return 0;

            uint8_t con_id = data[1] - NUM_RESERVED_PORTS;

            if (connections[con_id].status != ClientToClientConnectionStatus::NOT_USED)
                return 0;

            connections[con_id].status = ClientToClientConnectionStatus::OFFLINE;
            connections[con_id].number = ~0;
            connections[con_id].public_key = PublicKey(data + 2);

            if (event_listener)
                event_listener->on_response(this, con_id, connections[con_id].public_key);
            
            return 0;
        }

        case TCP_PACKET_CONNECTION_NOTIFICATION: {
            if (length != 1 + 1)
                return -1;

            if (data[1] < NUM_RESERVED_PORTS)
                return -1;

            uint8_t con_id = data[1] - NUM_RESERVED_PORTS;

            if (connections[con_id].status != ClientToClientConnectionStatus::OFFLINE)
                return 0;

            connections[con_id].status = ClientToClientConnectionStatus::ONLINE;

            if (event_listener)
                event_listener->on_status(this, connections[con_id].number, con_id,
                                      connections[con_id].status);

            return 0;
        }

        case TCP_PACKET_DISCONNECT_NOTIFICATION: {
            if (length != 1 + 1)
                return -1;

            if (data[1] < NUM_RESERVED_PORTS)
                return -1;

            uint8_t con_id = data[1] - NUM_RESERVED_PORTS;

            if (connections[con_id].status == ClientToClientConnectionStatus::NOT_USED)
                return 0;

            if (connections[con_id].status != ClientToClientConnectionStatus::ONLINE)
                return 0;

            connections[con_id].status = ClientToClientConnectionStatus::OFFLINE;

            if (event_listener)
                event_listener->on_status(this, connections[con_id].number, con_id,
                                      connections[con_id].status);
                
            return 0;
        }

        case TCP_PACKET_PING: {
            if (length != 1 + sizeof(uint64_t))
                return -1;

            uint64_t ping_id;
            memcpy(&ping_id, data + 1, sizeof(uint64_t));
            ping_response_id = ping_id;
            send_ping_response();
            return 0;
        }

        case TCP_PACKET_PONG: {
            if (length != 1 + sizeof(uint64_t))
                return -1;

            uint64_t ping_id;
            memcpy(&ping_id, data + 1, sizeof(uint64_t));

            if (ping_id) {
                if (ping_id == this->ping_id) {
                    this->ping_id = 0;
                }

                return 0;
            } else {
                return -1;
            }
        }

        case TCP_PACKET_OOB_RECV: {
            if (length <= 1 + crypto_box_PUBLICKEYBYTES)
                return -1;

            if (event_listener)
                event_listener->on_oob_data(this, PublicKey(data + 1), data + 1 + crypto_box_PUBLICKEYBYTES,
                                        length - (1 + crypto_box_PUBLICKEYBYTES));
            return 0;
        }

        case TCP_PACKET_ONION_RESPONSE: {
            if (event_listener)
                event_listener->on_onion(this, data + 1, length - 1);
            return 0;
        }

        default: {
            if (data[0] < NUM_RESERVED_PORTS)
                return -1;

            uint8_t con_id = data[0] - NUM_RESERVED_PORTS;

            if (event_listener)
                event_listener->on_data(this, connections[con_id].number, con_id, data + 1, length - 1);
        }
    }

    return 0;
}

int TCP_Client_Connection::do_confirmed_TCP()
{
    send_pending_data();
    send_ping_response();
    send_ping_request();

    uint8_t packet[MAX_PACKET_SIZE];
    int len;

    if (is_timeout(last_pinged, TCP_PING_FREQUENCY)) {
        uint64_t ping_id = random_64b();

        if (!ping_id)
            ++ping_id;

        ping_request_id = this->ping_id = ping_id;
        send_ping_request();
        last_pinged = unix_time();
    }

    if (ping_id && is_timeout(last_pinged, TCP_PING_TIMEOUT)) {
        status = ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED;
        return 0;
    }

    while ((len = read_packet_TCP_secure_connection(sock, &next_packet_length, shared_key,
                  recv_nonce, packet, sizeof(packet)))) {
        if (len == -1) {
            status = ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED;
            break;
        }

        if (handle_TCP_packet(packet, len) == -1) {
            status = ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED;
            break;
        }
    }

    return 0;
}

/* Run the TCP connection
 */
void TCP_Client_Connection::do_TCP_connection()
{
    unix_time_update();

    if (status == ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED) {
        return;
    }

    if (status == ClientToServerConnectionStatus::TCP_CLIENT_PROXY_HTTP_CONNECTING) {
        if (send_pending_data()) {
            int ret = proxy_http_read_connection_response();

            if (ret == -1) {
                kill_at = 0;
                status = ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED;
            }

            if (ret == 1) {
                generate_handshake();
                status = ClientToServerConnectionStatus::TCP_CLIENT_CONNECTING;
            }
        }
    }

    if (status == ClientToServerConnectionStatus::TCP_CLIENT_PROXY_SOCKS5_CONNECTING) {
        if (send_pending_data()) {
            int ret = socks5_read_handshake_response();

            if (ret == -1) {
                kill_at = 0;
                status = ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED;
            }

            if (ret == 1) {
                proxy_socks5_generate_connection_request();
                status = ClientToServerConnectionStatus::TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED;
            }
        }
    }

    if (status == ClientToServerConnectionStatus::TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED) {
        if (send_pending_data()) {
            int ret = proxy_socks5_read_connection_response();

            if (ret == -1) {
                kill_at = 0;
                status = ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED;
            }

            if (ret == 1) {
                generate_handshake();
                status = ClientToServerConnectionStatus::TCP_CLIENT_CONNECTING;
            }
        }
    }

    if (status == ClientToServerConnectionStatus::TCP_CLIENT_CONNECTING) {
        if (send_pending_data()) {
            status = ClientToServerConnectionStatus::TCP_CLIENT_UNCONFIRMED;
        }
    }

    if (status == ClientToServerConnectionStatus::TCP_CLIENT_UNCONFIRMED) {
        uint8_t data[TCP_SERVER_HANDSHAKE_SIZE];
        int len = read_TCP_packet(sock, data, sizeof(data));

        if (sizeof(data) == len) {
            if (handle_handshake(data) == 0) {
                kill_at = ~0;
                status = ClientToServerConnectionStatus::TCP_CLIENT_CONFIRMED;
            } else {
                kill_at = 0;
                status = ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED;
            }
        }
    }

    if (status == ClientToServerConnectionStatus::TCP_CLIENT_CONFIRMED) {
        do_confirmed_TCP();
    }

    if (kill_at <= unix_time()) {
        status = ClientToServerConnectionStatus::TCP_CLIENT_DISCONNECTED;
    }
}

/* Kill the TCP connection
 */
TCP_Client_Connection::~TCP_Client_Connection()
{
    kill_sock(sock);
}
