/*
* TCP_server.c -- Implementation of the TCP relay server part of Tox.
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

#include "TCP_server.hpp"

#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <sys/ioctl.h>
#endif

#include "util.hpp"
#include "protocol_impl.hpp"
#include <cassert>
#include <tuple>

using namespace bitox;
using namespace bitox::network;
using namespace bitox::impl;

/* return 1 on success
 * return 0 on failure
 */
static int bind_to_port(sock_t sock, int family, uint16_t port)
{
    struct sockaddr_storage addr = {0};
    size_t addrsize;

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
    } else {
        return 0;
    }

    return (bind(sock, (struct sockaddr *)&addr, addrsize) == 0);
}

/* return index corresponding to connection with peer on success
 * return -1 on failure.
 */
int TCP_Server::get_TCP_connection_index(const PublicKey &public_key)
{
    auto it = accepted_key_list.find(public_key);
    if (it == accepted_key_list.end())
        return -1;
    
    return it->second;
}


/* Add accepted TCP connection to the list.
 *
 * return index on success
 * return -1 on failure
 */
int TCP_Server::add_accepted(const TCP_Secure_Connection *con)
{
    int index = get_TCP_connection_index(con->client_dht_public_key);

    if (index != -1) { /* If an old connection to the same public key exists, kill it. */
        kill_accepted(index);
        index = -1;
    }

    if (accepted_connection_array.size() == num_accepted_connections) {
        accepted_connection_array.resize(accepted_connection_array.size() + 4);
        index = num_accepted_connections;
    } else {
        uint32_t i;

        for (i = accepted_connection_array.size(); i != 0; --i) {
            if (accepted_connection_array[i - 1].status == TCP_Secure_Connection_Status::TCP_STATUS_NO_STATUS) {
                index = i - 1;
                break;
            }
        }
    }

    if (index == -1) {
        fprintf(stderr, "FAIL index is -1\n");
        return -1;
    }

    if (accepted_key_list.count(con->client_dht_public_key))
        return -1;
    
    accepted_key_list[con->client_dht_public_key] = index;

    memcpy(&accepted_connection_array[index], con, sizeof(TCP_Secure_Connection));
    accepted_connection_array[index].status = TCP_Secure_Connection_Status::TCP_STATUS_CONFIRMED;
    ++num_accepted_connections;
    accepted_connection_array[index].identifier = ++counter;
    accepted_connection_array[index].last_pinged = unix_time();
    accepted_connection_array[index].ping_id = 0;

    return index;
}

/* Delete accepted connection from list.
 *
 * return 0 on success
 * return -1 on failure
 */
int TCP_Server::del_accepted(int index)
{
    if ((uint32_t)index >= accepted_connection_array.size())
        return -1;

    if (accepted_connection_array[index].status == TCP_Secure_Connection_Status::TCP_STATUS_NO_STATUS)
        return -1;

    auto it = accepted_key_list.find(accepted_connection_array[index].client_dht_public_key);
    if (it == accepted_key_list.end() || it->second != index) // TODO is the index check required?
        return -1;
    
    accepted_key_list.erase(it);

    sodium_memzero(&accepted_connection_array[index], sizeof(TCP_Secure_Connection));
    --num_accepted_connections;

    if (num_accepted_connections == 0)
        accepted_connection_array.clear();

    return 0;
}

/* return the amount of data in the tcp recv buffer.
 * return 0 on failure.
 */
unsigned int TCP_socket_data_recv_buffer(sock_t sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    unsigned long count = 0;
    ioctlsocket(sock, FIONREAD, &count);
#else
    int count = 0;
    ioctl(sock, FIONREAD, &count);
#endif

    return count;
}

/* Read the next two bytes in TCP stream then convert them to
 * length (host byte order).
 *
 * return length on success
 * return 0 if nothing has been read from socket.
 * return ~0 on failure.
 */
uint16_t read_TCP_length(sock_t sock)
{
    unsigned int count = TCP_socket_data_recv_buffer(sock);

    if (count >= sizeof(uint16_t)) {
        uint16_t length;
        int len = recv(sock, (uint8_t *)&length, sizeof(uint16_t), MSG_NOSIGNAL);

        if (len != sizeof(uint16_t)) {
            fprintf(stderr, "FAIL recv packet\n");
            return 0;
        }

        length = ntohs(length);

        if (length > MAX_PACKET_SIZE) {
            return ~0;
        }

        return length;
    }

    return 0;
}

/* Read length bytes from socket.
 *
 * return length on success
 * return -1 on failure/no data in buffer.
 */
int read_TCP_packet(sock_t sock, uint8_t *data, uint16_t length)
{
    unsigned int count = TCP_socket_data_recv_buffer(sock);

    if (count >= length) {
        int len = recv(sock, data, length, MSG_NOSIGNAL);

        if (len != length) {
            fprintf(stderr, "FAIL recv packet\n");
            return -1;
        }

        return len;
    }

    return -1;
}

/* return length of received packet on success.
 * return 0 if could not read any packet.
 * return -1 on failure (connection must be killed).
 */
int read_packet_TCP_secure_connection(sock_t sock, uint16_t *next_packet_length, const bitox::SharedKey &shared_key,
                                      Nonce &recv_nonce, uint8_t *data, uint16_t max_len)
{
    if (*next_packet_length == 0) {
        uint16_t len = read_TCP_length(sock);

        if (len == (uint16_t)~0)
            return -1;

        if (len == 0)
            return 0;

        *next_packet_length = len;
    }

    if (max_len + crypto_box_MACBYTES < *next_packet_length)
        return -1;

    uint8_t data_encrypted[*next_packet_length];
    int len_packet = read_TCP_packet(sock, data_encrypted, *next_packet_length);

    if (len_packet != *next_packet_length)
        return 0;

    *next_packet_length = 0;

    int len = decrypt_data_symmetric(shared_key.data.data(), recv_nonce.data.data(), data_encrypted, len_packet, data);

    if (len + crypto_box_MACBYTES != len_packet)
        return -1;

    ++recv_nonce;

    return len;
}

/* return 0 if pending data was sent completely
 * return -1 if it wasn't
 */
bool TCP_Secure_Connection::send_pending_data_nonpriority()
{
    if (last_packet_length == 0) {
        return true;
    }

    uint16_t left = last_packet_length - last_packet_sent;
    int len = send(sock, last_packet + last_packet_sent, left, MSG_NOSIGNAL);

    if (len <= 0)
        return false;

    if (len == left) {
        last_packet_length = 0;
        last_packet_sent = 0;
        return true;
    }

    last_packet_sent += len;
    return false;

}

/* return true if pending data was sent completely
 * return false if it wasn't
 */
bool TCP_Secure_Connection::send_pending_data()
{
    /* finish sending current non-priority packet */
    if (!send_pending_data_nonpriority()) {
        return false;
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

/* return 0 on failure (only if malloc fails)
 * return 1 on success
 */
void TCP_Secure_Connection::add_priority(const uint8_t *packet, size_t size, size_t sent)
{
    assert(size && "Size must not be 0");
    assert((sent < size) && "sent must be less than size");
    
    priority_queue.emplace_back(packet, size, sent);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Secure_Connection::write_packet_TCP_secure_connection(const uint8_t *data, uint16_t length, bool priority)
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
        return 0;
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

/* Kill a TCP_Secure_Connection
 */
static void kill_TCP_connection(TCP_Secure_Connection *con)
{
    kill_sock(con->sock);
    sodium_memzero(con, sizeof(TCP_Secure_Connection));
}

/* Kill an accepted TCP_Secure_Connection
 *
 * return -1 on failure.
 * return 0 on success.
 */
int TCP_Server::kill_accepted(int index)
{
    if ((uint32_t)index >= accepted_connection_array.size())
        return -1;

    uint32_t i;

    for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        rm_connection_index(&accepted_connection_array[index], i);
    }

    sock_t sock = accepted_connection_array[index].sock;

    if (del_accepted(index) != 0)
        return -1;

    kill_sock(sock);
    return 0;
}

/* return 1 if everything went well.
 * return -1 if the connection must be killed.
 */
int TCP_Secure_Connection::handle_TCP_handshake(const uint8_t *data, uint16_t length,
                                const SecretKey &self_secret_key)
{
    if (length != TCP_CLIENT_HANDSHAKE_SIZE)
        return -1;

    if (status != TCP_Secure_Connection_Status::TCP_STATUS_CONNECTED)
        return -1;

    InputBuffer input_packet(data, length);
    
    Nonce input_packet_nonce = Nonce::create_empty();
    if ((input_packet >> client_dht_public_key >> input_packet_nonce).fail())
        return -1;
    
    SharedKey shared_key = ::compute_shared_key(client_dht_public_key, self_secret_key);
    
    Buffer decrypted_input_packet;
    if (!::decrypt_buffer(input_packet.get_buffer_data(), shared_key, input_packet_nonce, decrypted_input_packet))
        return -1;
    
    PublicKey client_key;
    InputBuffer decrypted_buffer(std::move(decrypted_input_packet));
    if ((decrypted_buffer >> client_key >> recv_nonce).fail())
        return -1;
    
    SecretKey temp_secret_key;
    PublicKey temp_public_key;
    std::tie(temp_public_key, temp_secret_key) = generate_keys();
    this->shared_key = ::compute_shared_key(client_key, temp_secret_key);
    
    sent_nonce = Nonce::create_random();
    
    OutputBuffer data_to_encrypt;
    data_to_encrypt << temp_public_key << sent_nonce;
    
    Nonce temp_nonce = Nonce::create_random();
    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    new_nonce(response);

    Buffer encrypted_data;
    if (!encrypt_buffer(data_to_encrypt.get_buffer_data(), shared_key, temp_nonce, encrypted_data))
        return -1;
    
    OutputBuffer output_packet;
    output_packet << temp_nonce << encrypted_data;
    
    if (TCP_SERVER_HANDSHAKE_SIZE != send(sock, output_packet.begin(), output_packet.size(), MSG_NOSIGNAL))
        return -1;

    status = TCP_Secure_Connection_Status::TCP_STATUS_UNCONFIRMED;
    return 1;
}

/* return 1 if connection handshake was handled correctly.
 * return 0 if we didn't get it yet.
 * return -1 if the connection must be killed.
 */
int TCP_Secure_Connection::read_connection_handshake(const SecretKey &self_secret_key)
{
    uint8_t data[TCP_CLIENT_HANDSHAKE_SIZE];
    int len = 0;

    if ((len = read_TCP_packet(sock, data, TCP_CLIENT_HANDSHAKE_SIZE)) != -1) {
        return handle_TCP_handshake(data, len, self_secret_key);
    }

    return 0;
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Secure_Connection::send_routing_response(uint8_t rpid, const PublicKey &public_key)
{
    OutputBuffer buffer;
    buffer.write_byte(TCP_PACKET_ROUTING_RESPONSE);
    buffer.write_byte(rpid);
    buffer << public_key;

    return write_packet_TCP_secure_connection(buffer.begin(), buffer.size(), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Secure_Connection::send_connect_notification(uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_CONNECTION_NOTIFICATION, id + NUM_RESERVED_PORTS};
    return write_packet_TCP_secure_connection(data, sizeof(data), 1);
}

/* return 1 on success.
 * return 0 if could not send packet.
 * return -1 on failure (connection must be killed).
 */
int TCP_Secure_Connection::send_disconnect_notification(uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_DISCONNECT_NOTIFICATION, id + NUM_RESERVED_PORTS};
    return write_packet_TCP_secure_connection(data, sizeof(data), 1);
}

/* return 0 on success.
 * return -1 on failure (connection must be killed).
 */
int TCP_Server::handle_TCP_routing_req(uint32_t con_id, const PublicKey &public_key)
{
    uint32_t i;
    uint32_t index = ~0;
    TCP_Secure_Connection *con = &accepted_connection_array[con_id];

    /* If person tries to cennect to himself we deny the request*/
    if (con->client_dht_public_key == public_key) {
        if (con->send_routing_response(0, public_key) == -1)
            return -1;

        return 0;
    }

    for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        if (con->connections[i].status != ClientToClientConnectionStatus::NOT_USED) {
            if (public_key == con->connections[i].client_dht_public_key) {
                if (con->send_routing_response(i + NUM_RESERVED_PORTS, public_key) == -1) {
                    return -1;
                } else {
                    return 0;
                }
            }
        } else if (index == (uint32_t)~0) {
            index = i;
        }
    }

    if (index == (uint32_t)~0) {
        if (con->send_routing_response(0, public_key) == -1)
            return -1;

        return 0;
    }

    int ret = con->send_routing_response(index + NUM_RESERVED_PORTS, public_key);

    if (ret == 0)
        return 0;

    if (ret == -1)
        return -1;

    con->connections[index].status = ClientToClientConnectionStatus::OFFLINE;
    con->connections[index].client_dht_public_key = public_key;
    int other_index = get_TCP_connection_index(public_key);

    if (other_index != -1) {
        uint32_t other_id = ~0;
        TCP_Secure_Connection *other_conn = &accepted_connection_array[other_index];

        for (i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
            if (other_conn->connections[i].status == ClientToClientConnectionStatus::OFFLINE
                    && other_conn->connections[i].client_dht_public_key == con->client_dht_public_key) {
                other_id = i;
                break;
            }
        }

        if (other_id != (uint32_t)~0) {
            con->connections[index].status = ClientToClientConnectionStatus::ONLINE;
            con->connections[index].index = other_index;
            con->connections[index].other_id = other_id;
            other_conn->connections[other_id].status = ClientToClientConnectionStatus::ONLINE;
            other_conn->connections[other_id].index = con_id;
            other_conn->connections[other_id].other_id = index;
            //TODO: return values?
            con->send_connect_notification(index);
            other_conn->send_connect_notification(other_id);
        }
    }

    return 0;
}

/* return 0 on success.
 * return -1 on failure (connection must be killed).
 */
int TCP_Server::handle_TCP_oob_send(uint32_t con_id, const PublicKey &public_key, const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH)
        return -1;

    TCP_Secure_Connection *con = &accepted_connection_array[con_id];

    int other_index = get_TCP_connection_index(public_key);

    if (other_index != -1) {
        OutputBuffer resp_packet;
        resp_packet.write_byte(TCP_PACKET_OOB_RECV);
        resp_packet << con->client_dht_public_key;
        resp_packet.write_bytes(data, data + length);
        accepted_connection_array[other_index].write_packet_TCP_secure_connection(resp_packet.begin(), resp_packet.size(), 0);
    }

    return 0;
}

/* Remove connection with con_number from the connections array of con.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int TCP_Server::rm_connection_index(TCP_Secure_Connection *con, uint8_t con_number)
{
    if (con_number >= NUM_CLIENT_CONNECTIONS)
        return -1;

    if (con->connections[con_number].status != ClientToClientConnectionStatus::NOT_USED) {
        uint32_t index = con->connections[con_number].index;
        uint8_t other_id = con->connections[con_number].other_id;

        if (con->connections[con_number].status == ClientToClientConnectionStatus::ONLINE) {

            if (index >= accepted_connection_array.size())
                return -1;

            accepted_connection_array[index].connections[other_id].other_id = 0;
            accepted_connection_array[index].connections[other_id].index = 0;
            accepted_connection_array[index].connections[other_id].status = ClientToClientConnectionStatus::OFFLINE;
            //TODO: return values?
            accepted_connection_array[index].send_disconnect_notification(other_id);
        }

        con->connections[con_number].index = 0;
        con->connections[con_number].other_id = 0;
        con->connections[con_number].status = ClientToClientConnectionStatus::NOT_USED;
        return 0;
    } else {
        return -1;
    }
}

static int handle_onion_recv_1(void *object, const IPPort &dest, const uint8_t *data, uint16_t length)
{
    TCP_Server *TCP_server = (TCP_Server *) object;
    uint32_t index = dest.onion_ip.con_id;

    if (index >= TCP_server->accepted_connection_array.size())
        return 1;

    TCP_Secure_Connection *con = &TCP_server->accepted_connection_array[index];

    if (con->identifier != dest.onion_ip.identifier)
        return 1;

    OutputBuffer packet;
    packet.write_byte(TCP_PACKET_ONION_RESPONSE);
    packet.write_bytes(data, data + length);

    if (con->write_packet_TCP_secure_connection(packet.begin(), packet.size(), 0) != 1)
        return 1;

    return 0;
}

/* return 0 on success
 * return -1 on failure
 */
int TCP_Server::handle_TCP_packet(uint32_t con_id, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    TCP_Secure_Connection *con = &accepted_connection_array[con_id];

    switch (data[0]) {
        case TCP_PACKET_ROUTING_REQUEST: {
            if (length != 1 + crypto_box_PUBLICKEYBYTES)
                return -1;

            return handle_TCP_routing_req(con_id, PublicKey(data + 1));
        }

        case TCP_PACKET_CONNECTION_NOTIFICATION: {
            if (length != 2)
                return -1;

            break;
        }

        case TCP_PACKET_DISCONNECT_NOTIFICATION: {
            if (length != 2)
                return -1;

            return rm_connection_index(con, data[1] - NUM_RESERVED_PORTS);
        }

        case TCP_PACKET_PING: {
            if (length != 1 + sizeof(uint64_t))
                return -1;

            uint8_t response[1 + sizeof(uint64_t)];
            response[0] = TCP_PACKET_PONG;
            memcpy(response + 1, data + 1, sizeof(uint64_t));
            con->write_packet_TCP_secure_connection(response, sizeof(response), 1);
            return 0;
        }

        case TCP_PACKET_PONG: {
            if (length != 1 + sizeof(uint64_t))
                return -1;

            uint64_t ping_id;
            memcpy(&ping_id, data + 1, sizeof(uint64_t));

            if (ping_id) {
                if (ping_id == con->ping_id) {
                    con->ping_id = 0;
                }

                return 0;
            } else {
                return -1;
            }
        }

        case TCP_PACKET_OOB_SEND: {
            if (length <= 1 + crypto_box_PUBLICKEYBYTES)
                return -1;

            return handle_TCP_oob_send(con_id, PublicKey(data + 1), data + 1 + crypto_box_PUBLICKEYBYTES,
                                       length - (1 + crypto_box_PUBLICKEYBYTES));
        }

        case TCP_PACKET_ONION_REQUEST: {
            if (onion) {
                if (length <= 1 + crypto_box_NONCEBYTES + ONION_SEND_BASE * 2)
                    return -1;

                IPPort source;
                source.port = 0;  // dummy initialise
                source.ip.family = Family::FAMILY_TCP_ONION_FAMILY;
                source.onion_ip.con_id = con_id;
                source.onion_ip.identifier = con->identifier;
                onion_send_1(onion, data + 1 + crypto_box_NONCEBYTES, length - (1 + crypto_box_NONCEBYTES), source,
                             data + 1);
            }

            return 0;
        }

        case TCP_PACKET_ONION_RESPONSE: {
            return -1;
        }

        default: {
            if (data[0] < NUM_RESERVED_PORTS)
                return -1;

            uint8_t c_id = data[0] - NUM_RESERVED_PORTS;

            if (c_id >= NUM_CLIENT_CONNECTIONS)
                return -1;

            if (con->connections[c_id].status == ClientToClientConnectionStatus::NOT_USED)
                return -1;

            if (con->connections[c_id].status != ClientToClientConnectionStatus::ONLINE)
                return 0;

            uint32_t index = con->connections[c_id].index;
            uint8_t other_c_id = con->connections[c_id].other_id + NUM_RESERVED_PORTS;
            uint8_t new_data[length];
            memcpy(new_data, data, length);
            new_data[0] = other_c_id;
            int ret = accepted_connection_array[index].write_packet_TCP_secure_connection(new_data, length, 0);

            if (ret == -1)
                return -1;

            return 0;
        }
    }

    return 0;
}


int TCP_Server::confirm_TCP_connection(TCP_Secure_Connection *con, const uint8_t *data,
                                  uint16_t length)
{
    int index = add_accepted(con);

    if (index == -1) {
        kill_TCP_connection(con);
        return -1;
    }

    sodium_memzero(con, sizeof(TCP_Secure_Connection));

    if (handle_TCP_packet(index, data, length) == -1) {
        kill_accepted(index);
        return -1;
    }

    return index;
}

/* return index on success
 * return -1 on failure
 */
int TCP_Server::accept_connection(sock_t sock)
{
    if (!sock_valid(sock))
        return -1;

    if (!set_socket_nonblock(sock)) {
        kill_sock(sock);
        return -1;
    }

    if (!set_socket_nosigpipe(sock)) {
        kill_sock(sock);
        return -1;
    }

    uint16_t index = incomming_connection_queue_index % MAX_INCOMMING_CONNECTIONS;

    TCP_Secure_Connection *conn = &incomming_connection_queue[index];

    if (conn->status != TCP_Secure_Connection_Status::TCP_STATUS_NO_STATUS)
        kill_TCP_connection(conn);

    conn->status = TCP_Secure_Connection_Status::TCP_STATUS_CONNECTED;
    conn->sock = sock;
    conn->next_packet_length = 0;

    ++incomming_connection_queue_index;
    return index;
}

static sock_t new_listening_TCP_socket(int family, uint16_t port)
{
    sock_t sock = socket(family, SOCK_STREAM, IPPROTO_TCP);

    if (!sock_valid(sock)) {
        return ~0;
    }

    int ok = set_socket_nonblock(sock);

    if (ok && family == AF_INET6) {
        ok = set_socket_dualstack(sock);
    }

    if (ok) {
        ok = set_socket_reuseaddr(sock);
    }

    ok = ok && bind_to_port(sock, family, port) && (listen(sock, TCP_MAX_BACKLOG) == 0);

    if (!ok) {
        kill_sock(sock);
        return ~0;
    }

    return sock;
}

TCP_Server::TCP_Server(uint8_t ipv6_enabled, uint16_t num_sockets, const uint16_t *ports, const bitox::SecretKey &secret_key,
                           Onion *onion)
{
    assert(num_sockets && "num_sockets is 0");
    assert(ports && "ports is null");
    
    if (networking_at_startup() != 0)
    {
        throw std::runtime_error("Networking statup error");
    }

#ifdef TCP_SERVER_USE_EPOLL
    efd = epoll_create(8);

    if (efd == -1) {
        throw std::runtime_error("epoll_create error");
    }

#endif

    uint8_t family = ipv6_enabled ? AF_INET6 : AF_INET;

#ifdef TCP_SERVER_USE_EPOLL
    struct epoll_event ev;
#endif

    for (int i = 0; i < num_sockets; ++i) {
        sock_t sock = new_listening_TCP_socket(family, ports[i]);

        if (sock_valid(sock)) {
#ifdef TCP_SERVER_USE_EPOLL
            ev.events = EPOLLIN | EPOLLET;
            ev.data.u64 = sock | ((uint64_t)TCP_SOCKET_LISTENING << 32);

            if (epoll_ctl(efd, EPOLL_CTL_ADD, sock, &ev) == -1) {
                continue;
            }

#endif

            socks_listening.push_back(sock);
        }
    }

    if (socks_listening.empty()) {
        throw std::runtime_error("Fail to create listening sockets");
    }

    if (onion) {
        this->onion = onion;
        set_callback_handle_recv_1(onion, &handle_onion_recv_1, this);
    }

    this->secret_key = secret_key;
    crypto_scalarmult_curve25519_base(public_key.data.data(), secret_key.data.data());
}

void TCP_Server::do_TCP_accept_new()
{
    uint32_t i;

    for (i = 0; i < socks_listening.size(); ++i) {
        struct sockaddr_storage addr;
        unsigned int addrlen = sizeof(addr);
        sock_t sock;

        do {
            sock = accept(socks_listening[i], (struct sockaddr *)&addr, &addrlen);
        } while (accept_connection(sock) != -1);
    }
}

int TCP_Server::do_incoming(uint32_t i)
{
    if (incomming_connection_queue[i].status != TCP_Secure_Connection_Status::TCP_STATUS_CONNECTED)
        return -1;

    int ret = incomming_connection_queue[i].read_connection_handshake(secret_key);

    if (ret == -1) {
        kill_TCP_connection(&incomming_connection_queue[i]);
    } else if (ret == 1) {
        int index_new = unconfirmed_connection_queue_index % MAX_INCOMMING_CONNECTIONS;
        TCP_Secure_Connection *conn_old = &incomming_connection_queue[i];
        TCP_Secure_Connection *conn_new = &unconfirmed_connection_queue[index_new];

        if (conn_new->status != TCP_Secure_Connection_Status::TCP_STATUS_NO_STATUS)
            kill_TCP_connection(conn_new);

        *conn_new = *conn_old;
        sodium_memzero(conn_old, sizeof(TCP_Secure_Connection));
        ++unconfirmed_connection_queue_index;

        return index_new;
    }

    return -1;
}

int TCP_Server::do_unconfirmed(uint32_t i)
{
    TCP_Secure_Connection *conn = &unconfirmed_connection_queue[i];

    if (conn->status != TCP_Secure_Connection_Status::TCP_STATUS_UNCONFIRMED)
        return -1;

    uint8_t packet[MAX_PACKET_SIZE];
    int len = read_packet_TCP_secure_connection(conn->sock, &conn->next_packet_length, conn->shared_key, conn->recv_nonce,
              packet, sizeof(packet));

    if (len == 0) {
        return -1;
    } else if (len == -1) {
        kill_TCP_connection(conn);
        return -1;
    } else {
        return confirm_TCP_connection(conn, packet, len);
    }
}

void TCP_Server::do_confirmed_recv(uint32_t i)
{
    TCP_Secure_Connection *conn = &accepted_connection_array[i];

    uint8_t packet[MAX_PACKET_SIZE];
    int len;

    while ((len = read_packet_TCP_secure_connection(conn->sock, &conn->next_packet_length, conn->shared_key,
                  conn->recv_nonce, packet, sizeof(packet)))) {
        if (len == -1) {
            kill_accepted(i);
            break;
        }

        if (handle_TCP_packet(i, packet, len) == -1) {
            kill_accepted(i);
            break;
        }
    }
}

void TCP_Server::do_TCP_incomming()
{
    uint32_t i;

    for (i = 0; i < MAX_INCOMMING_CONNECTIONS; ++i) {
        do_incoming(i);
    }
}

void TCP_Server::do_TCP_unconfirmed()
{
    uint32_t i;

    for (i = 0; i < MAX_INCOMMING_CONNECTIONS; ++i) {
        do_unconfirmed(i);
    }
}

void TCP_Server::do_TCP_confirmed()
{
#ifdef TCP_SERVER_USE_EPOLL

    if (last_run_pinged == unix_time())
        return;

    last_run_pinged = unix_time();
#endif
    uint32_t i;

    for (i = 0; i < accepted_connection_array.size(); ++i) {
        TCP_Secure_Connection *conn = &accepted_connection_array[i];

        if (conn->status != TCP_Secure_Connection_Status::TCP_STATUS_CONFIRMED)
            continue;

        if (is_timeout(conn->last_pinged, TCP_PING_FREQUENCY)) {
            uint8_t ping[1 + sizeof(uint64_t)];
            ping[0] = TCP_PACKET_PING;
            uint64_t ping_id = random_64b();

            if (!ping_id)
                ++ping_id;

            memcpy(ping + 1, &ping_id, sizeof(uint64_t));
            int ret = conn->write_packet_TCP_secure_connection(ping, sizeof(ping), 1);

            if (ret == 1) {
                conn->last_pinged = unix_time();
                conn->ping_id = ping_id;
            } else {
                if (is_timeout(conn->last_pinged, TCP_PING_FREQUENCY + TCP_PING_TIMEOUT)) {
                    kill_accepted(i);
                    continue;
                }
            }
        }

        if (conn->ping_id && is_timeout(conn->last_pinged, TCP_PING_TIMEOUT)) {
            kill_accepted(i);
            continue;
        }

        conn->send_pending_data();

#ifndef TCP_SERVER_USE_EPOLL

        do_confirmed_recv(i);

#endif
    }
}

#ifdef TCP_SERVER_USE_EPOLL
void TCP_Server::do_TCP_epoll()
{
#define MAX_EVENTS 16
    struct epoll_event events[MAX_EVENTS];
    int nfds;

    while ((nfds = epoll_wait(efd, events, MAX_EVENTS, 0)) > 0) {
        int n;

        for (n = 0; n < nfds; ++n) {
            sock_t sock = events[n].data.u64 & 0xFFFFFFFF;
            int status = (events[n].data.u64 >> 32) & 0xFF, index = (events[n].data.u64 >> 40);

            if ((events[n].events & EPOLLERR) || (events[n].events & EPOLLHUP) || (events[n].events & EPOLLRDHUP)) {
                switch (status) {
                    case TCP_SOCKET_LISTENING: {
                        //should never happen
                        break;
                    }

                    case TCP_SOCKET_INCOMING: {
                        kill_TCP_connection(&incomming_connection_queue[index]);
                        break;
                    }

                    case TCP_SOCKET_UNCONFIRMED: {
                        kill_TCP_connection(&unconfirmed_connection_queue[index]);
                        break;
                    }

                    case TCP_SOCKET_CONFIRMED: {
                        kill_accepted(index);
                        break;
                    }
                }

                continue;
            }


            if (!(events[n].events & EPOLLIN)) {
                continue;
            }

            switch (status) {
                case TCP_SOCKET_LISTENING: {
                    //socket is from socks_listening, accept connection
                    struct sockaddr_storage addr;
                    unsigned int addrlen = sizeof(addr);

                    while (1) {
                        sock_t sock_new = accept(sock, (struct sockaddr *)&addr, &addrlen);

                        if (!sock_valid(sock_new)) {
                            break;
                        }

                        int index_new = accept_connection(sock_new);

                        if (index_new == -1) {
                            continue;
                        }

                        struct epoll_event ev = {
                            .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
                            .data.u64 = sock_new | ((uint64_t)TCP_SOCKET_INCOMING << 32) | ((uint64_t)index_new << 40)
                        };

                        if (epoll_ctl(efd, EPOLL_CTL_ADD, sock_new, &ev) == -1) {
                            kill_TCP_connection(&incomming_connection_queue[index_new]);
                            continue;
                        }
                    }

                    break;
                }

                case TCP_SOCKET_INCOMING: {
                    int index_new;

                    if ((index_new = do_incoming(index)) != -1) {
                        events[n].events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                        events[n].data.u64 = sock | ((uint64_t)TCP_SOCKET_UNCONFIRMED << 32) | ((uint64_t)index_new << 40);

                        if (epoll_ctl(efd, EPOLL_CTL_MOD, sock, &events[n]) == -1) {
                            kill_TCP_connection(&unconfirmed_connection_queue[index_new]);
                            break;
                        }
                    }

                    break;
                }

                case TCP_SOCKET_UNCONFIRMED: {
                    int index_new;

                    if ((index_new = do_unconfirmed(index)) != -1) {
                        events[n].events = EPOLLIN | EPOLLET | EPOLLRDHUP;
                        events[n].data.u64 = sock | ((uint64_t)TCP_SOCKET_CONFIRMED << 32) | ((uint64_t)index_new << 40);

                        if (epoll_ctl(efd, EPOLL_CTL_MOD, sock, &events[n]) == -1) {
                            //remove from confirmed connections
                            kill_accepted(index_new);
                            break;
                        }
                    }

                    break;
                }

                case TCP_SOCKET_CONFIRMED: {
                    do_confirmed_recv(index);
                    break;
                }
            }
        }
    }

#undef MAX_EVENTS
}
#endif

void TCP_Server::do_TCP_server()
{
    unix_time_update();

#ifdef TCP_SERVER_USE_EPOLL
    do_TCP_epoll();

#else
    do_TCP_accept_new();
    do_TCP_incomming();
    do_TCP_unconfirmed();
#endif

    do_TCP_confirmed();
}

TCP_Server::~TCP_Server()
{
    uint32_t i;

    for (i = 0; i < socks_listening.size(); ++i) {
        kill_sock(socks_listening[i]);
    }

    if (onion) {
        set_callback_handle_recv_1(onion, NULL, NULL);
    }

#ifdef TCP_SERVER_USE_EPOLL
    close(efd);
#endif
}
