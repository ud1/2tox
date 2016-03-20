/* net_crypto.c
 *
 * Functions for the core network crypto.
 *
 * NOTE: This code has to be perfect. We don't mess around with encryption.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
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

#include "net_crypto.hpp"
#include "util.hpp"
#include "math.h"
#include "logger.hpp"

#include "protocol_impl.hpp"
#include "event_dispatcher.hpp"

using namespace bitox;
using namespace bitox::network;
using namespace bitox::impl;

uint8_t Net_Crypto::crypt_connection_id_not_valid(int crypt_connection_id) const
{
    auto it = crypto_connections.find(crypt_connection_id);
    if (it == crypto_connections.end())
        return 1;

//    if (this->crypto_connections[crypt_connection_id]->status == CryptoConnectionStatus::CRYPTO_CONN_NO_CONNECTION)
//        return 1;

    return 0;
}

/* cookie timeout in seconds */
constexpr long COOKIE_TIMEOUT = 15;
constexpr size_t COOKIE_DATA_LENGTH = 2 * PUBLIC_KEY_LEN;
constexpr size_t COOKIE_CONTENTS_LENGTH = sizeof(uint64_t) + COOKIE_DATA_LENGTH;
constexpr size_t COOKIE_LENGTH = NONCE_LEN + COOKIE_CONTENTS_LENGTH + MAC_BYTES_LEN;

constexpr size_t COOKIE_REQUEST_PLAIN_LENGTH = COOKIE_DATA_LENGTH + sizeof(uint64_t);
constexpr size_t COOKIE_REQUEST_LENGTH = 1 + PUBLIC_KEY_LEN + NONCE_LEN + COOKIE_REQUEST_PLAIN_LENGTH + MAC_BYTES_LEN;
constexpr size_t COOKIE_RESPONSE_LENGTH = 1 + NONCE_LEN + COOKIE_LENGTH + sizeof(uint64_t) + MAC_BYTES_LEN;

/* Create a cookie request packet and put it in packet.
 * dht_public_key is the dht public key of the other
 *
 * packet must be of size COOKIE_REQUEST_LENGTH or bigger.
 *
 * return -1 on failure.
 * return COOKIE_REQUEST_LENGTH on success.
 */
int Net_Crypto::create_cookie_request(uint8_t *packet, PublicKey &dht_public_key, uint64_t number,
                                      SharedKey &shared_key) const
{
    uint8_t plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t padding[crypto_box_PUBLICKEYBYTES] = {0};

    memcpy(plain, this->self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    memcpy(plain + crypto_box_PUBLICKEYBYTES, padding, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + (crypto_box_PUBLICKEYBYTES * 2), &number, sizeof(uint64_t));

    this->dht->get_shared_key_sent(shared_key, dht_public_key);
    Nonce nonce = Nonce::create_random();
    packet[0] = NET_PACKET_COOKIE_REQUEST;
    memcpy(packet + 1, this->dht->self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    memcpy(packet + 1 + crypto_box_PUBLICKEYBYTES, nonce.data.data(), crypto_box_NONCEBYTES);
    int len = encrypt_data_symmetric(shared_key.data.data(), nonce.data.data(), plain, sizeof(plain),
                                     packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES)
        return -1;

    return (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + len);
}

/* Create cookie of length COOKIE_LENGTH from bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int create_cookie(uint8_t *cookie, const uint8_t *bytes, const SharedKey &encryption_key)
{
    uint8_t contents[COOKIE_CONTENTS_LENGTH];
    uint64_t temp_time = unix_time();
    memcpy(contents, &temp_time, sizeof(temp_time));
    memcpy(contents + sizeof(temp_time), bytes, COOKIE_DATA_LENGTH);
    new_nonce(cookie);
    int len = encrypt_data_symmetric(encryption_key.data.data(), cookie, contents, sizeof(contents), cookie + crypto_box_NONCEBYTES);

    if (len != COOKIE_LENGTH - crypto_box_NONCEBYTES)
        return -1;

    return 0;
}

/* Open cookie of length COOKIE_LENGTH to bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int open_cookie(uint8_t *bytes, const uint8_t *cookie, const SharedKey &encryption_key)
{
    uint8_t contents[COOKIE_CONTENTS_LENGTH];
    int len = decrypt_data_symmetric(encryption_key.data.data(), cookie, cookie + crypto_box_NONCEBYTES,
                                     COOKIE_LENGTH - crypto_box_NONCEBYTES, contents);

    if (len != sizeof(contents))
        return -1;

    uint64_t cookie_time;
    memcpy(&cookie_time, contents, sizeof(cookie_time));
    uint64_t temp_time = unix_time();

    if (cookie_time + COOKIE_TIMEOUT < temp_time || temp_time < cookie_time)
        return -1;

    memcpy(bytes, contents + sizeof(cookie_time), COOKIE_DATA_LENGTH);
    return 0;
}


/* Create a cookie response packet and put it in packet.
 * request_plain must be COOKIE_REQUEST_PLAIN_LENGTH bytes.
 * packet must be of size COOKIE_RESPONSE_LENGTH or bigger.
 *
 * return -1 on failure.
 * return COOKIE_RESPONSE_LENGTH on success.
 */
int Net_Crypto::create_cookie_response(uint8_t *packet, const uint8_t *request_plain,
                                       const SharedKey &shared_key, const PublicKey &dht_public_key) const
{
    uint8_t cookie_plain[COOKIE_DATA_LENGTH];
    memcpy(cookie_plain, request_plain, crypto_box_PUBLICKEYBYTES);
    memcpy(cookie_plain + crypto_box_PUBLICKEYBYTES, dht_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];

    if (create_cookie(plain, cookie_plain, this->secret_symmetric_key) != 0)
        return -1;

    memcpy(plain + COOKIE_LENGTH, request_plain + COOKIE_DATA_LENGTH, sizeof(uint64_t));
    packet[0] = NET_PACKET_COOKIE_RESPONSE;
    new_nonce(packet + 1);
    int len = encrypt_data_symmetric(shared_key.data.data(), packet + 1, plain, sizeof(plain), packet + 1 + crypto_box_NONCEBYTES);

    if (len != COOKIE_RESPONSE_LENGTH - (1 + crypto_box_NONCEBYTES))
        return -1;

    return COOKIE_RESPONSE_LENGTH;
}

/* Handle the cookie request packet of length length.
 * Put what was in the request in request_plain (must be of size COOKIE_REQUEST_PLAIN_LENGTH)
 * Put the key used to decrypt the request into shared_key (of size crypto_box_BEFORENMBYTES) for use in the response.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Net_Crypto::handle_cookie_request(uint8_t *request_plain, SharedKey &shared_key,
                                      PublicKey &dht_public_key, const uint8_t *packet, uint16_t length) const
{
    if (length != COOKIE_REQUEST_LENGTH)
        return -1;

    memcpy(dht_public_key.data.data(), packet + 1, crypto_box_PUBLICKEYBYTES);
    this->dht->get_shared_key_sent(shared_key, dht_public_key);
    int len = decrypt_data_symmetric(shared_key.data.data(), packet + 1 + crypto_box_PUBLICKEYBYTES,
                                     packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES,
                                     request_plain);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH)
        return -1;

    return 0;
}

/* Handle the cookie request packet (for raw UDP)
 */
int Net_Crypto::on_packet_cookie_request(const IPPort &source, const uint8_t *packet, uint16_t length)
{
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    SharedKey shared_key;
    PublicKey dht_public_key;

    if (handle_cookie_request(request_plain, shared_key, dht_public_key, packet, length) != 0)
        return 1;

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(data, request_plain, shared_key, dht_public_key) != sizeof(data))
        return 1;

    if ((uint32_t)sendpacket(dht->net, source, data, sizeof(data)) != sizeof(data))
        return 1;

    return 0;
}

/* Handle the cookie request packet (for TCP)
 */
int Net_Crypto::tcp_handle_cookie_request(TCP_Connection_to *connection, const uint8_t *packet, uint16_t length)
{
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    SharedKey shared_key;
    PublicKey dht_public_key;

    if (handle_cookie_request(request_plain, shared_key, dht_public_key, packet, length) != 0)
        return -1;

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(data, request_plain, shared_key, dht_public_key) != sizeof(data))
        return -1;

    int ret = connection->send_packet_tcp_connection(data, sizeof(data));
    return ret;
}

/* Handle the cookie request packet (for TCP oob packets)
 */
int Net_Crypto::tcp_oob_handle_cookie_request(unsigned int tcp_connections_number,
        const PublicKey &dht_public_key, const uint8_t *packet, uint16_t length) const
{
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    SharedKey shared_key;
    PublicKey dht_public_key_temp;

    if (handle_cookie_request(request_plain, shared_key, dht_public_key_temp, packet, length) != 0)
        return -1;

    if (dht_public_key != dht_public_key_temp)
        return -1;

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(data, request_plain, shared_key, dht_public_key) != sizeof(data))
        return -1;

    int ret = this->tcp_c->tcp_send_oob_packet(tcp_connections_number, dht_public_key, data, sizeof(data));
    return ret;
}

/* Handle a cookie response packet of length encrypted with shared_key.
 * put the cookie in the response in cookie
 *
 * cookie must be of length COOKIE_LENGTH.
 *
 * return -1 on failure.
 * return COOKIE_LENGTH on success.
 */
static int handle_cookie_response(uint8_t *cookie, uint64_t *number, const uint8_t *packet, uint16_t length,
                                  const SharedKey &shared_key)
{
    if (length != COOKIE_RESPONSE_LENGTH)
        return -1;

    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];
    int len = decrypt_data_symmetric(shared_key.data.data(), packet + 1, packet + 1 + crypto_box_NONCEBYTES,
                                     length - (1 + crypto_box_NONCEBYTES), plain);

    if (len != sizeof(plain))
        return -1;

    memcpy(cookie, plain, COOKIE_LENGTH);
    memcpy(number, plain + COOKIE_LENGTH, sizeof(uint64_t));
    return COOKIE_LENGTH;
}

#define HANDSHAKE_PACKET_LENGTH (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH + crypto_box_MACBYTES)

/* Create a handshake packet and put it in packet.
 * cookie must be COOKIE_LENGTH bytes.
 * packet must be of size HANDSHAKE_PACKET_LENGTH or bigger.
 *
 * return -1 on failure.
 * return HANDSHAKE_PACKET_LENGTH on success.
 */
int Net_Crypto::create_crypto_handshake(uint8_t *packet, const uint8_t *cookie, const Nonce &nonce,
                                        const PublicKey &session_pk, const PublicKey &peer_real_pk, const PublicKey &peer_dht_pubkey) const
{
    uint8_t plain[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH];
    memcpy(plain, nonce.data.data(), crypto_box_NONCEBYTES);
    memcpy(plain + crypto_box_NONCEBYTES, session_pk.data.data(), crypto_box_PUBLICKEYBYTES);
    crypto_hash_sha512(plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES, cookie, COOKIE_LENGTH);
    uint8_t cookie_plain[COOKIE_DATA_LENGTH];
    memcpy(cookie_plain, peer_real_pk.data.data(), crypto_box_PUBLICKEYBYTES);
    memcpy(cookie_plain + crypto_box_PUBLICKEYBYTES, peer_dht_pubkey.data.data(), crypto_box_PUBLICKEYBYTES);

    if (create_cookie(plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES, cookie_plain,
                      this->secret_symmetric_key) != 0)
        return -1;

    new_nonce(packet + 1 + COOKIE_LENGTH);
    int len = encrypt_data(peer_real_pk, this->self_secret_key, packet + 1 + COOKIE_LENGTH, plain, sizeof(plain),
                           packet + 1 + COOKIE_LENGTH + crypto_box_NONCEBYTES);

    if (len != HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES))
        return -1;

    packet[0] = NET_PACKET_CRYPTO_HS;
    memcpy(packet + 1, cookie, COOKIE_LENGTH);

    return HANDSHAKE_PACKET_LENGTH;
}

/* Handle a crypto handshake packet of length.
 * put the nonce contained in the packet in nonce,
 * the session public key in session_pk
 * the real public key of the peer in peer_real_pk
 * the dht public key of the peer in dht_public_key and
 * the cookie inside the encrypted part of the packet in cookie.
 *
 * if expected_real_pk isn't nullptr it denotes the real public key
 * the packet should be from.
 *
 * nonce must be at least crypto_box_NONCEBYTES
 * session_pk must be at least crypto_box_PUBLICKEYBYTES
 * peer_real_pk must be at least crypto_box_PUBLICKEYBYTES
 * cookie must be at least COOKIE_LENGTH
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Net_Crypto::handle_crypto_handshake(Nonce &nonce, PublicKey &session_pk, PublicKey &peer_real_pk,
                                        PublicKey &dht_public_key, uint8_t *cookie, const uint8_t *packet, uint16_t length, const PublicKey *expected_real_pk) const
{
    if (length != HANDSHAKE_PACKET_LENGTH)
        return -1;

    uint8_t cookie_plain[COOKIE_DATA_LENGTH];

    if (open_cookie(cookie_plain, packet + 1, this->secret_symmetric_key) != 0)
        return -1;

    if (expected_real_pk)
        if (public_key_cmp(cookie_plain, expected_real_pk->data.data()) != 0)
            return -1;

    uint8_t cookie_hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(cookie_hash, packet + 1, COOKIE_LENGTH);

    uint8_t plain[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH];
    int len = decrypt_data(PublicKey(cookie_plain), this->self_secret_key, packet + 1 + COOKIE_LENGTH,
                           packet + 1 + COOKIE_LENGTH + crypto_box_NONCEBYTES,
                           HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES), plain);

    if (len != sizeof(plain))
        return -1;

    if (sodium_memcmp(cookie_hash, plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                      crypto_hash_sha512_BYTES) != 0)
        return -1;

    memcpy(nonce.data.data(), plain, crypto_box_NONCEBYTES);
    memcpy(session_pk.data.data(), plain + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);
    memcpy(cookie, plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES, COOKIE_LENGTH);
    memcpy(peer_real_pk.data.data(), cookie_plain, crypto_box_PUBLICKEYBYTES);
    memcpy(dht_public_key.data.data(), cookie_plain + crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
    return 0;
}


Crypto_Connection *Net_Crypto::get_crypto_connection(int crypt_connection_id)
{
    auto it = crypto_connections.find(crypt_connection_id);
    if (it == crypto_connections.end())
        return nullptr;

    return it->second;
}

/* Associate an ip_port to a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::add_ip_port_connection(IPPort ip_port)
{
    if (ip_port.ip.family == Family::FAMILY_AF_INET) {
        if (ip_port != ip_portv4 && LAN_ip(ip_portv4.ip) != 0) {
            if (!net_crypto->ip_port_list.count(ip_port))
            {
                net_crypto->ip_port_list[ip_port] = id;
                net_crypto->ip_port_list.erase(ip_portv4);
                ip_portv4 = ip_port;
                return 0;
            }
        }
    } else if (ip_port.ip.family == Family::FAMILY_AF_INET6) {
        if (&ip_port != &ip_portv6) {
            if (!net_crypto->ip_port_list.count(ip_port))
            {
                net_crypto->ip_port_list[ip_port] = id;
                net_crypto->ip_port_list.erase(ip_portv6);
                ip_portv6 = ip_port;
                return 0;
            }
        }
    }

    return -1;
}

/* Return the IPPort that should be used to send packets to the other peer.
 *
 * return IPPort with family 0 on failure.
 * return IPPort on success.
 */
IPPort Crypto_Connection::return_ip_port_connection()
{
    IPPort empty;
    empty.ip.family = Family::FAMILY_NULL;

    uint64_t current_time = unix_time();
    bool v6 = 0, v4 = 0;

    if ((UDP_DIRECT_TIMEOUT + direct_lastrecv_timev4) > current_time) {
        v4 = 1;
    }

    if ((UDP_DIRECT_TIMEOUT + direct_lastrecv_timev6) > current_time) {
        v6 = 1;
    }

    if (v4 && LAN_ip(ip_portv4.ip) == 0) {
        return ip_portv4;
    } else if (v6 && ip_portv6.ip.family == Family::FAMILY_AF_INET6) {
        return ip_portv6;
    } else if (ip_portv4.ip.family == Family::FAMILY_AF_INET) {
        return ip_portv4;
    } else {
        return empty;
    }
}

/* Sends a packet to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::send_packet_to(const uint8_t *data, size_t length)
{
//TODO TCP, etc...
    int direct_send_attempt = 0;

    {
        std::lock_guard<std::mutex> lock(mutex);
        IPPort ip_port = return_ip_port_connection();

        //TODO: on bad networks, direct connections might not last indefinitely.
        if (ip_port.ip.family != Family::FAMILY_NULL) {
            bool direct_connected = 0;
            crypto_connection_status(&direct_connected, nullptr);

            if (direct_connected) {
                if ((uint32_t)sendpacket(net_crypto->dht->net, ip_port, data, length) == length) {
                    return 0;
                } else {
                    return -1;
                }
            }

            //TODO: a better way of sending packets directly to confirm the others ip.
            uint64_t current_time = unix_time();

            if ((((UDP_DIRECT_TIMEOUT / 2) + direct_send_attempt_time) > current_time && length < 96)
                    || data[0] == NET_PACKET_COOKIE_REQUEST || data[0] == NET_PACKET_CRYPTO_HS) {
                if ((uint32_t)sendpacket(net_crypto->dht->net, ip_port, data, length) == length) {
                    direct_send_attempt = 1;
                    direct_send_attempt_time = unix_time();
                }
            }
        }
    }

    int ret = 0;
    {
        std::lock_guard<std::mutex> lock(net_crypto->tcp_mutex);
        ret = tcp_connection->send_packet_tcp_connection(data, length);
    }

    if (ret == 0) {
        std::lock_guard<std::mutex> lock(mutex);
        last_tcp_sent = current_time_monotonic();
    }

    if (ret == 0 || direct_send_attempt) {
        return 0;
    }

    return -1;
}

/** START: Array Related functions **/


/* Return number of packets in array
 * Note that holes are counted too.
 */
static uint32_t num_packets_array(const Packets_Array *array)
{
    return array->buffer_end - array->buffer_start;
}

/* Add data with packet number to array.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int add_data_to_buffer(Packets_Array *array, uint32_t number, const Packet_Data *data)
{
    if (number - array->buffer_start > CRYPTO_PACKET_BUFFER_SIZE)
        return -1;

    uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (array->buffer[num])
        return -1;

    Packet_Data *new_d = (Packet_Data *) malloc(sizeof(Packet_Data));

    if (new_d == nullptr)
        return -1;

    memcpy(new_d, data, sizeof(Packet_Data));
    array->buffer[num] = new_d;

    if ((number - array->buffer_start) >= (array->buffer_end - array->buffer_start))
        array->buffer_end = number + 1;

    return 0;
}

/* Get pointer of data with packet number.
 *
 * return -1 on failure.
 * return 0 if data at number is empty.
 * return 1 if data pointer was put in data.
 */
static int get_data_pointer(const Packets_Array *array, Packet_Data **data, uint32_t number)
{
    uint32_t num_spots = array->buffer_end - array->buffer_start;

    if (array->buffer_end - number > num_spots || number - array->buffer_start >= num_spots)
        return -1;

    uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (!array->buffer[num])
        return 0;

    *data = array->buffer[num];
    return 1;
}

/* Add data to end of array.
 *
 * return -1 on failure.
 * return packet number on success.
 */
static int64_t add_data_end_of_buffer(Packets_Array *array, const Packet_Data *data)
{
    if (num_packets_array(array) >= CRYPTO_PACKET_BUFFER_SIZE)
        return -1;

    Packet_Data *new_d = (Packet_Data *) malloc(sizeof(Packet_Data));

    if (new_d == nullptr)
        return -1;

    memcpy(new_d, data, sizeof(Packet_Data));
    uint32_t id = array->buffer_end;
    array->buffer[id % CRYPTO_PACKET_BUFFER_SIZE] = new_d;
    ++array->buffer_end;
    return id;
}

/* Read data from begginning of array.
 *
 * return -1 on failure.
 * return packet number on success.
 */
static int64_t read_data_beg_buffer(Packets_Array *array, Packet_Data *data)
{
    if (array->buffer_end == array->buffer_start)
        return -1;

    uint32_t num = array->buffer_start % CRYPTO_PACKET_BUFFER_SIZE;

    if (!array->buffer[num])
        return -1;

    memcpy(data, array->buffer[num], sizeof(Packet_Data));
    uint32_t id = array->buffer_start;
    ++array->buffer_start;
    free(array->buffer[num]);
    array->buffer[num] = nullptr;
    return id;
}

/* Delete all packets in array before number (but not number)
 *
 * return -1 on failure.
 * return 0 on success
 */
static int clear_buffer_until(Packets_Array *array, uint32_t number)
{
    uint32_t num_spots = array->buffer_end - array->buffer_start;

    if (array->buffer_end - number >= num_spots || number - array->buffer_start > num_spots)
        return -1;

    uint32_t i;

    for (i = array->buffer_start; i != number; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num]) {
            free(array->buffer[num]);
            array->buffer[num] = nullptr;
        }
    }

    array->buffer_start = i;
    return 0;
}

static int clear_buffer(Packets_Array *array)
{
    uint32_t i;

    for (i = array->buffer_start; i != array->buffer_end; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num]) {
            free(array->buffer[num]);
            array->buffer[num] = nullptr;
        }
    }

    array->buffer_start = i;
    return 0;
}

/* Set array buffer end to number.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int set_buffer_end(Packets_Array *array, uint32_t number)
{
    if ((number - array->buffer_start) > CRYPTO_PACKET_BUFFER_SIZE)
        return -1;

    if ((number - array->buffer_end) > CRYPTO_PACKET_BUFFER_SIZE)
        return -1;

    array->buffer_end = number;
    return 0;
}

/* Create a packet request packet from recv_array and send_buffer_end into
 * data of length.
 *
 * return -1 on failure.
 * return length of packet on success.
 */
static int generate_request_packet(uint8_t *data, uint16_t length, const Packets_Array *recv_array)
{
    if (length == 0)
        return -1;

    data[0] = PACKET_ID_REQUEST;

    uint16_t cur_len = 1;

    if (recv_array->buffer_start == recv_array->buffer_end)
        return cur_len;

    if (length <= cur_len)
        return cur_len;

    uint32_t i, n = 1;

    for (i = recv_array->buffer_start; i != recv_array->buffer_end; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (!recv_array->buffer[num]) {
            data[cur_len] = n;
            n = 0;
            ++cur_len;

            if (length <= cur_len)
                return cur_len;

        } else if (n == 255) {
            data[cur_len] = 0;
            n = 0;
            ++cur_len;

            if (length <= cur_len)
                return cur_len;
        }

        ++n;
    }

    return cur_len;
}

/* Handle a request data packet.
 * Remove all the packets the other received from the array.
 *
 * return -1 on failure.
 * return number of requested packets on success.
 */
static int handle_request_packet(Packets_Array *send_array, const uint8_t *data, uint16_t length,
                                 uint64_t *latest_send_time, uint64_t rtt_time)
{
    if (length < 1)
        return -1;

    if (data[0] != PACKET_ID_REQUEST)
        return -1;

    if (length == 1)
        return 0;

    ++data;
    --length;

    uint32_t i, n = 1;
    uint32_t requested = 0;

    uint64_t temp_time = current_time_monotonic();
    uint64_t l_sent_time = ~0;

    for (i = send_array->buffer_start; i != send_array->buffer_end; ++i) {
        if (length == 0)
            break;

        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (n == data[0]) {
            if (send_array->buffer[num]) {
                uint64_t sent_time = send_array->buffer[num]->sent_time;

                if ((sent_time + rtt_time) < temp_time) {
                    send_array->buffer[num]->sent_time = 0;
                }
            }

            ++data;
            --length;
            n = 0;
            ++requested;
        } else {
            if (send_array->buffer[num]) {
                uint64_t sent_time = send_array->buffer[num]->sent_time;

                if (l_sent_time < sent_time)
                    l_sent_time = sent_time;

                free(send_array->buffer[num]);
                send_array->buffer[num] = nullptr;
            }
        }

        if (n == 255) {
            n = 1;

            if (data[0] != 0)
                return -1;

            ++data;
            --length;
        } else {
            ++n;
        }
    }

    if (*latest_send_time < l_sent_time)
        *latest_send_time = l_sent_time;

    return requested;
}

/** END: Array Related functions **/

#define MAX_DATA_DATA_PACKET_SIZE (MAX_CRYPTO_PACKET_SIZE - (1 + sizeof(uint16_t) + crypto_box_MACBYTES))

/* Creates and sends a data packet to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::send_data_packet(const uint8_t *data, uint16_t length)
{
    if (length == 0 || length + (1 + sizeof(uint16_t) + crypto_box_MACBYTES) > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    uint8_t packet[1 + sizeof(uint16_t) + length + crypto_box_MACBYTES];
    {
        std::lock_guard<std::mutex> lock(mutex);
        packet[0] = NET_PACKET_CRYPTO_DATA;
        memcpy(packet + 1, sent_nonce.data.data() + (crypto_box_NONCEBYTES - sizeof(uint16_t)), sizeof(uint16_t));
        int len = encrypt_data_symmetric(shared_key.data.data(), sent_nonce.data.data(), data, length, packet + 1 + sizeof(uint16_t));

        if (len + 1 + sizeof(uint16_t) != sizeof(packet)) {
            return -1;
        }

        ++sent_nonce;
    }

    return send_packet_to(packet, sizeof(packet));
}

/* Creates and sends a data packet with buffer_start and num to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::send_data_packet_helper(uint32_t buffer_start, uint32_t num,
        const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -1;

    num = htonl(num);
    buffer_start = htonl(buffer_start);
    uint16_t padding_length = (MAX_CRYPTO_DATA_SIZE - length) % CRYPTO_MAX_PADDING;
    uint8_t packet[sizeof(uint32_t) + sizeof(uint32_t) + padding_length + length];
    memcpy(packet, &buffer_start, sizeof(uint32_t));
    memcpy(packet + sizeof(uint32_t), &num, sizeof(uint32_t));
    memset(packet + (sizeof(uint32_t) * 2), PACKET_ID_PADDING, padding_length);
    memcpy(packet + (sizeof(uint32_t) * 2) + padding_length, data, length);

    return send_data_packet(packet, sizeof(packet));
}

int Crypto_Connection::reset_max_speed_reached()
{
    /* If last packet send failed, try to send packet again.
       If sending it fails we won't be able to send the new packet. */
    if (maximum_speed_reached) {
        Packet_Data *dt = nullptr;
        uint32_t packet_num = send_array.buffer_end - 1;
        int ret = get_data_pointer(&send_array, &dt, packet_num);

        uint8_t send_failed = 0;

        if (ret == 1) {
            if (!dt->sent_time) {
                if (send_data_packet_helper(recv_array.buffer_start, packet_num, dt->data,
                                            dt->length) != 0) {
                    send_failed = 1;
                } else {
                    dt->sent_time = current_time_monotonic();
                }
            }
        }

        if (!send_failed) {
            maximum_speed_reached = 0;
        } else {
            return -1;
        }
    }

    return 0;
}

/*  return -1 if data could not be put in packet queue.
 *  return positive packet number if data was put into the queue.
 */
int64_t Crypto_Connection::send_lossless_packet(const uint8_t *data, uint16_t length,
        uint8_t congestion_control)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -1;

    /* If last packet send failed, try to send packet again.
       If sending it fails we won't be able to send the new packet. */
    reset_max_speed_reached();

    if (maximum_speed_reached && congestion_control) {
        return -1;
    }

    Packet_Data dt;
    dt.sent_time = 0;
    dt.length = length;
    memcpy(dt.data, data, length);
    int64_t packet_num = -1;
    {
        std::lock_guard<std::mutex> lock(mutex);
        packet_num = add_data_end_of_buffer(&send_array, &dt);
    }

    if (packet_num == -1)
        return -1;

    if (!congestion_control && maximum_speed_reached) {
        return packet_num;
    }

    if (send_data_packet_helper(recv_array.buffer_start, packet_num, data, length) == 0) {
        Packet_Data *dt1 = nullptr;

        if (get_data_pointer(&send_array, &dt1, packet_num) == 1)
            dt1->sent_time = current_time_monotonic();
    } else {
        maximum_speed_reached = 1;
        LOGGER_ERROR("send_data_packet failed\n");
    }

    return packet_num;
}

/* Get the lowest 2 bytes from the nonce and convert
 * them to host byte format before returning them.
 */
static uint16_t get_nonce_uint16(const Nonce &nonce)
{
    uint16_t num;
    memcpy(&num, nonce.data.data() + (nonce.data.size() - sizeof(uint16_t)), sizeof(uint16_t));
    return ntohs(num);
}

#define DATA_NUM_THRESHOLD 21845

/* Handle a data packet.
 * Decrypt packet of length and put it into data.
 * data must be at least MAX_DATA_DATA_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of data on success.
 */
int Crypto_Connection::handle_data_packet(uint8_t *data, const uint8_t *packet,
        uint16_t length)
{
    if (length <= (1 + sizeof(uint16_t) + crypto_box_MACBYTES) || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    Nonce nonce = recv_nonce;
    uint16_t num_cur_nonce = get_nonce_uint16(nonce);
    uint16_t num;
    memcpy(&num, packet + 1, sizeof(uint16_t));
    num = ntohs(num);
    uint16_t diff = num - num_cur_nonce;
    increment_nonce_number(nonce.data.data(), diff);
    int len = decrypt_data_symmetric(shared_key.data.data(), nonce.data.data(), packet + 1 + sizeof(uint16_t),
                                     length - (1 + sizeof(uint16_t)), data);

    if ((unsigned int)len != length - (1 + sizeof(uint16_t) + crypto_box_MACBYTES))
        return -1;

    if (diff > DATA_NUM_THRESHOLD * 2) {
        increment_nonce_number(recv_nonce.data.data(), DATA_NUM_THRESHOLD);
    }

    return len;
}

/* Send a request packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::send_request_packet()
{
    uint8_t data[MAX_CRYPTO_DATA_SIZE];
    int len = generate_request_packet(data, sizeof(data), &recv_array);

    if (len == -1)
        return -1;

    return send_data_packet_helper(recv_array.buffer_start, send_array.buffer_end, data, len);
}

/* Send up to max num previously requested data packets.
 *
 * return -1 on failure.
 * return number of packets sent on success.
 */
int Crypto_Connection::send_requested_packets(uint32_t max_num)
{
    if (max_num == 0)
        return -1;

    uint64_t temp_time = current_time_monotonic();
    uint32_t i, num_sent = 0, array_size = num_packets_array(&send_array);

    for (i = 0; i < array_size; ++i) {
        Packet_Data *dt;
        uint32_t packet_num = (i + send_array.buffer_start);
        int ret = get_data_pointer(&send_array, &dt, packet_num);

        if (ret == -1) {
            return -1;
        } else if (ret == 0) {
            continue;
        }

        if (dt->sent_time) {
            continue;
        }

        if (send_data_packet_helper(recv_array.buffer_start, packet_num, dt->data, dt->length) == 0) {
            dt->sent_time = temp_time;
            ++num_sent;
        }

        if (num_sent >= max_num)
            break;
    }

    return num_sent;
}


/* Add a new temp packet to send repeatedly.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::new_temp_packet(const uint8_t *packet, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    temp_packet.clear();
    temp_packet.insert(temp_packet.end(), packet, packet + length);

    temp_packet_sent_time = 0;
    temp_packet_num_sent = 0;
    return 0;
}

/* Clear the temp packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::clear_temp_packet()
{
    temp_packet.clear();
    temp_packet_sent_time = 0;
    temp_packet_num_sent = 0;
    return 0;
}


/* Send the temp packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::send_temp_packet()
{
    if (temp_packet.empty())
        return -1;

    if (send_packet_to(temp_packet.data(), temp_packet.size()) != 0)
        return -1;

    temp_packet_sent_time = current_time_monotonic();
    ++temp_packet_num_sent;
    return 0;
}

/* Create a handshake packet and set it as a temp packet.
 * cookie must be COOKIE_LENGTH.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::create_send_handshake(const uint8_t *cookie, const PublicKey &dht_public_key)
{
    uint8_t handshake_packet[HANDSHAKE_PACKET_LENGTH];

    if (net_crypto->create_crypto_handshake(handshake_packet, cookie, sent_nonce, sessionpublic_key,
                                            public_key, dht_public_key) != sizeof(handshake_packet))
        return -1;

    if (new_temp_packet(handshake_packet, sizeof(handshake_packet)) != 0)
        return -1;

    send_temp_packet();
    return 0;
}

/* Send a kill packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::send_kill_packet()
{
    uint8_t kill_packet = PACKET_ID_KILL;
    return send_data_packet_helper(recv_array.buffer_start, send_array.buffer_end, &kill_packet, sizeof(kill_packet));
}

void Crypto_Connection::connection_kill()
{
    if (event_listener) {
        event_listener->on_status(0);
        event_listener->on_connection_killed();
    }
}

/* Handle a received data packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::handle_data_packet_helper(const uint8_t *packet, uint16_t length,
        bool udp)
{
    if (length > MAX_CRYPTO_PACKET_SIZE || length <= CRYPTO_DATA_PACKET_MIN_SIZE)
        return -1;

    uint8_t data[MAX_DATA_DATA_PACKET_SIZE];
    int len = handle_data_packet(data, packet, length);

    if (len <= (int)(sizeof(uint32_t) * 2))
        return -1;

    uint32_t buffer_start, num;
    memcpy(&buffer_start, data, sizeof(uint32_t));
    memcpy(&num, data + sizeof(uint32_t), sizeof(uint32_t));
    buffer_start = ntohl(buffer_start);
    num = ntohl(num);

    uint64_t rtt_calc_time = 0;

    if (buffer_start != send_array.buffer_start) {
        Packet_Data *packet_time;

        if (get_data_pointer(&send_array, &packet_time, send_array.buffer_start) == 1) {
            rtt_calc_time = packet_time->sent_time;
        }

        if (clear_buffer_until(&send_array, buffer_start) != 0) {
            return -1;
        }
    }

    uint8_t *real_data = data + (sizeof(uint32_t) * 2);
    uint16_t real_length = len - (sizeof(uint32_t) * 2);

    while (real_data[0] == PACKET_ID_PADDING) { /* Remove Padding */
        ++real_data;
        --real_length;

        if (real_length == 0)
            return -1;
    }

    if (real_data[0] == PACKET_ID_KILL) {
        connection_kill();
        return 0;
    }

    if (status == CryptoConnectionStatus::CRYPTO_CONN_NOT_CONFIRMED) {
        clear_temp_packet();
        status = CryptoConnectionStatus::CRYPTO_CONN_ESTABLISHED;

        if (event_listener)
            event_listener->on_status(1);
    }

    if (real_data[0] == PACKET_ID_REQUEST) {
        uint64_t rtt_time;

        if (udp) {
            rtt_time = this->rtt_time;
        } else {
            rtt_time = DEFAULT_TCP_PING_CONNECTION;
        }

        int requested = handle_request_packet(&send_array, real_data, real_length, &rtt_calc_time, rtt_time);

        if (requested == -1) {
            return -1;
        } else {
            //TODO?
        }

        set_buffer_end(&recv_array, num);
    } else if (real_data[0] >= CRYPTO_RESERVED_PACKETS && real_data[0] < PACKET_ID_LOSSY_RANGE_START) {
        Packet_Data dt;
        dt.length = real_length;
        memcpy(dt.data, real_data, real_length);

        if (add_data_to_buffer(&recv_array, num, &dt) != 0)
            return -1;


        while (1) {
            int ret = -1;
            {
                std::lock_guard<std::mutex> lock(mutex);
                ret = read_data_beg_buffer(&recv_array, &dt);
            }

            if (ret == -1)
                break;

            if (event_listener)
                event_listener->on_data(dt.data, dt.length);
        }

        /* Packet counter. */
        ++packet_counter;
    } else if (real_data[0] >= PACKET_ID_LOSSY_RANGE_START &&
               real_data[0] < (PACKET_ID_LOSSY_RANGE_START + PACKET_ID_LOSSY_RANGE_SIZE)) {

        set_buffer_end(&recv_array, num);

        if (event_listener)
            event_listener->on_lossy_data(real_data, real_length);

    } else {
        return -1;
    }

    if (rtt_calc_time != 0) {
        uint64_t rtt_time = current_time_monotonic() - rtt_calc_time;

        if (rtt_time < this->rtt_time)
            this->rtt_time = rtt_time;
    }

    return 0;
}

/* Handle a packet that was received for the connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::handle_packet_connection(const uint8_t *packet, uint16_t length,
        bool udp)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    switch (packet[0]) {
    case NET_PACKET_COOKIE_RESPONSE: {
        if (status != CryptoConnectionStatus::CRYPTO_CONN_COOKIE_REQUESTING)
            return -1;

        uint8_t cookie[COOKIE_LENGTH];
        uint64_t number;

        if (handle_cookie_response(cookie, &number, packet, length, shared_key) != sizeof(cookie))
            return -1;

        if (number != cookie_request_number)
            return -1;

        if (create_send_handshake(cookie, dht_public_key) != 0)
            return -1;

        status = CryptoConnectionStatus::CRYPTO_CONN_HANDSHAKE_SENT;
        return 0;
    }

    case NET_PACKET_CRYPTO_HS: {
        if (status == CryptoConnectionStatus::CRYPTO_CONN_COOKIE_REQUESTING || status == CryptoConnectionStatus::CRYPTO_CONN_HANDSHAKE_SENT
                || status == CryptoConnectionStatus::CRYPTO_CONN_NOT_CONFIRMED) {
            PublicKey peer_real_pk;
            PublicKey dht_public_key;
            uint8_t cookie[COOKIE_LENGTH];

            if (net_crypto->handle_crypto_handshake(recv_nonce, peersessionpublic_key, peer_real_pk, dht_public_key, cookie,
                                                    packet, length, &public_key) != 0)
                return -1;

            if (dht_public_key == this->dht_public_key) {
                shared_key = compute_shared_key(peersessionpublic_key, sessionsecret_key);

                if (status == CryptoConnectionStatus::CRYPTO_CONN_COOKIE_REQUESTING) {
                    if (create_send_handshake(cookie, dht_public_key) != 0)
                        return -1;
                }

                status = CryptoConnectionStatus::CRYPTO_CONN_NOT_CONFIRMED;
            } else {
                if (event_listener)
                    event_listener->on_dht_pk(dht_public_key);
            }

        } else {
            return -1;
        }

        return 0;
    }

    case NET_PACKET_CRYPTO_DATA: {
        if (status == CryptoConnectionStatus::CRYPTO_CONN_NOT_CONFIRMED || status == CryptoConnectionStatus::CRYPTO_CONN_ESTABLISHED) {
            return handle_data_packet_helper(packet, length, udp);
        } else {
            return -1;
        }

        return 0;
    }

    default: {
        return -1;
    }
    }

    return 0;
}

Crypto_Connection::Crypto_Connection(Net_Crypto *net_crypto) :
    net_crypto(net_crypto),
    id(net_crypto->id_pool.next())
{
    net_crypto->crypto_connections[id] = this;
}

/* Create a new empty crypto connection.
 *
 * return -1 on failure.
 * return connection id on success.
 */
std::shared_ptr<Crypto_Connection> Net_Crypto::create_crypto_connection()
{
    while (1) { /* TODO: is this really the best way to do this? */
        pthread_mutex_lock(&this->connections_mutex);

        if (!this->connection_use_counter) {
            break;
        }

        pthread_mutex_unlock(&this->connections_mutex);
    }

    std::shared_ptr<Crypto_Connection> result = std::shared_ptr<Crypto_Connection>(new Crypto_Connection(this));

    pthread_mutex_unlock(&this->connections_mutex);
    return result;
}

/* Get crypto connection id from public key of peer.
 *
 *  return -1 if there are no connections like we are looking for.
 *  return id if it found it.
 */
int Net_Crypto::getcryptconnection_id(const PublicKey &public_key) const
{
    for (auto &kv : crypto_connections)
    {
        Crypto_Connection *c = kv.second;
        if (public_key == c->public_key)
            return c->id;
    }

    return -1;
}

Crypto_Connection *Net_Crypto::find(const bitox::PublicKey &public_key)
{
    for (auto &kv : crypto_connections)
    {
        Crypto_Connection *c = kv.second;
        if (public_key == c->public_key)
            return c;
    }

    return nullptr;
}

/* Add a source to the crypto connection.
 * This is to be used only when we have received a packet from that source.
 *
 *  return -1 on failure.
 *  return positive number on success.
 *  0 if source was a direct UDP connection.
 */
int Crypto_Connection::crypto_connection_add_source(IPPort source)
{
    if (source.ip.family == Family::FAMILY_AF_INET || source.ip.family == Family::FAMILY_AF_INET6) {
        if (add_ip_port_connection(source) != 0)
            return -1;

        if (source.ip.family == Family::FAMILY_AF_INET) {
            direct_lastrecv_timev4 = unix_time();
        } else {
            direct_lastrecv_timev6 = unix_time();
        }

        return 0;
    } else if (source.ip.family == Family::FAMILY_TCP_FAMILY) {
        if (tcp_connection->add_tcp_number_relay_connection(source.onion_ip.con_id) == 0)
            return 1;
    }

    return -1;
}


/* Set function to be called when someone requests a new connection to us.
 *
 * The set function should return -1 on failure and 0 on success.
 *
 * n_c is only valid for the duration of the function call.
 */
void new_connection_handler(Net_Crypto *c, int (*new_connection_callback)(void *object, New_Connection *n_c),
                            void *object)
{
    c->new_connection_callback = new_connection_callback;
    c->new_connection_callback_object = object;
}

/* Handle a handshake packet by someone who wants to initiate a new connection with us.
 * This calls the callback set by new_connection_handler() if the handshake is ok.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Net_Crypto::handle_new_connection_handshake(IPPort source, const uint8_t *data, uint16_t length)
{
    New_Connection n_c;
    n_c.cookie.resize(COOKIE_LENGTH);

    n_c.source = source;

    if (handle_crypto_handshake(n_c.recv_nonce, n_c.peersessionpublic_key, n_c.public_key, n_c.dht_public_key,
                                n_c.cookie.data(), data, length, 0) != 0) {
        return -1;
    }

    if (Crypto_Connection *conn = find(n_c.public_key))
    {
        std::shared_ptr<Crypto_Connection> keep_alive_ptr = conn->shared_from_this();

        if (n_c.dht_public_key != conn->dht_public_key) {
            conn->connection_kill();
        } else {
            int ret = -1;

            if (conn && (conn->status == CryptoConnectionStatus::CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CryptoConnectionStatus::CRYPTO_CONN_HANDSHAKE_SENT)) {
                conn->recv_nonce = n_c.recv_nonce;
                conn->peersessionpublic_key = n_c.peersessionpublic_key;
                encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key.data.data());

                conn->crypto_connection_add_source(source);

                if (conn->create_send_handshake(n_c.cookie.data(), n_c.dht_public_key) == 0) {
                    conn->status = CryptoConnectionStatus::CRYPTO_CONN_NOT_CONFIRMED;
                    ret = 0;
                }
            }

            return ret;
        }
    }

    int ret = this->new_connection_callback(this->new_connection_callback_object, &n_c);
    return ret;
}

/* Accept a crypto connection.
 *
 * return -1 on failure.
 * return connection id on success.
 */
std::shared_ptr<Crypto_Connection> Net_Crypto::accept_crypto_connection(New_Connection *n_c)
{
    if (getcryptconnection_id(n_c->public_key) != -1)
        return std::shared_ptr<Crypto_Connection>();

    if (n_c->cookie.size() != COOKIE_LENGTH)
        return std::shared_ptr<Crypto_Connection>();

    std::shared_ptr<Crypto_Connection> crypt_connection = create_crypto_connection();

    {
        std::lock_guard<std::mutex> lock(this->tcp_mutex);
        crypt_connection->tcp_connection = this->tcp_c->new_tcp_connection_to(n_c->dht_public_key, crypt_connection->id);
    }

    if (!crypt_connection->tcp_connection)
        return std::shared_ptr<Crypto_Connection>();

    crypt_connection->public_key = n_c->public_key;
    crypt_connection->recv_nonce = n_c->recv_nonce;
    crypt_connection->peersessionpublic_key = n_c->peersessionpublic_key;
    random_nonce(crypt_connection->sent_nonce.data.data());
    crypto_box_keypair(crypt_connection->sessionpublic_key.data.data(), crypt_connection->sessionsecret_key.data.data());
    encrypt_precompute(crypt_connection->peersessionpublic_key, crypt_connection->sessionsecret_key, crypt_connection->shared_key.data.data());
    crypt_connection->status = CryptoConnectionStatus::CRYPTO_CONN_NOT_CONFIRMED;

    if (crypt_connection->create_send_handshake(n_c->cookie.data(), n_c->dht_public_key) != 0) {
        std::lock_guard<std::mutex> lock(this->tcp_mutex); // TODO ?
        return std::shared_ptr<Crypto_Connection>();
    }

    crypt_connection->dht_public_key = n_c->dht_public_key;
    crypt_connection->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    crypt_connection->packet_send_rate_requested = CRYPTO_PACKET_MIN_RATE;
    crypt_connection->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
    crypt_connection->rtt_time = DEFAULT_PING_CONNECTION;
    crypt_connection->crypto_connection_add_source(n_c->source);
    return crypt_connection;
}

/* Create a crypto connection.
 * If one to that real public key already exists, return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
std::shared_ptr<Crypto_Connection> Net_Crypto::new_crypto_connection(const PublicKey &real_public_key, const PublicKey &dht_public_key)
{
    Crypto_Connection *c = find(real_public_key);

    if (c)
        return c->shared_from_this();

    std::shared_ptr<Crypto_Connection> conn = create_crypto_connection();

    {
        std::lock_guard<std::mutex> lock(this->tcp_mutex);
        conn->tcp_connection = this->tcp_c->new_tcp_connection_to(dht_public_key, conn->id);
    }

    if (!conn->tcp_connection)
        return std::shared_ptr<Crypto_Connection>();

    conn->public_key = real_public_key;
    conn->sent_nonce = Nonce::create_random();
    crypto_box_keypair(conn->sessionpublic_key.data.data(), conn->sessionsecret_key.data.data());
    conn->status = CryptoConnectionStatus::CRYPTO_CONN_COOKIE_REQUESTING;
    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    conn->packet_send_rate_requested = CRYPTO_PACKET_MIN_RATE;
    conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
    conn->rtt_time = DEFAULT_PING_CONNECTION;
    conn->dht_public_key = dht_public_key;

    conn->cookie_request_number = random_64b();
    uint8_t cookie_request[COOKIE_REQUEST_LENGTH];

    if (create_cookie_request(cookie_request, conn->dht_public_key, conn->cookie_request_number,
                              conn->shared_key) != sizeof(cookie_request)
            || conn->new_temp_packet(cookie_request, sizeof(cookie_request)) != 0) {
        std::lock_guard<std::mutex> lock(this->tcp_mutex);
        conn->tcp_connection.reset();
        return std::shared_ptr<Crypto_Connection>();
    }

    return conn;
}

/* Set the direct ip of the crypto connection.
 *
 * Connected is 0 if we are not sure we are connected to that person, 1 if we are sure.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::set_direct_ip_port(IPPort ip_port, bool connected)
{
    if (add_ip_port_connection(ip_port) == 0) {
        if (connected) {
            if (ip_port.ip.family == Family::FAMILY_AF_INET) {
                direct_lastrecv_timev4 = unix_time();
            } else {
                direct_lastrecv_timev6 = unix_time();
            }
        } else {
            if (ip_port.ip.family == Family::FAMILY_AF_INET) {
                direct_lastrecv_timev4 = 0;
            } else {
                direct_lastrecv_timev6 = 0;
            }
        }

        return 0;
    }

    return -1;
}


static int tcp_data_callback(void *object, int id, const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    Net_Crypto *c = (Net_Crypto *) object;

    Crypto_Connection *conn = c->get_crypto_connection(id);

    if (conn == 0)
        return -1;
    
    std::shared_ptr<Crypto_Connection> keep_alive_ptr = conn->shared_from_this();

    if (data[0] == NET_PACKET_COOKIE_REQUEST && conn->tcp_connection) {
        return c->tcp_handle_cookie_request(conn->tcp_connection.get(), data, length);
    }

    int ret = -1;
    {
        std::lock_guard<std::mutex> lock(c->tcp_mutex);
        ret = conn->handle_packet_connection(data, length, 0);
    }

    if (ret != 0)
        return -1;

    //TODO detect and kill bad TCP connections.
    return 0;
}

static int tcp_oob_callback(void *object, const PublicKey &public_key, unsigned int tcp_connections_number,
                            const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    Net_Crypto *c = (Net_Crypto *) object;

    if (data[0] == NET_PACKET_COOKIE_REQUEST) {
        return c->tcp_oob_handle_cookie_request(tcp_connections_number, public_key, data, length);
    } else if (data[0] == NET_PACKET_CRYPTO_HS) {
        IPPort source;
        source.port = 0;
        source.ip.family = Family::FAMILY_TCP_FAMILY;
        source.onion_ip.con_id = tcp_connections_number;

        if (c->handle_new_connection_handshake(source, data, length) != 0)
            return -1;

        return 0;
    } else {
        return -1;
    }
}

/* Add a tcp relay, associating it to a crypt_connection_id.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int Crypto_Connection::add_tcp_relay_peer(IPPort ip_port, const PublicKey &public_key)
{
    std::lock_guard<std::mutex> lock(net_crypto->tcp_mutex);
    if (!tcp_connection)
        return -1;
    
    return tcp_connection->add_tcp_relay_connection(ip_port, public_key);
}

/* Add a tcp relay to the array.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int Net_Crypto::add_tcp_relay(IPPort ip_port, const PublicKey &public_key)
{
    std::lock_guard<std::mutex> lock(this->tcp_mutex);
    return this->tcp_c->add_tcp_relay_global(ip_port, public_key);
}

/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO: This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int Net_Crypto::get_random_tcp_con_number()
{
    std::lock_guard<std::mutex> lock(tcp_mutex);
    return tcp_c->get_random_tcp_onion_conn_number();
}

/* Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int Net_Crypto::send_tcp_onion_request(unsigned int tcp_connections_number, const uint8_t *data, uint16_t length)
{
    std::lock_guard<std::mutex> lock(tcp_mutex);
    return tcp_c->tcp_send_onion_request(tcp_connections_number, data, length);
}

/* Copy a maximum of num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int Net_Crypto::copy_connected_tcp_relays(bitox::dht::NodeFormat *tcp_relays, uint16_t num)
{
    if (num == 0)
        return 0;

    std::lock_guard<std::mutex> lock(tcp_mutex);
    return tcp_c->tcp_copy_connected_relays(tcp_relays, num);
}

void Net_Crypto::do_tcp()
{
    {
        std::lock_guard<std::mutex> lock(this->tcp_mutex);
        this->tcp_c->do_tcp_connections();
    }

    uint32_t i;

    for (auto &kv : crypto_connections) {
        Crypto_Connection *conn =  kv.second;

        if (conn->status == CryptoConnectionStatus::CRYPTO_CONN_ESTABLISHED) {
            bool direct_connected = false;
            conn->crypto_connection_status(&direct_connected, nullptr);

            std::lock_guard<std::mutex> lock(this->tcp_mutex);
            
            if (conn->tcp_connection)
                conn->tcp_connection->set_tcp_connection_to_status(!direct_connected);
        }
    }
}

/* Set function to be called when connection with crypt_connection_id goes connects/disconnects.
 *
 * The set function should return -1 on failure and 0 on success.
 * Note that if this function is set, the connection will clear itself on disconnect.
 * Object and id will be passed to this function untouched.
 * status is 1 if the connection is going online, 0 if it is going offline.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int set_event_listener(Net_Crypto *c, int crypt_connection_id, CryptoConnectionEventListener *listener)
{
    Crypto_Connection *conn = c->get_crypto_connection(crypt_connection_id);

    if (conn == 0)
        return -1;

    conn->event_listener = listener;
    return 0;
}

/* Get the crypto connection id from the ip_port.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int Net_Crypto::crypto_id_ip_port(IPPort ip_port) const
{
    auto it = this->ip_port_list.find(ip_port);
    if (it == this->ip_port_list.end())
        return -1;

    return it->second;
}

#define CRYPTO_MIN_PACKET_SIZE (1 + sizeof(uint16_t) + crypto_box_MACBYTES)

/* Handle raw UDP packets coming directly from the socket.
 *
 * Handles:
 * Cookie response packets.
 * Crypto handshake packets.
 * Crypto data packets.
 *
 */
int Net_Crypto::on_udp_packet(const IPPort &source, const uint8_t *packet, uint16_t length)
{
    if (length <= CRYPTO_MIN_PACKET_SIZE || length > MAX_CRYPTO_PACKET_SIZE)
        return 1;

    int crypt_connection_id = crypto_id_ip_port(source);

    if (crypt_connection_id == -1) {
        if (packet[0] != NET_PACKET_CRYPTO_HS)
            return 1;

        if (handle_new_connection_handshake(source, packet, length) != 0)
            return 1;

        return 0;
    }

    Crypto_Connection *conn = get_crypto_connection(crypt_connection_id);

    if (conn == 0)
        return -1;

    std::shared_ptr<Crypto_Connection> keep_alive_ptr = conn->shared_from_this();
    
    if (conn->handle_packet_connection(packet, length, 1) != 0)
        return 1;

    {
        std::lock_guard<std::mutex> lock(conn->mutex);

        if (source.ip.family == Family::FAMILY_AF_INET) {
            conn->direct_lastrecv_timev4 = unix_time();
        } else {
            conn->direct_lastrecv_timev6 = unix_time();
        }
    }

    return 0;
}

/* The dT for the average packet receiving rate calculations.
   Also used as the */
#define PACKET_COUNTER_AVERAGE_INTERVAL 50

/* Ratio of recv queue size / recv packet rate (in seconds) times
 * the number of ms between request packets to send at that ratio
 */
#define REQUEST_PACKETS_COMPARE_CONSTANT (0.125 * 100.0)

/* Timeout for increasing speed after congestion event (in ms). */
#define CONGESTION_EVENT_TIMEOUT 1000

/* If the send queue is SEND_QUEUE_RATIO times larger than the
 * calculated link speed the packet send speed will be reduced
 * by a value depending on this number.
 */
#define SEND_QUEUE_RATIO 2.0

void Net_Crypto::send_crypto_packets()
{
    uint64_t temp_time = current_time_monotonic();
    double total_send_rate = 0;
    uint32_t peak_request_packet_interval = ~0;

    for (auto &kv : crypto_connections) {
        Crypto_Connection *conn = kv.second;

        if (CRYPTO_SEND_PACKET_INTERVAL + conn->temp_packet_sent_time < temp_time) {
            conn->send_temp_packet();
        }

        if ((conn->status == CryptoConnectionStatus::CRYPTO_CONN_NOT_CONFIRMED || conn->status == CryptoConnectionStatus::CRYPTO_CONN_ESTABLISHED)
                && ((CRYPTO_SEND_PACKET_INTERVAL) + conn->last_request_packet_sent) < temp_time) {
            if (conn->send_request_packet() == 0) {
                conn->last_request_packet_sent = temp_time;
            }

        }

        if (conn->status == CryptoConnectionStatus::CRYPTO_CONN_ESTABLISHED) {
            if (conn->packet_recv_rate > CRYPTO_PACKET_MIN_RATE) {
                double request_packet_interval = (REQUEST_PACKETS_COMPARE_CONSTANT / (((double)num_packets_array(
                                                      &conn->recv_array) + 1.0) / (conn->packet_recv_rate + 1.0)));

                double request_packet_interval2 = ((CRYPTO_PACKET_MIN_RATE / conn->packet_recv_rate) *
                                                   (double)CRYPTO_SEND_PACKET_INTERVAL) + (double)PACKET_COUNTER_AVERAGE_INTERVAL;

                if (request_packet_interval2 < request_packet_interval)
                    request_packet_interval = request_packet_interval2;

                if (request_packet_interval < PACKET_COUNTER_AVERAGE_INTERVAL)
                    request_packet_interval = PACKET_COUNTER_AVERAGE_INTERVAL;

                if (request_packet_interval > CRYPTO_SEND_PACKET_INTERVAL)
                    request_packet_interval = CRYPTO_SEND_PACKET_INTERVAL;

                if (temp_time - conn->last_request_packet_sent > (uint64_t)request_packet_interval) {
                    if (conn->send_request_packet() == 0) {
                        conn->last_request_packet_sent = temp_time;
                    }
                }

                if (request_packet_interval < peak_request_packet_interval) {
                    peak_request_packet_interval = request_packet_interval;
                }
            }

            if ((PACKET_COUNTER_AVERAGE_INTERVAL + conn->packet_counter_set) < temp_time) {

                double dt = temp_time - conn->packet_counter_set;

                conn->packet_recv_rate = (double)conn->packet_counter / (dt / 1000.0);
                conn->packet_counter = 0;
                conn->packet_counter_set = temp_time;

                uint32_t packets_sent = conn->packets_sent;
                conn->packets_sent = 0;

                uint32_t packets_resent = conn->packets_resent;
                conn->packets_resent = 0;

                /* conjestion control
                    calculate a new value of conn->packet_send_rate based on some data
                 */

                unsigned int pos = conn->last_sendqueue_counter % CONGESTION_QUEUE_ARRAY_SIZE;
                conn->last_sendqueue_size[pos] = num_packets_array(&conn->send_array);
                ++conn->last_sendqueue_counter;

                unsigned int j;
                long signed int sum = 0;
                sum = (long signed int)conn->last_sendqueue_size[(pos) % CONGESTION_QUEUE_ARRAY_SIZE] -
                      (long signed int)conn->last_sendqueue_size[(pos - (CONGESTION_QUEUE_ARRAY_SIZE - 1)) % CONGESTION_QUEUE_ARRAY_SIZE];

                unsigned int n_p_pos = conn->last_sendqueue_counter % CONGESTION_LAST_SENT_ARRAY_SIZE;
                conn->last_num_packets_sent[n_p_pos] = packets_sent;
                conn->last_num_packets_resent[n_p_pos] = packets_resent;

                bool direct_connected = 0;
                conn->crypto_connection_status(&direct_connected, nullptr);

                if (direct_connected && conn->last_tcp_sent + CONGESTION_EVENT_TIMEOUT > temp_time) {
                    /* When switching from TCP to UDP, don't change the packet send rate for CONGESTION_EVENT_TIMEOUT ms. */
                } else {
                    long signed int total_sent = 0, total_resent = 0;

                    //TODO use real delay
                    unsigned int delay = (unsigned int)((conn->rtt_time / PACKET_COUNTER_AVERAGE_INTERVAL) + 0.5);
                    unsigned int packets_set_rem_array = (CONGESTION_LAST_SENT_ARRAY_SIZE - CONGESTION_QUEUE_ARRAY_SIZE);

                    if (delay > packets_set_rem_array) {
                        delay = packets_set_rem_array;
                    }

                    for (j = 0; j < CONGESTION_QUEUE_ARRAY_SIZE; ++j) {
                        unsigned int ind = (j + (packets_set_rem_array  - delay) + n_p_pos) % CONGESTION_LAST_SENT_ARRAY_SIZE;
                        total_sent += conn->last_num_packets_sent[ind];
                        total_resent += conn->last_num_packets_resent[ind];
                    }

                    if (sum > 0) {
                        total_sent -= sum;
                    } else {
                        if (total_resent > -sum)
                            total_resent = -sum;
                    }

                    /* if queue is too big only allow resending packets. */
                    uint32_t npackets = num_packets_array(&conn->send_array);
                    double min_speed = 1000.0 * (((double)(total_sent)) / ((double)(CONGESTION_QUEUE_ARRAY_SIZE) *
                                                 PACKET_COUNTER_AVERAGE_INTERVAL));

                    double min_speed_request = 1000.0 * (((double)(total_sent + total_resent)) / ((double)(
                            CONGESTION_QUEUE_ARRAY_SIZE) * PACKET_COUNTER_AVERAGE_INTERVAL));

                    if (min_speed < CRYPTO_PACKET_MIN_RATE)
                        min_speed = CRYPTO_PACKET_MIN_RATE;

                    double send_array_ratio = (((double)npackets) / min_speed);

                    //TODO: Improve formula?
                    if (send_array_ratio > SEND_QUEUE_RATIO && CRYPTO_MIN_QUEUE_LENGTH < npackets) {
                        conn->packet_send_rate = min_speed * (1.0 / (send_array_ratio / SEND_QUEUE_RATIO));
                    } else if (conn->last_congestion_event + CONGESTION_EVENT_TIMEOUT < temp_time) {
                        conn->packet_send_rate = min_speed * 1.2;
                    } else {
                        conn->packet_send_rate = min_speed * 0.9;
                    }

                    conn->packet_send_rate_requested = min_speed_request * 1.2;

                    if (conn->packet_send_rate < CRYPTO_PACKET_MIN_RATE) {
                        conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
                    }

                    if (conn->packet_send_rate_requested < conn->packet_send_rate) {
                        conn->packet_send_rate_requested = conn->packet_send_rate;
                    }
                }

            }

            if (conn->last_packets_left_set == 0 || conn->last_packets_left_requested_set == 0) {
                conn->last_packets_left_requested_set = conn->last_packets_left_set = temp_time;
                conn->packets_left_requested = conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
            } else {
                if (((uint64_t)((1000.0 / conn->packet_send_rate) + 0.5) + conn->last_packets_left_set) <= temp_time) {
                    double n_packets = conn->packet_send_rate * (((double)(temp_time - conn->last_packets_left_set)) / 1000.0);
                    n_packets += conn->last_packets_left_rem;

                    uint32_t num_packets = n_packets;
                    double rem = n_packets - (double)num_packets;

                    if (conn->packets_left > num_packets * 4 + CRYPTO_MIN_QUEUE_LENGTH) {
                        conn->packets_left = num_packets * 4 + CRYPTO_MIN_QUEUE_LENGTH;
                    } else {
                        conn->packets_left += num_packets;
                    }

                    conn->last_packets_left_set = temp_time;
                    conn->last_packets_left_rem = rem;
                }

                if (((uint64_t)((1000.0 / conn->packet_send_rate_requested) + 0.5) + conn->last_packets_left_requested_set) <=
                        temp_time) {
                    double n_packets = conn->packet_send_rate_requested * (((double)(temp_time - conn->last_packets_left_requested_set)) /
                                       1000.0);
                    n_packets += conn->last_packets_left_requested_rem;

                    uint32_t num_packets = n_packets;
                    double rem = n_packets - (double)num_packets;
                    conn->packets_left_requested = num_packets;

                    conn->last_packets_left_requested_set = temp_time;
                    conn->last_packets_left_requested_rem = rem;
                }

                if (conn->packets_left > conn->packets_left_requested)
                    conn->packets_left_requested = conn->packets_left;
            }

            int ret = conn->send_requested_packets(conn->packets_left_requested);

            if (ret != -1) {
                conn->packets_left_requested -= ret;
                conn->packets_resent += ret;

                if ((unsigned int)ret < conn->packets_left) {
                    conn->packets_left -= ret;
                } else {
                    conn->last_congestion_event = temp_time;
                    conn->packets_left = 0;
                }
            }

            if (conn->packet_send_rate > CRYPTO_PACKET_MIN_RATE * 1.5) {
                total_send_rate += conn->packet_send_rate;
            }
        }
    }

    this->current_sleep_time = ~0;
    uint32_t sleep_time = peak_request_packet_interval;

    if (this->current_sleep_time > sleep_time) {
        this->current_sleep_time = sleep_time;
    }

    if (total_send_rate > CRYPTO_PACKET_MIN_RATE) {
        sleep_time = (1000.0 / total_send_rate);

        if (this->current_sleep_time > sleep_time) {
            this->current_sleep_time = sleep_time + 1;
        }
    }

    sleep_time = CRYPTO_SEND_PACKET_INTERVAL;

    if (this->current_sleep_time > sleep_time) {
        this->current_sleep_time = sleep_time;
    }
}

/* Return 1 if max speed was reached for this connection (no more data can be physically through the pipe).
 * Return 0 if it wasn't reached.
 */
bool Crypto_Connection::max_speed_reached()
{
    return reset_max_speed_reached() != 0;
}

/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
uint32_t Crypto_Connection::crypto_num_free_sendqueue_slots() const
{
    uint32_t max_packets = CRYPTO_PACKET_BUFFER_SIZE - num_packets_array(&send_array);

    if (packets_left < max_packets) {
        return packets_left;
    } else {
        return max_packets;
    }
}

/* Sends a lossless cryptopacket.
 *
 * return -1 if data could not be put in packet queue.
 * return positive packet number if data was put into the queue.
 *
 * congestion_control: should congestion control apply to this packet?
 */
int64_t Crypto_Connection::write_cryptpacket(const uint8_t *data, uint16_t length,
        uint8_t congestion_control)
{
    if (length == 0)
        return -1;

    if (data[0] < CRYPTO_RESERVED_PACKETS)
        return -1;

    if (data[0] >= PACKET_ID_LOSSY_RANGE_START)
        return -1;

    if (status != CryptoConnectionStatus::CRYPTO_CONN_ESTABLISHED)
        return -1;

    if (congestion_control && packets_left == 0)
        return -1;

    int64_t ret = send_lossless_packet(data, length, congestion_control);

    if (ret == -1)
        return -1;

    if (congestion_control) {
        --packets_left;
        --packets_left_requested;
        packets_sent++;
    }

    return ret;
}

/* Check if packet_number was received by the other side.
 *
 * packet_number must be a valid packet number of a packet sent on this connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int Crypto_Connection::cryptpacket_received(uint32_t packet_number) const
{
    uint32_t num = send_array.buffer_end - send_array.buffer_start;
    uint32_t num1 = packet_number - send_array.buffer_start;

    if (num < num1) {
        return 0;
    } else {
        return -1;
    }
}

/* return -1 on failure.
 * return 0 on success.
 *
 * Sends a lossy cryptopacket. (first byte must in the PACKET_ID_LOSSY_RANGE_*)
 */
int Crypto_Connection::send_lossy_cryptpacket(const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -1;

    if (data[0] < PACKET_ID_LOSSY_RANGE_START)
        return -1;

    if (data[0] >= (PACKET_ID_LOSSY_RANGE_START + PACKET_ID_LOSSY_RANGE_SIZE))
        return -1;

    pthread_mutex_lock(&net_crypto->connections_mutex);
    ++net_crypto->connection_use_counter;
    pthread_mutex_unlock(&net_crypto->connections_mutex);

    uint32_t buffer_start, buffer_end;
    {
        std::lock_guard<std::mutex> lock(mutex);
        buffer_start = recv_array.buffer_start;
        buffer_end = send_array.buffer_end;
    }
    int ret = send_data_packet_helper(buffer_start, buffer_end, data, length);

    pthread_mutex_lock(&net_crypto->connections_mutex);
    --net_crypto->connection_use_counter;
    pthread_mutex_unlock(&net_crypto->connections_mutex);

    return ret;
}

Crypto_Connection::~Crypto_Connection()
{
    net_crypto->crypto_connections.erase(id);
    net_crypto->id_pool.release(id);
    
    while (1) { /* TODO: is this really the best way to do this? */
        pthread_mutex_lock(&net_crypto->connections_mutex);

        if (!net_crypto->connection_use_counter) {
            break;
        }

        pthread_mutex_unlock(&net_crypto->connections_mutex);
    }

    if (status == CryptoConnectionStatus::CRYPTO_CONN_ESTABLISHED)
        send_kill_packet();

    {
        std::lock_guard<std::mutex> lock(net_crypto->tcp_mutex);
        tcp_connection.reset();
    }

    net_crypto->ip_port_list.erase(ip_portv4);
    net_crypto->ip_port_list.erase(ip_portv6);
    clear_buffer(&send_array);
    clear_buffer(&recv_array);

    pthread_mutex_unlock(&net_crypto->connections_mutex);
}

/* return one of CRYPTO_CONN_* values indicating the state of the connection.
 *
 * sets direct_connected to 1 if connection connects directly to other, 0 if it isn't.
 * sets online_tcp_relays to the number of connected tcp relays this connection has.
 */
CryptoConnectionStatus Crypto_Connection::crypto_connection_status(bool *direct_connected,
        unsigned int *online_tcp_relays) const
{
    if (direct_connected) {
        *direct_connected = false;

        uint64_t current_time = unix_time();

        if ((UDP_DIRECT_TIMEOUT + direct_lastrecv_timev4) > current_time)
            *direct_connected = true;

        if ((UDP_DIRECT_TIMEOUT + direct_lastrecv_timev6) > current_time)
            *direct_connected = true;
    }

    if (online_tcp_relays && tcp_connection) {
        tcp_connection->online_tcp_connection_from_conn();
    }

    return status;
}

void Net_Crypto::new_keys()
{
    crypto_box_keypair(self_public_key.data.data(), self_secret_key.data.data());
}

/* Save the public and private keys to the keys array.
 * Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 *
 * TODO: Save only secret key.
 */
void Net_Crypto::save_keys(uint8_t *keys) const
{
    memcpy(keys, self_public_key.data.data(), crypto_box_PUBLICKEYBYTES);
    memcpy(keys + crypto_box_PUBLICKEYBYTES, self_secret_key.data.data(), crypto_box_SECRETKEYBYTES);
}

/* Load the secret key.
 * Length must be crypto_box_SECRETKEYBYTES.
 */
void Net_Crypto::load_secret_key(const uint8_t *sk)
{
    memcpy(self_secret_key.data.data(), sk, crypto_box_SECRETKEYBYTES);
    crypto_scalarmult_curve25519_base(self_public_key.data.data(), self_secret_key.data.data());
}

/* Run this to (re)initialize net_crypto.
 * Sets all the global connection variables to their default values.
 */
Net_Crypto::Net_Crypto(DHT *dht, TCP_Proxy_Info *proxy_info, bitox::EventDispatcher *event_dispatcher) : event_dispatcher(event_dispatcher)
{
    unix_time_update();

    assert(dht && "DHT must not be null");

    tcp_c = new TCP_Connections(dht->self_secret_key, proxy_info, event_dispatcher);

    set_packet_tcp_connection_callback(tcp_c, &tcp_data_callback, this);
    set_oob_packet_tcp_connection_callback(tcp_c, &tcp_oob_callback, this);

    if (pthread_mutex_init(&connections_mutex, nullptr) != 0) {
        delete tcp_c;
        throw std::runtime_error("pthread_mutex_init error");
    }

    this->dht = dht;

    new_keys();
    new_symmetric_key(secret_symmetric_key.data.data());

    current_sleep_time = CRYPTO_SEND_PACKET_INTERVAL;
    event_dispatcher->set_net_crypto(this);
}

void Net_Crypto::kill_timedout()
{
    uint32_t i;
    //uint64_t temp_time = current_time_monotonic();

    std::vector<Crypto_Connection *> connections_to_kill;
    for (auto &kv : crypto_connections) {
        Crypto_Connection *conn = kv.second;

        if (conn->status == CryptoConnectionStatus::CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CryptoConnectionStatus::CRYPTO_CONN_HANDSHAKE_SENT
                || conn->status == CryptoConnectionStatus::CRYPTO_CONN_NOT_CONFIRMED) {
            if (conn->temp_packet_num_sent < MAX_NUM_SENDPACKET_TRIES)
                continue;
            
            connections_to_kill.push_back(conn);
        }

        if (conn->status == CryptoConnectionStatus::CRYPTO_CONN_ESTABLISHED) {
            //TODO: add a timeout here?
        }
    }
    
    for (Crypto_Connection *conn : connections_to_kill)
        conn->connection_kill();
}

/* return the optimal interval in ms for running do_net_crypto.
 */
uint32_t Net_Crypto::crypto_run_interval() const
{
    return current_sleep_time;
}

/* Main loop. */
void Net_Crypto::do_net_crypto()
{
    unix_time_update();
    kill_timedout();
    do_tcp();
    send_crypto_packets();
}

Net_Crypto::~Net_Crypto()
{
    uint32_t i;

    std::vector<Crypto_Connection *> connections_to_kill;
    for (auto &kv : crypto_connections) {
        connections_to_kill.push_back(kv.second);
    }
    
    for (Crypto_Connection *conn : connections_to_kill)
        conn->connection_kill();

    pthread_mutex_destroy(&connections_mutex);

    delete tcp_c;
    event_dispatcher->set_net_crypto(nullptr);
}
