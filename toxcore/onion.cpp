/*
* onion.c -- Implementation of the onion part of docs/Prevent_Tracking.txt
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

#include "onion.hpp"
#include "util.hpp"
#include "protocol_impl.hpp"
#include <cstring>

#define RETURN_1 ONION_RETURN_1
#define RETURN_2 ONION_RETURN_2
#define RETURN_3 ONION_RETURN_3

#define SEND_BASE ONION_SEND_BASE
#define SEND_3 ONION_SEND_3
#define SEND_2 ONION_SEND_2
#define SEND_1 ONION_SEND_1

using namespace bitox;
using namespace bitox::network;
using namespace bitox::dht;

/* Change symmetric keys every 2 hours to make paths expire eventually. */
#define KEY_REFRESH_INTERVAL (2 * 60 * 60)
void Onion::change_symmetric_key()
{
    if (is_timeout(timestamp, KEY_REFRESH_INTERVAL)) {
        new_symmetric_key(secret_symmetric_key);
        timestamp = unix_time();
    }
}

/* packing and unpacking functions */
static void ip_pack(uint8_t *data, const IPPort &source) // TODO
{
    /*to_net_family(&source);

    data[0] = source.family;

    if (source.family == bitox::impl::network::TOX_AF_INET || source.family == bitox::impl::network::TOX_TCP_INET) {
        memset(data + 1, 0, SIZE_IP6);
        memcpy(data + 1, source.ip4.uint8, SIZE_IP4);
    } else {
        memcpy(data + 1, source.ip6.uint8, SIZE_IP6);
    }*/
}

/* return 0 on success, -1 on failure. */
static int ip_unpack(const IPPort &target, const uint8_t *data, unsigned int data_size, _Bool disable_family_check) // TODO
{
    /*if (data_size < (1 + SIZE_IP6))
        return -1;

    target->family = data[0];

    if (target->family == bitox::impl::network::TOX_AF_INET || target->family == bitox::impl::network::TOX_TCP_INET) {
        memcpy(target->ip4.uint8, data + 1, SIZE_IP4);
    } else {
        memcpy(target->ip6.uint8, data + 1, SIZE_IP6);
    }

    if (!disable_family_check) {
        return to_host_family(target);
    } else {
        to_host_family(target);
        return 0;
    }*/
}

static void ipport_pack(uint8_t *data, const IPPort &source)
{
    ip_pack(data, source);
    memcpy(data + SIZE_IP, &source.port, SIZE_PORT);
}

/* return 0 on success, -1 on failure. */
static int ipport_unpack(IPPort &target, const uint8_t *data, unsigned int data_size, _Bool disable_family_check)
{
    if (data_size < (SIZE_IP + SIZE_PORT))
        return -1;

    if (ip_unpack(target, data, data_size, disable_family_check) == -1)
        return -1;

    memcpy(&target.port, data + SIZE_IP, SIZE_PORT);
    return 0;
}


/* Create a new onion path.
 *
 * Create a new onion path out of nodes (nodes is a list of ONION_PATH_LENGTH nodes)
 *
 * new_path must be an empty memory location of atleast Onion_Path size.
 *
 * return -1 on failure.
 * return 0 on success.
 */
Onion_Path::Onion_Path(const DHT *dht, const NodeFormat *nodes)
{
    encrypt_precompute(nodes[0].public_key, dht->self_secret_key, shared_key1.data.data());
    public_key1 = dht->self_public_key;

    PublicKey random_public_key;
    SecretKey random_secret_key;

    crypto_box_keypair(random_public_key.data.data(), random_secret_key.data.data());
    encrypt_precompute(nodes[1].public_key, random_secret_key, shared_key2.data.data());
    public_key2 = random_public_key;

    crypto_box_keypair(random_public_key.data.data(), random_secret_key.data.data());
    encrypt_precompute(nodes[2].public_key, random_secret_key, shared_key3.data.data());
    public_key3 = random_public_key;

    ip_port1 = nodes[0].ip_port;
    ip_port2 = nodes[1].ip_port;
    ip_port3 = nodes[2].ip_port;

    node_public_key1 = nodes[0].public_key;
    node_public_key2 = nodes[1].public_key;
    node_public_key3 = nodes[2].public_key;
}

/* Dump nodes in onion path to nodes of length num_nodes;
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_path_to_nodes(NodeFormat *nodes, unsigned int num_nodes, const Onion_Path *path)
{
    if (num_nodes < ONION_PATH_LENGTH)
        return -1;

    nodes[0].ip_port = path->ip_port1;
    nodes[1].ip_port = path->ip_port2;
    nodes[2].ip_port = path->ip_port3;

    nodes[0].public_key = path->node_public_key1;
    nodes[1].public_key = path->node_public_key2;
    nodes[2].public_key = path->node_public_key3;
    return 0;
}

/* Create a onion packet.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int Onion_Path::create_onion_packet(uint8_t *packet, uint16_t max_packet_length, const bitox::network::IPPort &dest,
                        const uint8_t *data, uint16_t length) const
{
    if (1 + length + SEND_1 > max_packet_length || length == 0)
        return -1;

    uint8_t step1[SIZE_IPPORT + length];

    ipport_pack(step1, dest);
    memcpy(step1 + SIZE_IPPORT, data, length);

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

    uint8_t step2[SIZE_IPPORT + SEND_BASE + length];
    ipport_pack(step2, ip_port3);
    memcpy(step2 + SIZE_IPPORT, public_key3.data.data(), crypto_box_PUBLICKEYBYTES);

    int len = encrypt_data_symmetric(shared_key3.data.data(), nonce, step1, sizeof(step1),
                                     step2 + SIZE_IPPORT + crypto_box_PUBLICKEYBYTES);

    if (len != SIZE_IPPORT + length + crypto_box_MACBYTES)
        return -1;

    uint8_t step3[SIZE_IPPORT + SEND_BASE * 2 + length];
    ipport_pack(step3, ip_port2);
    memcpy(step3 + SIZE_IPPORT, public_key2.data.data(), crypto_box_PUBLICKEYBYTES);
    len = encrypt_data_symmetric(shared_key2.data.data(), nonce, step2, sizeof(step2),
                                 step3 + SIZE_IPPORT + crypto_box_PUBLICKEYBYTES);

    if (len != SIZE_IPPORT + SEND_BASE + length + crypto_box_MACBYTES)
        return -1;

    packet[0] = NET_PACKET_ONION_SEND_INITIAL;
    memcpy(packet + 1, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + 1 + crypto_box_NONCEBYTES, public_key1.data.data(), crypto_box_PUBLICKEYBYTES);

    len = encrypt_data_symmetric(shared_key1.data.data(), nonce, step3, sizeof(step3),
                                 packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES);

    if (len != SIZE_IPPORT + SEND_BASE * 2 + length + crypto_box_MACBYTES)
        return -1;

    return 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + len;
}

/* Create a onion packet to be sent over tcp.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet_tcp(uint8_t *packet, uint16_t max_packet_length, const Onion_Path *path, const IPPort &dest,
                            const uint8_t *data, uint16_t length)
{
    if (crypto_box_NONCEBYTES + SIZE_IPPORT + SEND_BASE * 2 + length > max_packet_length || length == 0)
        return -1;

    uint8_t step1[SIZE_IPPORT + length];

    ipport_pack(step1, dest);
    memcpy(step1 + SIZE_IPPORT, data, length);

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

    uint8_t step2[SIZE_IPPORT + SEND_BASE + length];
    ipport_pack(step2, path->ip_port3);
    memcpy(step2 + SIZE_IPPORT, path->public_key3.data.data(), crypto_box_PUBLICKEYBYTES);

    int len = encrypt_data_symmetric(path->shared_key3.data.data(), nonce, step1, sizeof(step1),
                                     step2 + SIZE_IPPORT + crypto_box_PUBLICKEYBYTES);

    if (len != SIZE_IPPORT + length + crypto_box_MACBYTES)
        return -1;

    ipport_pack(packet + crypto_box_NONCEBYTES, path->ip_port2);
    memcpy(packet + crypto_box_NONCEBYTES + SIZE_IPPORT, path->public_key2.data.data(), crypto_box_PUBLICKEYBYTES);
    len = encrypt_data_symmetric(path->shared_key2.data.data(), nonce, step2, sizeof(step2),
                                 packet + crypto_box_NONCEBYTES + SIZE_IPPORT + crypto_box_PUBLICKEYBYTES);

    if (len != SIZE_IPPORT + SEND_BASE + length + crypto_box_MACBYTES)
        return -1;

    memcpy(packet, nonce, crypto_box_NONCEBYTES);

    return crypto_box_NONCEBYTES + SIZE_IPPORT + crypto_box_PUBLICKEYBYTES + len;
}

/* Create and send a onion packet.
 *
 * Use Onion_Path path to send data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_packet(Networking_Core *net, const Onion_Path *path, IPPort dest, const uint8_t *data, uint16_t length)
{
    uint8_t packet[ONION_MAX_PACKET_SIZE];
    int len = path->create_onion_packet(packet, sizeof(packet), dest, data, length);

    if (len == -1)
        return -1;

    if (sendpacket(net, path->ip_port1, packet, len) != len)
        return -1;

    return 0;
}

/* Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(Networking_Core *net, IPPort dest, const uint8_t *data, uint16_t length, const uint8_t *ret)
{
    if (length > ONION_RESPONSE_MAX_DATA_SIZE || length == 0)
        return -1;

    uint8_t packet[1 + RETURN_3 + length];
    packet[0] = NET_PACKET_ONION_RECV_3;
    memcpy(packet + 1, ret, RETURN_3);
    memcpy(packet + 1 + RETURN_3, data, length);

    if ((uint32_t)sendpacket(net, dest, packet, sizeof(packet)) != sizeof(packet))
        return -1;

    return 0;
}

static int handle_send_initial(void *object, const IPPort &source, const uint8_t *packet, uint16_t length)
{
    Onion *onion = (Onion *) object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + SEND_1)
        return 1;

    onion->change_symmetric_key();

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    bitox::SharedKey shared_key;
    get_shared_key(&onion->shared_keys_1, shared_key, onion->dht.self_secret_key, PublicKey(packet + 1 + crypto_box_NONCEBYTES));
    int len = decrypt_data_symmetric(shared_key.data.data(), packet + 1, packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                                     length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES), plain);

    if (len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES))
        return 1;

    return onion_send_1(onion, plain, len, source, packet + 1);
}

int onion_send_1(const Onion *onion, const uint8_t *plain, uint16_t len, const IPPort &source, const uint8_t *nonce)
{
    if (len > ONION_MAX_PACKET_SIZE + SIZE_IPPORT - (1 + crypto_box_NONCEBYTES + ONION_RETURN_1))
        return 1;

    if (len <= SIZE_IPPORT + SEND_BASE * 2)
        return 1;

    IPPort send_to;

    if (ipport_unpack(send_to, plain, len, 0) == -1)
        return 1;

    uint8_t ip_port[SIZE_IPPORT];
    ipport_pack(ip_port, source);

    uint8_t data[ONION_MAX_PACKET_SIZE];
    data[0] = NET_PACKET_ONION_SEND_1;
    memcpy(data + 1, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + crypto_box_NONCEBYTES, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint16_t data_len = 1 + crypto_box_NONCEBYTES + (len - SIZE_IPPORT);
    uint8_t *ret_part = data + data_len;
    new_nonce(ret_part);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ip_port, SIZE_IPPORT,
                                 ret_part + crypto_box_NONCEBYTES);

    if (len != SIZE_IPPORT + crypto_box_MACBYTES)
        return 1;

    data_len += crypto_box_NONCEBYTES + len;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_send_1(void *object, const IPPort &source, const uint8_t *packet, uint16_t length)
{
    Onion *onion = (Onion *) object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + SEND_2)
        return 1;

    onion->change_symmetric_key();

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    SharedKey shared_key;
    get_shared_key(&onion->shared_keys_2, shared_key, onion->dht.self_secret_key, PublicKey(packet + 1 + crypto_box_NONCEBYTES));
    int len = decrypt_data_symmetric(shared_key.data.data(), packet + 1, packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                                     length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_1), plain);

    if (len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_1 + crypto_box_MACBYTES))
        return 1;

    IPPort send_to;

    if (ipport_unpack(send_to, plain, len, 0) == -1)
        return 1;

    uint8_t data[ONION_MAX_PACKET_SIZE];
    data[0] = NET_PACKET_ONION_SEND_2;
    memcpy(data + 1, packet + 1, crypto_box_NONCEBYTES);
    memcpy(data + 1 + crypto_box_NONCEBYTES, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint16_t data_len = 1 + crypto_box_NONCEBYTES + (len - SIZE_IPPORT);
    uint8_t *ret_part = data + data_len;
    new_nonce(ret_part);
    uint8_t ret_data[RETURN_1 + SIZE_IPPORT];
    ipport_pack(ret_data, source);
    memcpy(ret_data + SIZE_IPPORT, packet + (length - RETURN_1), RETURN_1);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ret_data, sizeof(ret_data),
                                 ret_part + crypto_box_NONCEBYTES);

    if (len != RETURN_2 - crypto_box_NONCEBYTES)
        return 1;

    data_len += crypto_box_NONCEBYTES + len;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_send_2(void *object, const IPPort &source, const uint8_t *packet, uint16_t length)
{
    Onion *onion = (Onion *) object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + SEND_3)
        return 1;

    onion->change_symmetric_key();

    uint8_t plain[ONION_MAX_PACKET_SIZE];
    SharedKey shared_key;
    get_shared_key(&onion->shared_keys_3, shared_key, onion->dht.self_secret_key, PublicKey(packet + 1 + crypto_box_NONCEBYTES));
    int len = decrypt_data_symmetric(shared_key.data.data(), packet + 1, packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                                     length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_2), plain);

    if (len != length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + RETURN_2 + crypto_box_MACBYTES))
        return 1;

    IPPort send_to;

    if (ipport_unpack(send_to, plain, len, 0) == -1)
        return 1;

    uint8_t data[ONION_MAX_PACKET_SIZE];
    memcpy(data, plain + SIZE_IPPORT, len - SIZE_IPPORT);
    uint16_t data_len = (len - SIZE_IPPORT);
    uint8_t *ret_part = data + (len - SIZE_IPPORT);
    new_nonce(ret_part);
    uint8_t ret_data[RETURN_2 + SIZE_IPPORT];
    ipport_pack(ret_data, source);
    memcpy(ret_data + SIZE_IPPORT, packet + (length - RETURN_2), RETURN_2);
    len = encrypt_data_symmetric(onion->secret_symmetric_key, ret_part, ret_data, sizeof(ret_data),
                                 ret_part + crypto_box_NONCEBYTES);

    if (len != RETURN_3 - crypto_box_NONCEBYTES)
        return 1;

    data_len += RETURN_3;

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}


static int handle_recv_3(void *object, const IPPort &source, const uint8_t *packet, uint16_t length)
{
    Onion *onion = (Onion *) object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + RETURN_3)
        return 1;

    onion->change_symmetric_key();

    uint8_t plain[SIZE_IPPORT + RETURN_2];
    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES,
                                     SIZE_IPPORT + RETURN_2 + crypto_box_MACBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    IPPort send_to;

    if (ipport_unpack(send_to, plain, len, 0) == -1)
        return 1;

    uint8_t data[ONION_MAX_PACKET_SIZE];
    data[0] = NET_PACKET_ONION_RECV_2;
    memcpy(data + 1, plain + SIZE_IPPORT, RETURN_2);
    memcpy(data + 1 + RETURN_2, packet + 1 + RETURN_3, length - (1 + RETURN_3));
    uint16_t data_len = 1 + RETURN_2 + (length - (1 + RETURN_3));

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_recv_2(void *object, const IPPort &source, const uint8_t *packet, uint16_t length)
{
    Onion *onion = (Onion *) object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + RETURN_2)
        return 1;

    onion->change_symmetric_key();

    uint8_t plain[SIZE_IPPORT + RETURN_1];
    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES,
                                     SIZE_IPPORT + RETURN_1 + crypto_box_MACBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    IPPort send_to;

    if (ipport_unpack(send_to, plain, len, 0) == -1)
        return 1;

    uint8_t data[ONION_MAX_PACKET_SIZE];
    data[0] = NET_PACKET_ONION_RECV_1;
    memcpy(data + 1, plain + SIZE_IPPORT, RETURN_1);
    memcpy(data + 1 + RETURN_1, packet + 1 + RETURN_2, length - (1 + RETURN_2));
    uint16_t data_len = 1 + RETURN_1 + (length - (1 + RETURN_2));

    if ((uint32_t)sendpacket(onion->net, send_to, data, data_len) != data_len)
        return 1;

    return 0;
}

static int handle_recv_1(void *object, const IPPort &source, const uint8_t *packet, uint16_t length)
{
    Onion *onion = (Onion *) object;

    if (length > ONION_MAX_PACKET_SIZE)
        return 1;

    if (length <= 1 + RETURN_1)
        return 1;

    onion->change_symmetric_key();

    uint8_t plain[SIZE_IPPORT];
    int len = decrypt_data_symmetric(onion->secret_symmetric_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES,
                                     SIZE_IPPORT + crypto_box_MACBYTES, plain);

    if ((uint32_t)len != SIZE_IPPORT)
        return 1;

    IPPort send_to;

    if (ipport_unpack(send_to, plain, len, 1) == -1)
        return 1;

    uint16_t data_len = length - (1 + RETURN_1);

    if (onion->recv_1_function && send_to.ip.family != Family::FAMILY_AF_INET && send_to.ip.family != Family::FAMILY_AF_INET6)
        return onion->recv_1_function(onion->callback_object, send_to, packet + (1 + RETURN_1), data_len);

    if ((uint32_t)sendpacket(onion->net, send_to, packet + (1 + RETURN_1), data_len) != data_len)
        return 1;

    return 0;
}

void set_callback_handle_recv_1(Onion *onion, int (*function)(void *, IPPort, const uint8_t *, uint16_t), void *object)
{
    onion->recv_1_function = function;
    onion->callback_object = object;
}

Onion::Onion(DHT &dht) : dht(dht)
{
    this->net = dht.net;
    new_symmetric_key(this->secret_symmetric_key);
    this->timestamp = unix_time();

    networking_registerhandler(net, NET_PACKET_ONION_SEND_INITIAL, &handle_send_initial, this);
    networking_registerhandler(net, NET_PACKET_ONION_SEND_1, &handle_send_1, this);
    networking_registerhandler(net, NET_PACKET_ONION_SEND_2, &handle_send_2, this);

    networking_registerhandler(net, NET_PACKET_ONION_RECV_3, &handle_recv_3, this);
    networking_registerhandler(net, NET_PACKET_ONION_RECV_2, &handle_recv_2, this);
    networking_registerhandler(net, NET_PACKET_ONION_RECV_1, &handle_recv_1, this);
}

Onion::~Onion()
{
    networking_registerhandler(net, NET_PACKET_ONION_SEND_INITIAL, NULL, NULL);
    networking_registerhandler(net, NET_PACKET_ONION_SEND_1, NULL, NULL);
    networking_registerhandler(net, NET_PACKET_ONION_SEND_2, NULL, NULL);

    networking_registerhandler(net, NET_PACKET_ONION_RECV_3, NULL, NULL);
    networking_registerhandler(net, NET_PACKET_ONION_RECV_2, NULL, NULL);
    networking_registerhandler(net, NET_PACKET_ONION_RECV_1, NULL, NULL);
}
