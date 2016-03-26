/*
* onion.h -- Implementation of the onion part of docs/Prevent_Tracking.txt
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

#ifndef ONION_H
#define ONION_H

#include "DHT.hpp"

namespace bitox
{
class EventDispatcher;
}

class Onion
{
public:
    
    Onion(DHT &dht, bitox::EventDispatcher *event_dispatcher);
    ~Onion();
    
    int on_packet_send_initial(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    int on_packet_send_1(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    int on_packet_send_2(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    int on_packet_recv_3(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    int on_packet_recv_2(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    int on_packet_recv_1(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    
    DHT &dht;
    bitox::EventDispatcher *const event_dispatcher;
    bitox::network::Networking_Core *net;
    bitox::SymmetricKey secret_symmetric_key = bitox::SymmetricKey::create_random();
    uint64_t timestamp;

    Shared_Keys shared_keys_1;
    Shared_Keys shared_keys_2;
    Shared_Keys shared_keys_3;

    int (*recv_1_function)(void *, const bitox::network::IPPort &, const uint8_t *, uint16_t);
    void *callback_object;

    void change_symmetric_key();
};

#define ONION_MAX_PACKET_SIZE 1400

#define ONION_RETURN_1 (crypto_box_NONCEBYTES + SIZE_IPPORT + crypto_box_MACBYTES)
#define ONION_RETURN_2 (crypto_box_NONCEBYTES + SIZE_IPPORT + crypto_box_MACBYTES + ONION_RETURN_1)
#define ONION_RETURN_3 (crypto_box_NONCEBYTES + SIZE_IPPORT + crypto_box_MACBYTES + ONION_RETURN_2)

#define ONION_SEND_BASE (crypto_box_PUBLICKEYBYTES + SIZE_IPPORT + crypto_box_MACBYTES)
#define ONION_SEND_3 (crypto_box_NONCEBYTES + ONION_SEND_BASE + ONION_RETURN_2)
#define ONION_SEND_2 (crypto_box_NONCEBYTES + ONION_SEND_BASE*2 + ONION_RETURN_1)
#define ONION_SEND_1 (crypto_box_NONCEBYTES + ONION_SEND_BASE*3)

#define ONION_MAX_DATA_SIZE (ONION_MAX_PACKET_SIZE - (ONION_SEND_1 + 1))
#define ONION_RESPONSE_MAX_DATA_SIZE (ONION_MAX_PACKET_SIZE - (1 + ONION_RETURN_3))

#define ONION_PATH_LENGTH 3

struct Onion_Path
{
    Onion_Path() {}
    /* Create a new onion path.
    *
    * Create a new onion path out of nodes (nodes is a list of ONION_PATH_LENGTH nodes)
    */
    explicit Onion_Path(const DHT *dht, const bitox::dht::NodeFormat *nodes);
    
    bitox::SharedKey shared_key1;
    bitox::SharedKey shared_key2;
    bitox::SharedKey shared_key3;

    bitox::PublicKey public_key1;
    bitox::PublicKey public_key2;
    bitox::PublicKey public_key3;

    bitox::network::IPPort     ip_port1;
    bitox::PublicKey node_public_key1;

    bitox::network::IPPort     ip_port2;
    bitox::PublicKey node_public_key2;

    bitox::network::IPPort     ip_port3;
    bitox::PublicKey node_public_key3;

    uint32_t path_num;

    /* Create a onion packet.
     *
     * Use Onion_Path path to create packet for data of length to dest.
     * Maximum length of data is ONION_MAX_DATA_SIZE.
     * packet should be at least ONION_MAX_PACKET_SIZE big.
     *
     * return -1 on failure.
     * return length of created packet on success.
     */
    int create_onion_packet(uint8_t *packet, uint16_t max_packet_length, const bitox::network::IPPort &dest,
                            const uint8_t *data, uint16_t length) const;
};

/* Dump nodes in onion path to nodes of length num_nodes;
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_path_to_nodes(bitox::dht::NodeFormat *nodes, unsigned int num_nodes, const Onion_Path *path);


/* Create a onion packet to be sent over tcp.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet_tcp(uint8_t *packet, uint16_t max_packet_length, const Onion_Path *path, const bitox::network::IPPort &dest,
                            const uint8_t *data, uint16_t length);

/* Create and send a onion packet.
 *
 * Use Onion_Path path to send data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_packet(bitox::network::Networking_Core *net, const Onion_Path *path, bitox::network::IPPort dest, const uint8_t *data, uint16_t length);

/* Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(bitox::network::Networking_Core *net, bitox::network::IPPort dest, const uint8_t *data, uint16_t length, const uint8_t *ret);

/* Function to handle/send received decrypted versions of the packet sent with send_onion_packet.
 *
 * return 0 on success.
 * return 1 on failure.
 *
 * Used to handle these packets that are received in a non traditional way (by TCP for example).
 *
 * Source family must be set to something else than AF_INET6 or AF_INET so that the callback gets called
 * when the response is received.
 */
int onion_send_1(const Onion *onion, const uint8_t *plain, uint16_t len, const bitox::network::IPPort &source, const uint8_t *nonce);

/* Set the callback to be called when the dest ip_port doesn't have AF_INET6 or AF_INET as the family.
 *
 * Format: function(void *object, bitox::network::IPPort dest, uint8_t *data, uint16_t length)
 */
void set_callback_handle_recv_1(Onion *onion, int (*function)(void *, const bitox::network::IPPort &, const uint8_t *, uint16_t),
                                void *object);

#endif
