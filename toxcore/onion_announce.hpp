/*
* onion_announce.h -- Implementation of the announce part of docs/Prevent_Tracking.txt
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

#ifndef ONION_ANNOUNCE_H
#define ONION_ANNOUNCE_H

#include "onion.hpp"
#include "protocol.hpp"

#define ONION_ANNOUNCE_MAX_ENTRIES 160
#define ONION_ANNOUNCE_TIMEOUT 300
#define ONION_PING_ID_SIZE crypto_hash_sha256_BYTES

#define ONION_ANNOUNCE_SENDBACK_DATA_LENGTH (sizeof(uint64_t))

#define ONION_ANNOUNCE_REQUEST_SIZE (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + ONION_PING_ID_SIZE + crypto_box_PUBLICKEYBYTES + crypto_box_PUBLICKEYBYTES + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_MACBYTES)

#define ONION_ANNOUNCE_RESPONSE_MIN_SIZE (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES + 1 + ONION_PING_ID_SIZE + crypto_box_MACBYTES)
#define ONION_ANNOUNCE_RESPONSE_MAX_SIZE (ONION_ANNOUNCE_RESPONSE_MIN_SIZE + sizeof(bitox::dht::NodeFormat)*MAX_SENT_NODES)

#define ONION_DATA_RESPONSE_MIN_SIZE (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)

#if ONION_PING_ID_SIZE != crypto_box_PUBLICKEYBYTES
#error announce response packets assume that ONION_PING_ID_SIZE is equal to crypto_box_PUBLICKEYBYTES
#endif

#define ONION_DATA_REQUEST_MIN_SIZE (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)
#define MAX_DATA_REQUEST_SIZE (ONION_MAX_DATA_SIZE - ONION_DATA_REQUEST_MIN_SIZE)

namespace bitox
{
class EventDispatcher;
}

struct Onion_Announce_Entry
{
    bitox::PublicKey public_key;
    bitox::network::IPPort ret_ip_port;
    uint8_t ret[ONION_RETURN_3];
    bitox::PublicKey data_public_key;
    uint64_t time;
};

class Onion_Announce
{
public:
    Onion_Announce(DHT *dht, bitox::EventDispatcher *event_dispatcher);
    ~Onion_Announce();
    
    int on_announce_request (const bitox::network::IPPort &source, const bitox::PublicKey &sender_public_key, const bitox::AnnounceRequestData &data);
    int on_packet_announce_request(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    int on_packet_data_request(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    
    DHT     *dht;
    bitox::EventDispatcher *const event_dispatcher;
    bitox::network::Networking_Core *net;
    Onion_Announce_Entry entries[ONION_ANNOUNCE_MAX_ENTRIES];
    /* This is crypto_box_KEYBYTES long just so we can use new_symmetric_key() to fill it */
    bitox::SymmetricKey secret_bytes = bitox::SymmetricKey::create_random();

    Shared_Keys shared_keys_recv;
};

/* Create an onion announce request packet in packet of max_packet_length (recommended size ONION_ANNOUNCE_REQUEST_SIZE).
 *
 * dest_client_id is the public key of the node the packet will be sent to.
 * public_key and secret_key is the kepair which will be used to encrypt the request.
 * ping_id is the ping id that will be sent in the request.
 * client_id is the client id of the node we are searching for.
 * data_public_key is the public key we want others to encrypt their data packets with.
 * sendback_data is the data of ONION_ANNOUNCE_SENDBACK_DATA_LENGTH length that we expect to
 * receive back in the response.
 *
 * return -1 on failure.
 * return packet length on success.
 */
int create_announce_request(uint8_t *packet, uint16_t max_packet_length, const bitox::PublicKey &dest_client_id,
                            const bitox::PublicKey &public_key, const bitox::SecretKey &secret_key, const bitox::OnionPingId &ping_id, const bitox::PublicKey &client_id,
                            const bitox::PublicKey &data_public_key, uint64_t sendback_data);

/* Create an onion data request packet in packet of max_packet_length (recommended size ONION_MAX_PACKET_SIZE).
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * encrypt_public_key is the public key used to encrypt the data packet.
 *
 * nonce is the nonce to encrypt this packet with
 *
 * return -1 on failure.
 * return 0 on success.
 */
int create_data_request(uint8_t *packet, uint16_t max_packet_length, const bitox::PublicKey &public_key,
                        const bitox::PublicKey &encrypt_public_key, const uint8_t *nonce, const uint8_t *data, uint16_t length);

/* Create and send an onion announce request packet.
 *
 * path is the path the request will take before it is sent to dest.
 *
 * public_key and secret_key is the kepair which will be used to encrypt the request.
 * ping_id is the ping id that will be sent in the request.
 * client_id is the client id of the node we are searching for.
 * data_public_key is the public key we want others to encrypt their data packets with.
 * sendback_data is the data of ONION_ANNOUNCE_SENDBACK_DATA_LENGTH length that we expect to
 * receive back in the response.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_announce_request(bitox::network::Networking_Core *net, const Onion_Path *path, bitox::dht::NodeFormat dest, const bitox::PublicKey &public_key,
                          const bitox::SecretKey &secret_key, const bitox::OnionPingId &ping_id, const bitox::PublicKey &client_id, const bitox::PublicKey &data_public_key,
                          uint64_t sendback_data);

/* Create and send an onion data request packet.
 *
 * path is the path the request will take before it is sent to dest.
 * (if dest knows the person with the public_key they should
 * send the packet to that person in the form of a response)
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * encrypt_public_key is the public key used to encrypt the data packet.
 *
 * nonce is the nonce to encrypt this packet with
 *
 * The maximum length of data is MAX_DATA_REQUEST_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_data_request(bitox::network::Networking_Core *net, const Onion_Path *path, bitox::network::IPPort dest, const bitox::PublicKey &public_key,
                      const bitox::PublicKey &encrypt_public_key, const uint8_t *nonce, const uint8_t *data, uint16_t length);

#endif
