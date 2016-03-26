/*
* onion_client.h -- Implementation of the client part of docs/Prevent_Tracking.txt
*                   (The part that uses the onion stuff to connect to the friend)
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

#ifndef ONION_CLIENT_H
#define ONION_CLIENT_H

#include "onion_announce.hpp"
#include "net_crypto.hpp"
#include "ping_array.hpp"
#include <vector>
#include <map>
#include <memory>
#include <deque>

constexpr size_t MAX_ONION_CLIENTS = 8;
constexpr size_t MAX_ONION_CLIENTS_ANNOUNCE = 12; /* Number of nodes to announce ourselves to. */
constexpr unsigned ONION_NODE_PING_INTERVAL = 15;
constexpr unsigned ONION_NODE_TIMEOUT = ONION_NODE_PING_INTERVAL * 3;

/* The interval in seconds at which to tell our friends where we are */
constexpr unsigned ONION_DHTPK_SEND_INTERVAL = 30;
constexpr unsigned DHT_DHTPK_SEND_INTERVAL = 20;

constexpr size_t NUMBER_ONION_PATHS = 6;

/* The timeout the first time the path is added and
   then for all the next consecutive times */
constexpr unsigned ONION_PATH_FIRST_TIMEOUT = 4;
constexpr unsigned ONION_PATH_TIMEOUT = 10;
constexpr unsigned ONION_PATH_MAX_LIFETIME = 1200;
constexpr size_t ONION_PATH_MAX_NO_RESPONSE_USES = 4;

constexpr size_t MAX_STORED_PINGED_NODES = 9;
constexpr unsigned MIN_NODE_PING_TIME = 10;

/* If no packets are received within that interval tox will
 * be considered offline.
 */
constexpr unsigned ONION_OFFLINE_TIMEOUT = ONION_NODE_PING_INTERVAL * 1.25;

/* Onion data packet ids. */
#define ONION_DATA_FRIEND_REQ CRYPTO_PACKET_FRIEND_REQ
#define ONION_DATA_DHTPK CRYPTO_PACKET_DHTPK

namespace bitox
{
    class EventDispatcher;
}

struct Onion_Node
{
    bitox::PublicKey public_key;
    bitox::network::IPPort     ip_port;
    bitox::OnionPingId ping_id;
    bitox::PublicKey data_public_key;
    uint8_t     is_stored;

    uint64_t    timestamp;

    uint64_t    last_pinged;

    uint32_t    path_used;
};

struct Onion_Client_Paths
{
    Onion_Path paths[NUMBER_ONION_PATHS];
    uint64_t last_path_success[NUMBER_ONION_PATHS];
    uint64_t last_path_used[NUMBER_ONION_PATHS];
    uint64_t path_creation_time[NUMBER_ONION_PATHS];
    /* number of times used without success. */
    unsigned int last_path_used_times[NUMBER_ONION_PATHS];
};

struct Last_Pinged
{
    bitox::PublicKey public_key;
    uint64_t    timestamp;
};

struct Onion_Client;
struct Onion_Friend : public std::enable_shared_from_this<Onion_Friend>
{
    Onion_Friend(Onion_Client *client, const bitox::PublicKey &real_public_key);
    ~Onion_Friend();

    /* Set a friends DHT public key */
    bool onion_set_friend_DHT_pubkey(const bitox::PublicKey &dht_key);

    /* Copy friends DHT public key into dht_key */
    bitox::PublicKey onion_getfriend_DHT_pubkey() const
    {
        return dht_public_key;
    }

    /* Get the ip of friend friendnum and put it in ip_port
    *
    *  return -1, -- if public_key does NOT refer to a friend
    *  return  0, -- if public_key refers to a friend and we failed to find the friend (yet)
    *  return  1, ip if public_key refers to a friend and we found him
    *
    */
    int onion_getfriendip(bitox::network::IPPort *ip_port);

    /* Set if friend is online or not.
    * NOTE: This function is there and should be used so that we don't send useless packets to the friend if he is online.
    *
    * is_online 1 means friend is online.
    * is_online 0 means friend is offline
    */
    void onion_set_friend_online(uint8_t is_online);

    void do_friend();

    /* Send data of length length to friendnum.
    * This data will be received by the friend using the Onion_Data_Handlers callbacks.
    *
    * Even if this function succeeds, the friend might not receive any data.
    *
    * return the number of packets sent on success
    * return -1 on failure.
    */
    int send_onion_data(const uint8_t *data, uint16_t length);

    /* Try to send the dht public key via the DHT instead of onion
    *
    * Even if this function succeeds, the friend might not receive any data.
    *
    * return the number of packets sent on success
    * return -1 on failure.
    */
    int send_dht_dhtpk(const uint8_t *data, uint16_t length);

    /* Set the function for this friend that will be callbacked with object and number
    * when that friends gives us one of the TCP relays he is connected to.
    *
    * object and number will be passed as argument to this function.
    */
    void recv_tcp_relay_handler(int (*tcp_relay_node_callback)(void *object,
                                uint32_t number, bitox::network::IPPort ip_port, const bitox::PublicKey &public_key), void *object, uint32_t number);


    /* Set the function for this friend that will be callbacked with object and number
    * when that friend gives us his DHT temporary public key.
    *
    * object and number will be passed as argument to this function.
    */
    void onion_dht_pk_callback(void (*function)(void *data, int32_t number,
                               const bitox::PublicKey &dht_public_key), void *object, uint32_t number);

    Onion_Client *const client;

    uint8_t is_online; /* Set by the onion_set_friend_status function. */

    uint8_t know_dht_public_key; /* 0 if we don't know the dht public key of the other, 1 if we do. */
    bitox::PublicKey dht_public_key;
    const bitox::PublicKey real_public_key;

    Onion_Node clients_list[MAX_ONION_CLIENTS];
    bitox::PublicKey temp_public_key;
    bitox::SecretKey temp_secret_key;

    uint64_t last_dht_pk_onion_sent;
    uint64_t last_dht_pk_dht_sent;

    uint64_t last_noreplay;

    uint64_t last_seen;

    Last_Pinged last_pinged[MAX_STORED_PINGED_NODES];
    uint8_t last_pinged_index;

    int (*tcp_relay_node_callback)(void *object, uint32_t number, bitox::network::IPPort ip_port, const bitox::PublicKey &public_key);
    void *tcp_relay_node_callback_object;
    uint32_t tcp_relay_node_callback_number;

    void (*dht_pk_callback)(void *data, int32_t number, const bitox::PublicKey &dht_public_key);
    void *dht_pk_callback_object;
    uint32_t dht_pk_callback_number;

    uint32_t run_count;

    /* Send the packets to tell our friends what our DHT public key is.
    *
    * if onion_dht_both is 0, use only the onion to send the packet.
    * if it is 1, use only the dht.
    * if it is something else, use both.
    *
    * return the number of packets sent on success
    * return -1 on failure.
    */
    int send_dhtpk_announce(uint8_t onion_dht_both);
};

typedef int (*oniondata_handler_callback)(void *object, const bitox::PublicKey &source_pubkey, const uint8_t *data,
        uint16_t len);

class Onion_Client
{
public:
    
    explicit Onion_Client(Net_Crypto *c, bitox::EventDispatcher *event_dispatcher);
    ~Onion_Client();

    /* Add a friend who we want to connect to.
    *
    * return -1 on failure.
    * return the friend number on success or if the friend was already added.
    */
    std::shared_ptr<Onion_Friend> onion_addfriend(const bitox::PublicKey &public_key);

    /* Add a node to the path_nodes bootstrap array */
    bool onion_add_bs_path_node(const bitox::network::IPPort &ip_port, const bitox::PublicKey &public_key);

    /* Put up to max_num nodes in nodes.
    *
    * return the number of nodes.
    */
    uint16_t onion_backup_nodes(bitox::dht::NodeFormat *nodes, uint16_t max_num) const;

    /* Function to call when onion data packet with contents beginning with byte is received. */
    void oniondata_registerhandler(uint8_t byte, oniondata_handler_callback cb, void *object);

    void do_onion_client();

    /*  return 0 if we are not connected to the network.
    *  return 1 if we are connected with TCP only.
    *  return 2 if we are also connected with UDP.
    */
    unsigned int onion_connection_status() const;
    
    int on_packet_announce_response(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);
    int on_packet_data_response(const bitox::network::IPPort &source, const uint8_t *packet, uint16_t length);

    DHT     *dht;
    bitox::EventDispatcher *const event_dispatcher;
    Net_Crypto *c;
    bitox::network::Networking_Core *net;

    std::map<bitox::PublicKey, Onion_Friend *> friends;

    Onion_Node clients_announce_list[MAX_ONION_CLIENTS_ANNOUNCE];

    Onion_Client_Paths onion_paths_self;
    Onion_Client_Paths onion_paths_friends;

    bitox::SymmetricKey secret_symmetric_key = bitox::SymmetricKey::create_random();
    uint64_t last_run, first_run;

    bitox::PublicKey temp_public_key;
    bitox::SecretKey temp_secret_key;

    Last_Pinged last_pinged[MAX_STORED_PINGED_NODES];

    std::deque<bitox::dht::NodeFormat> path_nodes;
    std::deque<bitox::dht::NodeFormat> path_nodes_bs;

    struct AnnounceRecord
    {
        bitox::PublicKey real_public_key;
        bitox::PublicKey public_key;
        bitox::network::IPPort ip_port;
        uint32_t path_num;
    };

    bitox::PingArray<AnnounceRecord> announce_ping_array;
    uint8_t last_pinged_index;
    struct {
        oniondata_handler_callback function;
        void *object;
    } Onion_Data_Handlers[256];

    uint64_t last_packet_recv;

    unsigned int onion_connected;
    bool UDP_connected;

//private:
    int new_sendback(Onion_Friend *onion_friend, const bitox::PublicKey &public_key, const bitox::network::IPPort &ip_port, uint32_t path_num, uint64_t *sendback);
    bool check_sendback(const uint8_t *sendback, bitox::PublicKey &ret_pubkey, bitox::network::IPPort &ret_ip_port, uint32_t &path_num, bitox::PublicKey &real_public_key_out);

    /* Add a node to the path_nodes array */
    bool onion_add_path_node(bitox::network::IPPort &ip_port, const bitox::PublicKey &public_key);

    /* Put up to max_num random nodes in nodes.
    *
    * return the number of nodes.
    */
    uint16_t random_nodes_path_onion(bitox::dht::NodeFormat *nodes, uint16_t max_num) const;

    /* Create a new path or use an old suitable one (if pathnum is valid)
    * or a random one from onion_paths.
    *
    * return -1 on failure
    * return 0 on success
    *
    * TODO: Make this function better, it currently probably is vulnerable to some attacks that
    * could de anonimize us.
    */
    int random_path(Onion_Client_Paths *onion_paths, uint32_t pathnum, Onion_Path *path) const;

    /* return true if we are connected to the network */
    bool onion_isconnected() const;

    void do_announce();

    void populate_path_nodes_tcp();

    void populate_path_nodes();

    int client_ping_nodes(Onion_Friend *onion_friend, const bitox::dht::NodeFormat *nodes, uint16_t num_nodes, bitox::network::IPPort source);

    int client_add_to_list(Onion_Friend *onion_friend, const bitox::PublicKey &public_key, bitox::network::IPPort &ip_port,
                           uint8_t is_stored, const bitox::PublicKey &pingid_or_key, uint32_t path_num);

    int client_send_announce_request(Onion_Friend *onion_friend, const bitox::network::IPPort &dest, const bitox::PublicKey &dest_pubkey,
                                     const bitox::OnionPingId &ping_id, uint32_t pathnum);

    /* Function to send onion packet via TCP and UDP.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int send_onion_packet_tcp_udp(const Onion_Path *path, const bitox::network::IPPort &dest,
                                  const uint8_t *data, uint16_t length) const;

    /* Set path timeouts, return the path number.
    *
    */
    uint32_t set_path_timeouts(Onion_Friend *onion_friend, uint32_t path_num);
};

constexpr size_t ONION_DATA_IN_RESPONSE_MIN_SIZE = bitox::PUBLIC_KEY_LEN + bitox::MAC_BYTES_LEN;
constexpr size_t ONION_CLIENT_MAX_DATA_SIZE = MAX_DATA_REQUEST_SIZE - ONION_DATA_IN_RESPONSE_MIN_SIZE;

#endif
