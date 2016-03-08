/* friend_connection.h
 *
 * Connection to friends.
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


#ifndef FRIEND_CONNECTION_H
#define FRIEND_CONNECTION_H

#include "net_crypto.hpp"
#include "DHT.hpp"
#include "LAN_discovery.hpp"
#include "onion_client.hpp"
#include <map>
#include <memory>

#define MAX_FRIEND_CONNECTION_CALLBACKS 2
#define MESSENGER_CALLBACK_INDEX 0
#define GROUPCHAT_CALLBACK_INDEX 1

#define PACKET_ID_ALIVE 16
#define PACKET_ID_SHARE_RELAYS 17
#define PACKET_ID_FRIEND_REQUESTS 18

/* Interval between the sending of ping packets. */
#define FRIEND_PING_INTERVAL 8

/* If no packets are received from friend in this time interval, kill the connection. */
#define FRIEND_CONNECTION_TIMEOUT (FRIEND_PING_INTERVAL * 4)

/* Time before friend is removed from the DHT after last hearing about him. */
#define FRIEND_DHT_TIMEOUT BAD_NODE_TIMEOUT

#define FRIEND_MAX_STORED_TCP_RELAYS (MAX_FRIEND_TCP_CONNECTIONS * 4)

/* Max number of tcp relays sent to friends */
#define MAX_SHARED_RELAYS (RECOMMENDED_FRIEND_TCP_CONNECTIONS)

/* Interval between the sending of tcp relay information */
#define SHARE_RELAYS_INTERVAL (5 * 60)


enum class FriendConnectionStatus
{
    FRIENDCONN_STATUS_NONE,
    FRIENDCONN_STATUS_CONNECTING,
    FRIENDCONN_STATUS_CONNECTED
};

struct Friend_Connections;

struct Friend_Conn : public std::enable_shared_from_this<Friend_Conn>, public CryptoConnectionEventListener
{
    Friend_Conn(Friend_Connections *connections, const bitox::PublicKey &real_public_key);
    ~Friend_Conn();
    
    /* Send a Friend request packet.
    *
    *  return -1 if failure.
    *  return  0 if it sent the friend request directly to the friend.
    *  return the number of peers it was routed through if it did not send it directly.
    */
    int send_friend_request_packet(uint32_t nospam_num, const uint8_t *data, uint16_t length);
    
    /* Add a TCP relay associated to the friend.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int friend_add_tcp_relay(bitox::network::IPPort ip_port, const bitox::PublicKey &public_key);
    
    Friend_Connections * const connections;
    
    FriendConnectionStatus status;

    const bitox::PublicKey real_public_key;
    bitox::PublicKey dht_temp_pk;
    uint16_t dht_lock;
    bitox::network::IPPort dht_ip_port;
    uint64_t dht_pk_lastrecv, dht_ip_port_lastrecv;

    int onion_friendnum = -1;
    std::shared_ptr<Crypto_Connection> crypt_connection;

    uint64_t ping_lastrecv, ping_lastsent;
    uint64_t share_relays_lastsent;

    ConnectionEventListener *event_listener = nullptr;

    bitox::dht::NodeFormat tcp_relays[FRIEND_MAX_STORED_TCP_RELAYS];
    uint16_t tcp_relay_counter;

    bool hosting_tcp_relay;
    
    virtual int on_status(uint8_t status) override;
    virtual int on_data(uint8_t *data, uint16_t length) override;
    virtual int on_lossy_data(uint8_t *data, uint16_t length) override;
    virtual void on_dht_pk(const bitox::PublicKey &dht_public_key) override;
    
// private:
    unsigned int send_relays();
    
    void connect_to_saved_tcp_relays(unsigned int number);
    int friend_new_connection();
    void change_dht_pk(const bitox::PublicKey &dht_public_key);
    int send_ping();
};


struct Friend_Connections
{
    Friend_Connections(Onion_Client *onion_c);
    ~Friend_Connections();
    
    /* Create a new friend connection.
    * If one to that real public key already exists, increase lock count and return it.
    *
    * return -1 on failure.
    * return connection id on success.
    */
    std::shared_ptr<Friend_Conn> new_friend_connection(const bitox::PublicKey &real_public_key);

    Net_Crypto *net_crypto;
    DHT *dht;
    Onion_Client *onion_c;

    std::map<bitox::PublicKey, Friend_Conn *> connections_map;

    int (*fr_request_callback)(void *object, const bitox::PublicKey &source_pubkey, const uint8_t *data, uint16_t len);
    void *fr_request_object;

    uint64_t last_LANdiscovery;
    
    void do_friend_connections();
    
// private:
    void LANdiscovery();
};

/* Set friend request callback.
 *
 * This function will be called every time a friend request is received.
 */
void set_friend_request_callback(Friend_Connections *fr_c, int (*fr_request_callback)(void *, const bitox::PublicKey &,
                                 const uint8_t *, uint16_t), void *object);

#endif
