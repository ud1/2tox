/* net_crypto.h
 *
 * Functions for the core network crypto.
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

#ifndef NET_CRYPTO_H
#define NET_CRYPTO_H

#include "DHT.hpp"
#include "LAN_discovery.hpp"
#include "TCP_connection.hpp"
#include <pthread.h>
#include <map>
#include <mutex>
#include <vector>

/* Maximum size of receiving and sending packet buffers. */
#define CRYPTO_PACKET_BUFFER_SIZE 32768 /* Must be a power of 2 */

/* Minimum packet rate per second. */
#define CRYPTO_PACKET_MIN_RATE 4.0

/* Minimum packet queue max length. */
#define CRYPTO_MIN_QUEUE_LENGTH 64

/* Maximum total size of packets that net_crypto sends. */
#define MAX_CRYPTO_PACKET_SIZE 1400

#define CRYPTO_DATA_PACKET_MIN_SIZE (1 + sizeof(uint16_t) + (sizeof(uint32_t) + sizeof(uint32_t)) + crypto_box_MACBYTES)

/* Max size of data in packets */
#define MAX_CRYPTO_DATA_SIZE (MAX_CRYPTO_PACKET_SIZE - CRYPTO_DATA_PACKET_MIN_SIZE)

/* Interval in ms between sending cookie request/handshake packets. */
#define CRYPTO_SEND_PACKET_INTERVAL 1000

/* The maximum number of times we try to send the cookie request and handshake
   before giving up. */
#define MAX_NUM_SENDPACKET_TRIES 8

/* The timeout of no received UDP packets before the direct UDP connection is considered dead. */
#define UDP_DIRECT_TIMEOUT ((MAX_NUM_SENDPACKET_TRIES * CRYPTO_SEND_PACKET_INTERVAL) / 1000)

#define PACKET_ID_PADDING 0 /* Denotes padding */
#define PACKET_ID_REQUEST 1 /* Used to request unreceived packets */
#define PACKET_ID_KILL    2 /* Used to kill connection */

/* Packet ids 0 to CRYPTO_RESERVED_PACKETS - 1 are reserved for use by net_crypto. */
#define CRYPTO_RESERVED_PACKETS 16

#define MAX_TCP_CONNECTIONS 64
#define MAX_TCP_RELAYS_PEER 4

/* All packets starting with a byte in this range are considered lossy packets. */
#define PACKET_ID_LOSSY_RANGE_START 192
#define PACKET_ID_LOSSY_RANGE_SIZE 63

#define CRYPTO_MAX_PADDING 8 /* All packets will be padded a number of bytes based on this number. */

/* Base current transfer speed on last CONGESTION_QUEUE_ARRAY_SIZE number of points taken
   at the dT defined in net_crypto.c */
#define CONGESTION_QUEUE_ARRAY_SIZE 12
#define CONGESTION_LAST_SENT_ARRAY_SIZE (CONGESTION_QUEUE_ARRAY_SIZE * 2)

/* Default connection ping in ms. */
#define DEFAULT_PING_CONNECTION 1000
#define DEFAULT_TCP_PING_CONNECTION 500

typedef struct {
    uint64_t sent_time;
    uint16_t length;
    uint8_t data[MAX_CRYPTO_DATA_SIZE];
} Packet_Data;

typedef struct {
    Packet_Data *buffer[CRYPTO_PACKET_BUFFER_SIZE];
    uint32_t  buffer_start = 0;
    uint32_t  buffer_end = 0; /* packet numbers in array: {buffer_start, buffer_end) */
} Packets_Array;

enum class CryptoConnectionStatus
{
    // No connection
    CRYPTO_CONN_NO_CONNECTION = 0,
    
    // We are sending cookie request packets
    CRYPTO_CONN_COOKIE_REQUESTING = 1,
    
    // We are sending handshake packet
    CRYPTO_CONN_HANDSHAKE_SENT = 2,
    
    // Connection is not confirmed yet (we have received a handshake but no data packets yet)
    CRYPTO_CONN_NOT_CONFIRMED = 3,
    
    // The connection is established
    CRYPTO_CONN_ESTABLISHED = 4
};

struct Crypto_Connection
{
    bitox::PublicKey public_key; /* The real public key of the peer. */
    bitox::Nonce recv_nonce = bitox::Nonce::create_empty(); /* Nonce of received packets. */
    bitox::Nonce sent_nonce = bitox::Nonce::create_empty(); /* Nonce of sent packets. */
    bitox::PublicKey sessionpublic_key; /* Our public key for this session. */
    bitox::SecretKey sessionsecret_key; /* Our private key for this session. */
    bitox::PublicKey peersessionpublic_key; /* The public key of the peer. */
    bitox::SharedKey shared_key; /* The precomputed shared key from encrypt_precompute. */
    CryptoConnectionStatus status = CryptoConnectionStatus::CRYPTO_CONN_NO_CONNECTION;
    uint64_t cookie_request_number = 0; /* number used in the cookie request packets for this connection */
    bitox::PublicKey dht_public_key; /* The dht public key of the peer */

    std::vector<uint8_t> temp_packet; /* Where the cookie request/handshake packet is stored while it is being sent. */
    uint64_t temp_packet_sent_time = 0; /* The time at which the last temp_packet was sent in ms. */
    uint32_t temp_packet_num_sent = 0;

    bitox::network::IPPort ip_portv4; /* The ip and port to contact this guy directly.*/
    bitox::network::IPPort ip_portv6;
    uint64_t direct_lastrecv_timev4 = 0; /* The Time at which we last received a direct packet in ms. */
    uint64_t direct_lastrecv_timev6 = 0;

    uint64_t last_tcp_sent = 0; /* Time the last TCP packet was sent. */

    Packets_Array send_array;
    Packets_Array recv_array;

    int (*connection_status_callback)(void *object, int id, uint8_t status) = nullptr;
    void *connection_status_callback_object = nullptr;
    int connection_status_callback_id = 0;

    int (*connection_data_callback)(void *object, int id, uint8_t *data, uint16_t length) = nullptr;
    void *connection_data_callback_object;
    int connection_data_callback_id = 0;

    int (*connection_lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length) = nullptr;
    void *connection_lossy_data_callback_object;
    int connection_lossy_data_callback_id = 0;

    uint64_t last_request_packet_sent = 0;
    uint64_t direct_send_attempt_time = 0;

    uint32_t packet_counter = 0;
    double packet_recv_rate = 0;
    uint64_t packet_counter_set = 0;

    double packet_send_rate = 0;
    uint32_t packets_left = 0;
    uint64_t last_packets_left_set = 0;
    double last_packets_left_rem = 0;

    double packet_send_rate_requested = 0;
    uint32_t packets_left_requested = 0;
    uint64_t last_packets_left_requested_set = 0;
    double last_packets_left_requested_rem = 0;

    uint32_t last_sendqueue_size[CONGESTION_QUEUE_ARRAY_SIZE], last_sendqueue_counter;
    long signed int last_num_packets_sent[CONGESTION_LAST_SENT_ARRAY_SIZE],
         last_num_packets_resent[CONGESTION_LAST_SENT_ARRAY_SIZE];
    uint32_t packets_sent = 0, packets_resent = 0;
    uint64_t last_congestion_event = 0;
    uint64_t rtt_time = 0;

    /* TCP_connection connection_number */
    unsigned int connection_number_tcp = 0;

    uint8_t maximum_speed_reached = 0;

    std::mutex mutex;

    void (*dht_pk_callback)(void *data, int32_t number, const bitox::PublicKey &dht_public_key) = nullptr;
    void *dht_pk_callback_object = nullptr;
    uint32_t dht_pk_callback_number = 0;
};

struct New_Connection
{
    bitox::network::IPPort source;
    bitox::PublicKey public_key; /* The real public key of the peer. */
    bitox::PublicKey dht_public_key; /* The dht public key of the peer. */
    bitox::Nonce recv_nonce = bitox::Nonce::create_empty(); /* Nonce of received packets. */
    bitox::PublicKey peersessionpublic_key; /* The public key of the peer. */
    std::vector<uint8_t> cookie;
};

struct Net_Crypto
{
    /* Create new instance of Net_Crypto.
    *  Sets all the global connection variables to their default values.
    */
    Net_Crypto(DHT *dht, TCP_Proxy_Info *proxy_info);
    
    ~Net_Crypto();

    /* Accept a crypto connection.
    *
    * return -1 on failure.
    * return connection id on success.
    */
    int accept_crypto_connection(New_Connection *n_c);
    
    /* Create a crypto connection.
    * If one to that real public key already exists, return it.
    *
    * return -1 on failure.
    * return connection id on success.
    */
    int new_crypto_connection(const bitox::PublicKey &real_public_key, const bitox::PublicKey &dht_public_key);
    
    /* Set the direct ip of the crypto connection.
    *
    * Connected is 0 if we are not sure we are connected to that person, 1 if we are sure.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int set_direct_ip_port(int crypt_connection_id, bitox::network::IPPort ip_port, bool connected);
    
    /* returns the number of packet slots left in the sendbuffer.
    * return 0 if failure.
    */
    uint32_t crypto_num_free_sendqueue_slots(int crypt_connection_id);
    
    /* Return 1 if max speed was reached for this connection (no more data can be physically through the pipe).
    * Return 0 if it wasn't reached.
    */
    bool max_speed_reached(int crypt_connection_id);

    /* Sends a lossless cryptopacket.
    *
    * return -1 if data could not be put in packet queue.
    * return positive packet number if data was put into the queue.
    *
    * The first byte of data must be in the CRYPTO_RESERVED_PACKETS to PACKET_ID_LOSSY_RANGE_START range.
    *
    * congestion_control: should congestion control apply to this packet?
    */
    int64_t write_cryptpacket(int crypt_connection_id, const uint8_t *data, uint16_t length,
                            uint8_t congestion_control);
    
    /* Check if packet_number was received by the other side.
    *
    * packet_number must be a valid packet number of a packet sent on this connection.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int cryptpacket_received(int crypt_connection_id, uint32_t packet_number);

    /* return -1 on failure.
    * return 0 on success.
    *
    * Sends a lossy cryptopacket. (first byte must in the PACKET_ID_LOSSY_RANGE_*)
    */
    int send_lossy_cryptpacket(int crypt_connection_id, const uint8_t *data, uint16_t length);

    /* Add a tcp relay, associating it to a crypt_connection_id.
    *
    * return 0 if it was added.
    * return -1 if it wasn't.
    */
    int add_tcp_relay_peer(int crypt_connection_id, bitox::network::IPPort ip_port, const bitox::PublicKey &public_key);

    /* Add a tcp relay to the array.
    *
    * return 0 if it was added.
    * return -1 if it wasn't.
    */
    int add_tcp_relay(bitox::network::IPPort ip_port, const bitox::PublicKey &public_key);

    /* Return a random TCP connection number for use in send_tcp_onion_request.
    *
    * return TCP connection number on success.
    * return -1 on failure.
    */
    int get_random_tcp_con_number();

    /* Send an onion packet via the TCP relay corresponding to TCP_conn_number.
    *
    * return 0 on success.
    * return -1 on failure.
    */
    int send_tcp_onion_request(unsigned int TCP_conn_number, const uint8_t *data, uint16_t length);

    /* Copy a maximum of num TCP relays we are connected to to tcp_relays.
    * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
    *
    * return number of relays copied to tcp_relays on success.
    * return 0 on failure.
    */
    unsigned int copy_connected_tcp_relays(bitox::dht::NodeFormat *tcp_relays, uint16_t num);
    
    /* return one of CRYPTO_CONN_* values indicating the state of the connection.
    *
    * sets direct_connected to 1 if connection connects directly to other, 0 if it isn't.
    * sets online_tcp_relays to the number of connected tcp relays this connection has.
    */
    CryptoConnectionStatus crypto_connection_status(int crypt_connection_id, bool *direct_connected,
                                        unsigned int *online_tcp_relays);

    /* Generate our public and private keys.
    *  Only call this function the first time the program starts.
    */
    void new_keys();

    /* Save the public and private keys to the keys array.
    *  Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
    */
    void save_keys(uint8_t *keys) const;

    /* Load the secret key.
    * Length must be crypto_box_SECRETKEYBYTES.
    */
    void load_secret_key(const uint8_t *sk);
    
    /* Kill a crypto connection.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int crypto_kill(int crypt_connection_id);

    /* return the optimal interval in ms for running do_net_crypto.
    */
    uint32_t crypto_run_interval() const;

    /* Main loop. */
    void do_net_crypto();

    DHT *dht;
    TCP_Connections *tcp_c;

    std::vector<std::unique_ptr<Crypto_Connection> > crypto_connections;
    std::mutex tcp_mutex; // TODO recursive?

    pthread_mutex_t connections_mutex;
    unsigned int connection_use_counter;

    //uint32_t crypto_connections_length; /* Length of connections array. */

    /* Our public and secret keys. */
    bitox::PublicKey self_public_key;
    bitox::SecretKey self_secret_key;

    /* The secret key used for cookies */
    bitox::SharedKey secret_symmetric_key;

    int (*new_connection_callback)(void *object, New_Connection *n_c);
    void *new_connection_callback_object;

    /* The current optimal sleep time */
    uint32_t current_sleep_time;

    std::map<bitox::network::IPPort, int> ip_port_list;
    
// private:
    /* Handle the cookie request packet of length length.
    * Put what was in the request in request_plain (must be of size COOKIE_REQUEST_PLAIN_LENGTH)
    * Put the key used to decrypt the request into shared_key (of size crypto_box_BEFORENMBYTES) for use in the response.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int handle_cookie_request(uint8_t *request_plain, bitox::SharedKey &shared_key,
                                    bitox::PublicKey &dht_public_key, const uint8_t *packet, uint16_t length) const;
                                    
    /* Create a cookie response packet and put it in packet.
    * request_plain must be COOKIE_REQUEST_PLAIN_LENGTH bytes.
    * packet must be of size COOKIE_RESPONSE_LENGTH or bigger.
    *
    * return -1 on failure.
    * return COOKIE_RESPONSE_LENGTH on success.
    */
    int create_cookie_response(uint8_t *packet, const uint8_t *request_plain,
                                    const bitox::SharedKey &shared_key, const bitox::PublicKey &dht_public_key) const;
           
    Crypto_Connection *get_crypto_connection(int crypt_connection_id);
    
    /* Handle the cookie request packet (for TCP)
    */
    int tcp_handle_cookie_request(int connections_number, const uint8_t *packet, uint16_t length);
    
    /* Handle a packet that was received for the connection.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int handle_packet_connection(int crypt_connection_id, const uint8_t *packet, uint16_t length,
                                        bool udp);
    
    uint8_t crypt_connection_id_not_valid(int crypt_connection_id) const;
    
    /* Create a cookie request packet and put it in packet.
    * dht_public_key is the dht public key of the other
    *
    * packet must be of size COOKIE_REQUEST_LENGTH or bigger.
    *
    * return -1 on failure.
    * return COOKIE_REQUEST_LENGTH on success.
    */
    int create_cookie_request(uint8_t *packet, bitox::PublicKey &dht_public_key, uint64_t number,
                                    bitox::SharedKey &shared_key) const;

    /* Handle the cookie request packet (for TCP oob packets)
    */
    int tcp_oob_handle_cookie_request(unsigned int tcp_connections_number,
            const bitox::PublicKey &dht_public_key, const uint8_t *packet, uint16_t length) const;

    int create_crypto_handshake(uint8_t *packet, const uint8_t *cookie, const bitox::Nonce &nonce,
                                    const bitox::PublicKey &session_pk, const bitox::PublicKey &peer_real_pk, const bitox::PublicKey &peer_dht_pubkey) const;

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
    int handle_crypto_handshake(bitox::Nonce &nonce, bitox::PublicKey &session_pk, bitox::PublicKey &peer_real_pk,
                                    bitox::PublicKey &dht_public_key, uint8_t *cookie, const uint8_t *packet, uint16_t length, const bitox::PublicKey *expected_real_pk) const;



    /* Associate an ip_port to a connection.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int add_ip_port_connection(int crypt_connection_id, bitox::network::IPPort ip_port);

    /* Return the IPPort that should be used to send packets to the other peer.
    *
    * return IPPort with family 0 on failure.
    * return IPPort on success.
    */
    bitox::network::IPPort return_ip_port_connection(int crypt_connection_id);

    /* Sends a packet to the peer using the fastest route.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int send_packet_to(int crypt_connection_id, const uint8_t *data, size_t length);

    /* Creates and sends a data packet to the peer using the fastest route.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int send_data_packet(int crypt_connection_id, const uint8_t *data, uint16_t length);

    /* Creates and sends a data packet with buffer_start and num to the peer using the fastest route.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int send_data_packet_helper(int crypt_connection_id, uint32_t buffer_start, uint32_t num,
                                    const uint8_t *data, uint16_t length);

    int reset_max_speed_reached(int crypt_connection_id);

    /*  return -1 if data could not be put in packet queue.
    *  return positive packet number if data was put into the queue.
    */
    int64_t send_lossless_packet(int crypt_connection_id, const uint8_t *data, uint16_t length,
                                        uint8_t congestion_control);

    /* Handle a data packet.
    * Decrypt packet of length and put it into data.
    * data must be at least MAX_DATA_DATA_PACKET_SIZE big.
    *
    * return -1 on failure.
    * return length of data on success.
    */
    int handle_data_packet(int crypt_connection_id, uint8_t *data, const uint8_t *packet,
                                uint16_t length);

    /* Send a request packet.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int send_request_packet(int crypt_connection_id);

    /* Send up to max num previously requested data packets.
    *
    * return -1 on failure.
    * return number of packets sent on success.
    */
    int send_requested_packets(int crypt_connection_id, uint32_t max_num);

    /* Add a new temp packet to send repeatedly.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int new_temp_packet(int crypt_connection_id, const uint8_t *packet, uint16_t length);

    /* Clear the temp packet.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int clear_temp_packet(int crypt_connection_id);

    /* Send the temp packet.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int send_temp_packet(int crypt_connection_id);

    /* Create a handshake packet and set it as a temp packet.
    * cookie must be COOKIE_LENGTH.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int create_send_handshake(int crypt_connection_id, const uint8_t *cookie,
                                    const bitox::PublicKey &dht_public_key);

    /* Send a kill packet.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int send_kill_packet(int crypt_connection_id);

    void connection_kill(int crypt_connection_id);

    /* Handle a received data packet.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int handle_data_packet_helper(int crypt_connection_id, const uint8_t *packet, uint16_t length,
                                        bool udp);

    /* Create a new empty crypto connection.
    *
    * return -1 on failure.
    * return connection id on success.
    */
    int create_crypto_connection();

    /* Wipe a crypto connection.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int wipe_crypto_connection(int crypt_connection_id);

    /* Get crypto connection id from public key of peer.
    *
    *  return -1 if there are no connections like we are looking for.
    *  return id if it found it.
    */
    int getcryptconnection_id(const bitox::PublicKey &public_key) const;

    /* Add a source to the crypto connection.
    * This is to be used only when we have received a packet from that source.
    *
    *  return -1 on failure.
    *  return positive number on success.
    *  0 if source was a direct UDP connection.
    */
    int crypto_connection_add_source(int crypt_connection_id, bitox::network::IPPort source);

    /* Handle a handshake packet by someone who wants to initiate a new connection with us.
    * This calls the callback set by new_connection_handler() if the handshake is ok.
    *
    * return -1 on failure.
    * return 0 on success.
    */
    int handle_new_connection_handshake(bitox::network::IPPort source, const uint8_t *data, uint16_t length);

    void do_tcp();

    /* Get the crypto connection id from the ip_port.
    *
    * return -1 on failure.
    * return connection id on success.
    */
    int crypto_id_ip_port(bitox::network::IPPort ip_port) const;

    void send_crypto_packets();
    
    void kill_timedout();

};


/* Set function to be called when someone requests a new connection to us.
 *
 * The set function should return -1 on failure and 0 on success.
 *
 * n_c is only valid for the duration of the function call.
 */
void new_connection_handler(Net_Crypto *c, int (*new_connection_callback)(void *object, New_Connection *n_c),
                            void *object);


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
int connection_status_handler(const Net_Crypto *c, int crypt_connection_id,
                              int (*connection_status_callback)(void *object, int id, uint8_t status), void *object, int id);

/* Set function to be called when connection with crypt_connection_id receives a lossless data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_data_handler(const Net_Crypto *c, int crypt_connection_id, int (*connection_data_callback)(void *object,
                            int id, uint8_t *data, uint16_t length), void *object, int id);


/* Set function to be called when connection with crypt_connection_id receives a lossy data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_lossy_data_handler(Net_Crypto *c, int crypt_connection_id,
                                  int (*connection_lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length), void *object,
                                  int id);

/* Set the function for this friend that will be callbacked with object and number if
 * the friend sends us a different dht public key than we have associated to him.
 *
 * If this function is called, the connection should be recreated with the new public key.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int nc_dht_pk_callback(Net_Crypto *c, int crypt_connection_id, void (*function)(void *data, int32_t number,
                       const bitox::PublicKey &dht_public_key), void *object, uint32_t number);

#endif
