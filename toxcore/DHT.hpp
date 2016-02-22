/* DHT.h
 *
 * An implementation of the DHT as seen in docs/updates/DHT.md
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

#ifndef DHT_H
#define DHT_H

#include "crypto_core.hpp"
#include "network.hpp"
#include "ping_array.hpp"
#include "protocol.hpp"
#include "ping.hpp"

#include <sodium.h>
#include <sodium/utils.h>
#include <memory>

/* Maximum number of clients stored per friend_. */
#define MAX_FRIEND_CLIENTS 8

#define LCLIENT_NODES (MAX_FRIEND_CLIENTS)
#define LCLIENT_LENGTH 128

/* A list of the clients mathematically closest to ours. */
#define LCLIENT_LIST (LCLIENT_LENGTH * LCLIENT_NODES)

#define MAX_CLOSE_TO_BOOTSTRAP_NODES 8


/* Ping timeout in seconds */
#define PING_TIMEOUT 5

/* size of DHT ping arrays. */
#define DHT_PING_ARRAY_SIZE 512

/* Ping interval in seconds for each node in our lists. */
#define PING_INTERVAL 60

/* The number of seconds for a non responsive node to become bad. */
#define PINGS_MISSED_NODE_GOES_BAD 1
#define PING_ROUNDTRIP 2
#define BAD_NODE_TIMEOUT (PING_INTERVAL + PINGS_MISSED_NODE_GOES_BAD * (PING_INTERVAL + PING_ROUNDTRIP))

/* The number of "fake" friends to add (for optimization purposes and so our paths for the onion part are more random) */
#define DHT_FAKE_FRIEND_NUMBER 2

/* Functions to transfer ips safely across wire. */
void to_net_family (IP *ip);

/* return 0 on success, -1 on failure. */
int to_host_family (IP *ip);

struct IPPTs
{
	IP_Port     ip_port;
	uint64_t    timestamp;
};

struct Hardening
{
	/* Node routes request correctly (true (1) or false/didn't check (0)) */
	uint8_t     routes_requests_ok;                                          //- константа в hardening_correct
	/* Time which we last checked this.*/
	uint64_t    routes_requests_timestamp;                                   //- не используется
	uint8_t     routes_requests_pingedid[crypto_box_PUBLICKEYBYTES];         //- не используется
	/* Node sends correct send_node (true (1) or false/didn't check (0)) */
	uint8_t     send_nodes_ok;                                               //- 0 или 1
	/* Time which we last checked this.*/
	uint64_t    send_nodes_timestamp;                                        //- do_hardening   = unix_time()
	uint8_t     send_nodes_pingedid[crypto_box_PUBLICKEYBYTES];              //- do_hardening  memcpy
	/* Node can be used to test other nodes (true (1) or false/didn't check (0)) */
	uint8_t     testing_requests;                                            //- константа в hardening_correct
	/* Time which we last checked this.*/
	uint64_t    testing_timestamp;                                           //- не используется
	uint8_t     testing_pingedid[crypto_box_PUBLICKEYBYTES];                 //- не используется
};

struct IPPTsPng
{
	IP_Port     ip_port;
	uint64_t    timestamp;
	uint64_t    last_pinged;

	Hardening hardening;
	/* Returned by this node. Either our friend_ or us. */
	IP_Port     ret_ip_port;
	uint64_t    ret_timestamp;
};

struct Client_data
{
	uint8_t     public_key[crypto_box_PUBLICKEYBYTES];
	IPPTsPng    assoc4;
	IPPTsPng    assoc6;
};

/*----------------------------------------------------------------------------------*/

struct NAT
{
	/* 1 if currently hole punching, otherwise 0 */
	uint8_t     hole_punching;                 //- 0 или 1
	uint32_t    punching_index;
	uint32_t    tries;
	uint32_t    punching_index2;

	uint64_t    punching_timestamp;
	uint64_t    recvNATping_timestamp;
	uint64_t    NATping_id;
	uint64_t    NATping_timestamp;
};

#define DHT_FRIEND_MAX_LOCKS 32

struct DHT_Friend
{
	uint8_t     public_key[crypto_box_PUBLICKEYBYTES];
	Client_data client_list[MAX_FRIEND_CLIENTS];

	/* Time at which the last get_nodes request was sent. */
	uint64_t    lastgetnode;
	/* number of times get_node packets were sent. */
	uint32_t    bootstrap_times;

	/* Symetric NAT hole punching stuff. */
	NAT         nat;

	uint16_t lock_count;
	struct
	{
		void (*ip_callback) (void *, int32_t, IP_Port);
		void *data;
		int32_t number;
	} callbacks[DHT_FRIEND_MAX_LOCKS];

	Node_format to_bootstrap[bitox::MAX_SENT_NODES];
	unsigned int num_to_bootstrap;
};

/* Return packet size of packed node with ip_family on success.
 * Return -1 on failure.
 */
int packed_node_size (uint8_t ip_family);

/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_nodes (uint8_t *data, uint16_t length, const Node_format *nodes, uint16_t number);

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_nodes (Node_format *nodes, uint16_t max_num_nodes, uint16_t *processed_data_len, const uint8_t *data,
				  uint16_t length, uint8_t tcp_enabled);


/*----------------------------------------------------------------------------------*/
/* struct to store some shared keys so we don't have to regenerate them for each request. */
#define MAX_KEYS_PER_SLOT 4
#define KEYS_TIMEOUT 600
struct Shared_Keys
{
	struct
	{
		uint8_t public_key[crypto_box_PUBLICKEYBYTES];
		uint8_t shared_key[crypto_box_BEFORENMBYTES];
		uint32_t times_requested;
		uint8_t  stored; /* 0 if not, 1 if is */
		uint64_t time_last_requested;
	} keys[256 * MAX_KEYS_PER_SLOT];
};

/*----------------------------------------------------------------------------------*/

typedef int (*cryptopacket_handler_callback) (void *object, IP_Port ip_port, const uint8_t *source_pubkey,
											  const uint8_t *data, uint16_t len);

struct Cryptopacket_Handles
{
	cryptopacket_handler_callback function;
	void *object;
};

struct DHT
{
    explicit DHT(Networking_Core *net);
    ~DHT();
    
	Networking_Core *net = nullptr;

	Client_data    close_clientlist[LCLIENT_LIST];
	uint64_t       close_lastgetnodes = 0;
	uint32_t       close_bootstrap_times = 0;

	/* Note: this key should not be/is not used to transmit any sensitive materials */
	uint8_t      secret_symmetric_key[crypto_box_BEFORENMBYTES];
	/* DHT keypair */
	uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
	uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];

        std::vector<DHT_Friend> friends_list;
        std::vector<Node_format> loaded_nodes_list;
	uint32_t       loaded_num_nodes = 0;
	unsigned int   loaded_nodes_index = 0;

	Shared_Keys shared_keys_recv;
	Shared_Keys shared_keys_sent;

	std::unique_ptr<PING> ping;
	Ping_Array    dht_ping_array;
	Ping_Array    dht_harden_ping_array;
#ifdef ENABLE_ASSOC_DHT
	struct Assoc  *assoc = nullptr;
#endif
	uint64_t       last_run = 0;

	Cryptopacket_Handles cryptopackethandlers[256] = {};

	Node_format to_bootstrap[MAX_CLOSE_TO_BOOTSTRAP_NODES] = {};
	unsigned int num_to_bootstrap = 0;

	/*
	 * Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
	 * for packets that we receive.
	 */
	void get_shared_key_recv (uint8_t *shared_key, const uint8_t *public_key);
	
	/* 
	 * Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
	 * for packets that we send.
	 */
	void get_shared_key_sent (uint8_t *shared_key, const uint8_t *public_key);
	
	void getnodes (const IP_Port *from_ipp, const uint8_t *from_id, const uint8_t *which_id);

	/*
	 * Add a new friend_ to the friends list.
	 * public_key must be crypto_box_PUBLICKEYBYTES bytes long.
	 *
	 * ip_callback is the callback of a function that will be called when the ip address
	 * is found along with arguments data and number.
	 *
	 * lock_count will be set to a non zero number that must be passed to DHT_delfriend()
	 * to properly remove the callback.
	 *
	 *  return true if success.
	 *  return false if failure (friends list is full).
	 */
	bool addfriend (const uint8_t *public_key, void (*ip_callback) (void *data, int32_t number, IP_Port),
					   void *data, int32_t number, uint16_t *lock_count);
	
	/* 
	 * Delete a friend_ from the friends list.
	 * public_key must be crypto_box_PUBLICKEYBYTES bytes long.
	 *
	 *  return true if success.
	 *  return false if failure (public_key not in friends list).
	 */
	bool delfriend (const uint8_t *public_key, uint16_t lock_count);
	
	/*
	 * Get ip of friend_.
	 *  public_key must be crypto_box_PUBLICKEYBYTES bytes long.
	 *  ip must be 4 bytes long.
	 *  port must be 2 bytes long.
	 *
	 * int DHT_getfriendip(DHT *dht, uint8_t *public_key, IP_Port *ip_port);
	 *
	 *  return -1, -- if public_key does NOT refer to a friend_
	 *  return  0, -- if public_key refers to a friend_ and we failed to find the friend_ (yet)
	 *  return  1, ip if public_key refers to a friend_ and we found him
	 */
	int getfriendip (const uint8_t *public_key, IP_Port *ip_port) const;
	
	/*
	 * Return true if node can be added to close list, false if it can't.
	 */
	bool node_addable_to_close_list (const uint8_t *public_key, IP_Port ip_port);
	
	/*
	 * Get the (maximum MAX_SENT_NODES) closest nodes to public_key we know
	 * and put them in nodes_list (must be MAX_SENT_NODES big).
	 *
	 * sa_family = family (IPv4 or IPv6) (0 if we don't care)?
	 * is_LAN = return some LAN ips (true or false)
	 * want_good = do we want tested nodes or not? (TODO)
	 *
	 * return the number of nodes returned.
	 *
	 */
	int get_close_nodes (const uint8_t *public_key, Node_format *nodes_list, sa_family_t sa_family,
						 uint8_t is_LAN, uint8_t want_good) const;
						
	/* 
	 * Put up to max_num nodes in nodes from the random friends.
	 * return the number of nodes.
	 */
	uint16_t randfriends_nodes (Node_format *nodes, uint16_t max_num);

	/*
	 * Put up to max_num nodes in nodes from the closelist.
	 * return the number of nodes.
	 */
	uint16_t closelist_nodes (Node_format *nodes, uint16_t max_num);

	/*
	 * Load the DHT from data of size size.
	 * return false if failure.
	 * return true if success.
	 */
	bool load(const uint8_t *data, uint32_t length);

	/*
	 * Sends a "get nodes" request to the given node with ip, port and public_key
	 * to setup connections
	 */
	void bootstrap (IP_Port ip_port, const uint8_t *public_key);

	/* Resolves address into an IP address. If successful, sends a "get nodes"
	 *   request to the given node with ip, port and public_key to setup connections
	 *
	 * address can be a hostname or an IP address (IPv4 or IPv6).
	 * if ipv6enabled is 0 (zero), the resolving sticks STRICTLY to IPv4 addresses
	 * if ipv6enabled is not 0 (zero), the resolving looks for IPv6 addresses first,
	 *   then IPv4 addresses.
	 *
	 *  returns 1 if the address could be converted into an IP address
	 *  returns 0 otherwise
	 */
	bool bootstrap_from_address (const char *address, uint8_t ipv6enabled,
								uint16_t port, const uint8_t *public_key);

	/* Start sending packets after DHT loaded_friends_list and loaded_clients_list are set.
	*
	* returns true if successful
	* returns false otherwise
	*/
	bool connect_after_load ();

	/**
	 * return true if we are connected to the DHT
	 */
	bool isconnected() const;

	/** 
	 * return false if we are not connected or only connected to lan peers with the DHT.
	 * return true if we are.
	 */
	bool non_lan_connected() const;
	
	/* Run this function at least a couple times per second (It's the main loop). */
	void do_DHT ();
	
	
	/* ROUTING FUNCTIONS */

	/* Send the given packet to node with public_key.
	*  return number if datagrams sent (length parameter)
	*  return -1 if failure.
	*/
	int route_packet (const uint8_t *public_key, const uint8_t *packet, uint16_t length) const;
	
	/* Send the following packet to everyone who tells us they are connected to friend_id.
	*
	*  return number of nodes it sent the packet to.
	*/
	int route_tofriend (const uint8_t *friend_id, const uint8_t *packet, uint16_t length) const;
	
	/* Function to handle crypto packets.
	*/
	void cryptopacket_registerhandler (uint8_t byte, cryptopacket_handler_callback cb, void *object);
	
	/* Get the size of the DHT (for saving). */
	uint32_t size () const;

	/* Save the DHT in data where data is an array of size DHT_size(). */
	void save (uint8_t *data);
	
	
	int addto_lists (IP_Port ip_port, const uint8_t *public_key);
	void do_hardening ();
	
//private:
	/**
	 * Send a getnodes request.
	 * sendback_node is the node that it will send back the response to (set to NULL to disable this) 
	 */
	int getnodes (IP_Port ip_port, const uint8_t *public_key, const uint8_t *client_id,
					 const Node_format *sendback_node);
	
	uint8_t do_ping_and_sendnode_requests (uint64_t *lastgetnode, const uint8_t *public_key,
										   Client_data *list, uint32_t list_count, uint32_t *bootstrap_times, bool sortable);
	
	void do_DHT_friends ();
	void do_Close ();
	void do_NAT ();
	int add_to_close (const uint8_t *public_key, IP_Port ip_port, bool simulate);
	unsigned int ping_node_from_getnodes_ok (const uint8_t *public_key, IP_Port ip_port);
	int friend_iplist (IP_Port *ip_portlist, uint16_t friend_num) const;
	int send_hardening_req (Node_format *sendto, uint8_t type, uint8_t *contents, uint16_t length);
	int send_hardening_getnode_req (Node_format *dest, Node_format *node_totest, uint8_t *search_id);
	int returnedip_ports (IP_Port ip_port, const uint8_t *public_key, const uint8_t *nodepublic_key);
	int routeone_tofriend (const uint8_t *friend_id, const uint8_t *packet, uint16_t length);
	void punch_holes (IP ip, uint16_t *port_list, uint16_t numports, uint16_t friend_num);
	IPPTsPng *get_closelist_IPPTsPng (const uint8_t *public_key, sa_family_t sa_family);
	Node_format random_node (sa_family_t sa_family);
	uint8_t sent_getnode_to_node (const uint8_t *public_key, IP_Port node_ip_port, uint64_t ping_id,
								Node_format *sendback_node);
	int send_NATping (const uint8_t *public_key, uint64_t ping_id, uint8_t type);
	uint32_t have_nodes_closelist (Node_format *nodes, uint16_t num);
};
/*----------------------------------------------------------------------------------*/

/* Shared key generations are costly, it is therefor smart to store commonly used
 * ones so that they can re used later without being computed again.
 *
 * If shared key is already in shared_keys, copy it to shared_key.
 * else generate it into shared_key and copy it to shared_keys
 */
void get_shared_key (Shared_Keys *shared_keys, uint8_t *shared_key, const uint8_t *secret_key,
					 const uint8_t *public_key);


/* Compares pk1 and pk2 with pk.
 *
 *  return 0 if both are same distance.
 *  return 1 if pk1 is closer.
 *  return 2 if pk2 is closer.
 */
int id_closest (const uint8_t *pk, const uint8_t *pk1, const uint8_t *pk2);

/* Add node to the node list making sure only the nodes closest to cmp_pk are in the list.
 */
bool add_to_list (Node_format *nodes_list, unsigned int length, const uint8_t *pk, IP_Port ip_port,
				  const uint8_t *cmp_pk);


#endif

