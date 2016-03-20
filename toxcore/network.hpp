/**
 * This file is part of 2tox
 *
 * Copyright 2013 by Tox project <https://github.com/irungentoo/toxcore>
 *
 * See LICENSE.
 *
 * @license GPL-3.0 <http://spdx.org/licenses/GPL-3.0>
 */

#ifndef NETWORK_HPP
#define NETWORK_HPP


#include <netinet/in.h>

#define MAX_UDP_PACKET_SIZE 2048


/* Only used for bootstrap nodes */
//#define BOOTSTRAP_INFO_PACKET_ID 240


#define TOX_PORTRANGE_FROM 33445
#define TOX_PORTRANGE_TO   33545
#define TOX_PORT_DEFAULT   TOX_PORTRANGE_FROM

/* TCP related */
#define TCP_ONION_FAMILY (AF_INET6 + 1)
#define TCP_INET (AF_INET6 + 2)
#define TCP_INET6 (AF_INET6 + 3)
#define TCP_FAMILY (AF_INET6 + 4)

#include "protocol.hpp"

/* Does the IP6 struct a contain an IPv4 address in an IPv6 one? */
#define IPV6_IPV4_IN_V6(a) ((a.uint64[0] == 0) && (a.uint32[2] == htonl (0xffff)))

#define SIZE_IP4 4
#define SIZE_IP6 16
#define SIZE_IP (1 + SIZE_IP6)
#define SIZE_PORT 2
#define SIZE_IPPORT (SIZE_IP + SIZE_PORT)

#define TOX_ENABLE_IPV6_DEFAULT 1

struct DHT;

/* return current monotonic time in milliseconds (ms). */
uint64_t current_time_monotonic(void);


namespace bitox
{

class EventDispatcher;

namespace network
{
    
struct Socket {
    int fd;

    Socket();
    explicit Socket(sa_family_t family, size_t tx_rx_buff_size);

    bool is_valid() const;
    void kill() const;
    int bind(const IPPort& ip_port) const;
    int sendto(uint8_t socket_family, IPPort ip_port, const void* data, size_t length, int flags) const;
    int recvfrom(IPPort* ip_port, void* data, uint32_t* length, size_t max_len, int flags) const;
    bool set_nonblock() const;
    bool set_nosigpipe() const;
    bool set_reuseaddr() const;
    bool set_dualstack() const;
};

typedef unsigned int sock_t;

struct Networking_Core
{
    sa_family_t family;
    uint16_t port;
    /* Our UDP socket. */
    int sock;
    DHT *dht = nullptr;
    EventDispatcher *const event_dispatcher;

    Networking_Core(EventDispatcher *event_dispatcher);
    ~Networking_Core();
    
    void set_dht(DHT *dht)
    {
        this->dht = dht;
    }

    /* Call this several times a second. */
    void poll() const;
};

#define TOX_ENABLE_IPV6_DEFAULT 1

/* ip_ntoa
 *   converts ip into a string
 *   uses a static buffer, so mustn't used multiple times in the same output
 *
 *   IPv6 addresses are enclosed into square brackets, i.e. "[IPv6]"
 *   writes error message into the buffer on error
 */
const char* ip_ntoa(const IP* ip);

/*
 * ip_parse_addr
 *  parses IP structure into an address string
 *
 * input
 *  ip: ip of AF_INET or AF_INET6 families
 *  length: length of the address buffer
 *          Must be at least INET_ADDRSTRLEN for AF_INET
 *          and INET6_ADDRSTRLEN for AF_INET6
 *
 * output
 *  address: dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6)
 *
 * returns 1 on success, 0 on failure
 */
int ip_parse_addr(const IP* ip, char* address, size_t length);

/*
 * addr_parse_ip
 *  directly parses the input into an IP structure
 *  tries IPv4 first, then IPv6
 *
 * input
 *  address: dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6)
 *
 * output
 *  IP: family and the value is set on success
 *
 * returns 1 on success, 0 on failure
 */
int addr_parse_ip(const char* address, IP* to);

/* ip_equal
 *  compares two IPAny structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ip_equal(const IP* a, const IP* b);

/* ipport_equal
 *  compares two IPAny_Port structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ipport_equal(const IPPort* a, const IPPort* b);

/* nulls out ip */
void ip_reset(IP* ip);
/* nulls out ip, sets family according to flag */
void ip_init(IP* ip, uint8_t ipv6enabled);
/* checks if ip is valid */
int ip_isset(const IP* ip);
/* checks if ip is valid */
int ipport_isset(const IPPort *ipport);
/* copies an ip structure */
void ip_copy(IP* target, const IP* source);
/* copies an ip_port structure */
void ipport_copy(IPPort* target, const IPPort* source);

/*
 * addr_resolve():
 *  uses getaddrinfo to resolve an address into an IP address
 *  uses the first IPv4/IPv6 addresses returned by getaddrinfo
 *
 * input
 *  address: a hostname (or something parseable to an IP address)
 *  to: to.family MUST be initialized, either set to a specific IP version
 *     (AF_INET/AF_INET6) or to the unspecified AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 * returns in *to a valid IPAny (v4/v6),
 *     prefers v6 if ip.family was AF_UNSPEC and both available
 * returns in *extra an IPv4 address, if family was AF_UNSPEC and *to is AF_INET6
 * returns 0 on failure
 */
int addr_resolve(const char* address, IP* to, IP* extra);

/*
 * addr_resolve_or_parse_ip
 *  resolves string into an IP address
 *
 *  address: a hostname (or something parseable to an IP address)
 *  to: to.family MUST be initialized, either set to a specific IP version
 *     (AF_INET/AF_INET6) or to the unspecified AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 *  returns in *tro a matching address (IPv6 or IPv4)
 *  returns in *extra, if not NULL, an IPv4 address, if to->family was AF_UNSPEC
 *  returns 1 on success
 *  returns 0 on failure
 */
int addr_resolve_or_parse_ip(const char* address, IP* to, IP* extra);

/* Run this before creating sockets.
 *
 * return 0 on success
 * return -1 on failure
 */
int networking_at_startup(void);

/* Check if socket is valid.
 *
 * return 1 if valid
 * return 0 if not valid
 */
int sock_valid(sock_t sock);

/* Close the socket.
 */
void kill_sock(sock_t sock);

/* Set socket as nonblocking
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nonblock(sock_t sock);

/* Set socket to not emit SIGPIPE
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nosigpipe(sock_t sock);

/* Enable SO_REUSEADDR on socket.
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_reuseaddr(sock_t sock);

/* Set socket to dual (IPv4 + IPv6 socket)
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_dualstack(sock_t sock);

/* Basic network functions: */

/* Function to send packet(data) of length to ip_port. */
int sendpacket(Networking_Core* net, IPPort ip_port, const uint8_t* data, uint16_t length);

/* Initialize networking.
 * bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 * return Networking_Core object if no problems
 * return NULL if there are problems.
 *
 * If error is non NULL it is set to 0 if no issues, 1 if socket related error, 2 if other.
 */
Networking_Core* new_networking(IP ip, uint16_t port, EventDispatcher *event_dispatcher);
Networking_Core* new_networking_ex(IP ip, uint16_t port_from, uint16_t port_to, unsigned int* error, EventDispatcher *event_dispatcher);

/* Function to cleanup networking stuff (doesn't do much right now). */
void kill_networking(Networking_Core *net);
}
}

#endif
