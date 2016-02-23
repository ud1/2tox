#include "network.hpp"

#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <errno.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <assert.h>
#include <algorithm>

#include "protocol_impl.hpp"

static void unix_time_update() { /* FIXME */ }

static uint64_t current_time_actual(void) { /* FIXME */ return 0; }

uint64_t current_time_monotonic(void) { /* FIXME */ return 0; }

namespace bitox
{

namespace network
{    

int networking_at_startup(void) { /* FIXME */ return 0; }

IP IP::create_ip4()
{
    IP result = IP();
    result.family = bitox::network::Family::FAMILY_AF_INET;
    return result;
}

IP IP::create_ip6()
{
    IP result = IP();
    result.family = bitox::network::Family::FAMILY_AF_INET6;
    return result;
}

IP IP::create(bool ipv6enabled)
{
    return ipv6enabled ? create_ip6() : create_ip4();
}

in_addr IP::to_in_addr() const
{
    in_addr result;
    boost::asio::ip::address_v4::bytes_type bytes = address.to_v4().to_bytes();
    memcpy((void *)&result, (void *) bytes.data(), 4);
    
    return result;
}

in6_addr IP::to_in6_addr() const
{
    in6_addr result;
    boost::asio::ip::address_v6::bytes_type bytes = address.is_v6() ? address.to_v6().to_bytes() : boost::asio::ip::address_v6::v4_mapped(address.to_v4()).to_bytes();
    memcpy((void *)&result, (void *) bytes.data(), 16);
    
    return result;
}

void IP::from_in_addr(in_addr addr)
{
    boost::asio::ip::address_v4::bytes_type bytes;
    memcpy((void *) bytes.data(), (void *)&addr, 4);
    address = boost::asio::ip::address_v4(bytes);
}

void IP::from_in6_addr(in6_addr addr)
{
    boost::asio::ip::address_v6::bytes_type bytes;
    memcpy((void *) bytes.data(), (void *)&addr, 16);
    address = boost::asio::ip::address_v6(bytes);
}

void IP::from_uint32(uint32_t ipv4_addr)
{
    boost::asio::ip::address_v4::bytes_type bytes;
    memcpy((void *) bytes.data(), (void *)&ipv4_addr, 4);
    address = boost::asio::ip::address_v4(bytes);
}

uint32_t IP::to_uint32() const
{
    uint32_t result;
    boost::asio::ip::address_v4::bytes_type bytes = address.to_v4().to_bytes();
    memcpy((void *)&result, (void *) bytes.data(), 4);
    return result;
}

void IP::from_string(const std::string &str)
{
    address = boost::asio::ip::address::from_string(str);
}

sockaddr_storage IPPort::to_addr_4() const
{
    assert(ip.address.is_v4());
    sockaddr_storage storage;
    sockaddr_in* const addr = reinterpret_cast<sockaddr_in*>( &storage );

    addr->sin_family = AF_INET;
    addr->sin_addr = ip.to_in_addr();
    addr->sin_port = port;

    return storage;
}

sockaddr_storage IPPort::to_addr_6() const
{
    sockaddr_storage storage;
    sockaddr_in6* const addr = reinterpret_cast<sockaddr_in6*>( &storage );

    addr->sin6_family = AF_INET6;
    addr->sin6_port = port;
    addr->sin6_addr = ip.to_in6_addr();
    addr->sin6_flowinfo = 0;
    addr->sin6_scope_id = 0;

    return storage;
}


IPPort IPPort::from_addr(const sockaddr_storage& addr) // TODO
{
    IPPort ip_port;
    if (addr.ss_family == AF_INET) {
        const sockaddr_in* const addr_in = (sockaddr_in*) &addr;
        ip_port.ip.family = bitox::network::Family::FAMILY_AF_INET;
        ip_port.ip.from_in_addr(addr_in->sin_addr);
        ip_port.port = addr_in->sin_port;
    } else if (addr.ss_family == AF_INET6) {
        const sockaddr_in6* const addr_in = (sockaddr_in6*) &addr;
        ip_port.ip.family = bitox::network::Family::FAMILY_AF_INET6;
        ip_port.ip.from_in6_addr(addr_in->sin6_addr);
        ip_port.port = addr_in->sin6_port;

        if (ip_port.ip.address.to_v6().is_v4_compatible() || ip_port.ip.address.to_v6().is_v4_mapped()) {
            ip_port.ip.family = bitox::network::Family::FAMILY_AF_INET;
            ip_port.ip.address = ip_port.ip.address.to_v6().to_v4();
        }
    }
    return ip_port;
}


Socket::Socket() : fd() { }

Socket::Socket(sa_family_t family, size_t tx_rx_buff_size)
    : fd()
{
    int ret;
    ret = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    this->fd = ret;
    if (ret == -1) {
        // TODO log
        return;
    }
    ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void*) &tx_rx_buff_size, sizeof(tx_rx_buff_size));
    if (ret == -1) {
        // TODO log
        kill_sock(fd);
        fd = -1;
        return;
    }
    ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void*) &tx_rx_buff_size, sizeof(tx_rx_buff_size));
    if (ret == -1) {
        // TODO log
        kill_sock(fd);
        fd = -1;
        return;
    }

    /* Enable broadcast on socket */
    int broadcast = 1;
    ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast));
    if (ret == -1) {
        // TODO log
        kill_sock(fd);
        fd = -1;
        return;
    }
}


bool Socket::is_valid() const {
    if (fd < 0) {
        return false;
    }

    return true;
}

void Socket::kill() const {
    close(fd);
}

int Socket::bind(const IPPort& ip_port) const
{
    sockaddr_storage addr;
    size_t addrsize;

    if (ip_port.ip.address.is_v4()) {
        addr = ip_port.to_addr_4();
        addrsize = sizeof(sockaddr_in);
    } else if (ip_port.ip.address.is_v6()) {
        addr = ip_port.to_addr_6();
        addrsize = sizeof(sockaddr_in6);
    } else {
        addrsize = 0;
    }
    return ::bind(fd, (sockaddr*) &addr, addrsize);
}


int Socket::sendto(uint8_t socket_family, IPPort target, const void* data, size_t length, int flags) const
{
    if (socket_family == 0 || !(socket_family == AF_INET || socket_family == AF_INET6)) {
        /* Socket not initialized */
        /* Unknown address type*/
        return -1;
    }

    if (!target.isset())
        return -1;

    /* socket AF_INET, but target IP NOT: can't send */
    if (socket_family == AF_INET && !target.ip.address.is_v4())
        return -1;

    sockaddr_storage addr;
    size_t addrsize = 0;

    if (socket_family == AF_INET6) {
        addr = target.to_addr_6();
        addrsize = sizeof(sockaddr_in6);
    } else if (socket_family == AF_INET) {
        addr = target.to_addr_4();
        addrsize = sizeof(sockaddr_in);
    }

    return ::sendto(fd, data, length, flags, reinterpret_cast<sockaddr*>(&addr), addrsize);
}

int Socket::recvfrom(IPPort* ip_port, void* data, uint32_t* length, size_t max_len, int flags) const
{
    *ip_port = IPPort();
    *length = 0;

    sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    const int ret = ::recvfrom(fd, data, max_len, flags, (sockaddr*) &addr, &addrlen);
    if (ret == -1) {
        return -1; /* Nothing received. */
    }
    *length = ret;

    if (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
        *ip_port = IPPort::from_addr(addr);
    } else {
        return -1;
    }

    return 0;
}

bool Socket::set_nonblock() const {
    return fcntl(fd, F_SETFL, O_NONBLOCK, 1) == 0;
}

bool Socket::set_nosigpipe() const {
    return true; // FIXME not impletented. Maybe we should use MSG_NOSIGNAL instead?
}

bool Socket::set_reuseaddr() const {
    int set = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*) &set, sizeof(set)) == 0;
}

bool Socket::set_dualstack() const
{
    int ipv6only = 0;
    socklen_t optsize = sizeof(ipv6only);
    const int ret = getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &ipv6only, &optsize);

    if ((ret == 0) && (ipv6only == 0))
        return true;

    ipv6only = false;
    return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &ipv6only, sizeof(ipv6only)) == 0;
}


Networking_Core::Networking_Core() :
    packethandlers(), family(), port(), sock()
{

}

Networking_Core::~Networking_Core()
{
    if (family != 0)
        kill_sock(sock);
}

void Networking_Core::poll() const
{
    if (family == 0) /* Socket not initialized */
        return;

    unix_time_update();

    IPPort ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;

    Socket socket;
    socket.fd = sock;
    while (socket.recvfrom(&ip_port, data, &length, MAX_UDP_PACKET_SIZE, /*flags*/ 0) != -1)
    {
        if (length < 1) continue;

        uint8_t handler_id = data[0];
        const Packet_Handler& handler = packethandlers[handler_id];

        if (!handler.function) {
            //LOGGER_WARNING("[%02u] -- Packet has no handler", data[0]);
            continue;
        } else {
            handler.function(handler.object, ip_port, data, length);
        }
    }
}


int sock_valid(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    return socket.is_valid();
}

void kill_sock(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    socket.kill();
}

int set_socket_nonblock(sock_t sock) {
    Socket socket;
    socket.fd = sock;
    return socket.set_nonblock();
}

int set_socket_nosigpipe(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    return socket.set_nosigpipe();
}

int set_socket_reuseaddr(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    return socket.set_reuseaddr();
}

int set_socket_dualstack(sock_t sock)
{
    Socket socket;
    socket.fd = sock;
    return socket.set_dualstack();
}

int sendpacket(Networking_Core* net, IPPort ip_port, const uint8_t* data, uint16_t length)
{
    Socket socket;
    socket.fd = net->sock;
    return socket.sendto(net->family, ip_port, data, length, /*flags*/ 0);
}

void networking_registerhandler(Networking_Core* net, uint8_t byte, packet_handler_callback cb, void* object)
{
    Packet_Handler& handler = net->packethandlers[byte];
    handler.function = cb;
    handler.object = object;
}

void networking_poll(Networking_Core* net)
{
    net->poll();
}

Networking_Core* new_networking(IP ip, uint16_t port)
{
    return new_networking_ex(ip, port, port + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM), 0);
}

Networking_Core* new_networking_ex(IP ip, uint16_t port_from, uint16_t port_to, unsigned int* error)
{
    /* If both from and to are 0, use default port range
     * If one is 0 and the other is non-0, use the non-0 value as only port
     * If from > to, swap
     */
    if (port_from == 0 && port_to == 0) {
        port_from = TOX_PORTRANGE_FROM;
        port_to = TOX_PORTRANGE_TO;
    } else if (port_from == 0 && port_to != 0) {
        port_from = port_to;
    } else if (port_from != 0 && port_to == 0) {
        port_to = port_from;
    } else if (port_from > port_to) {
        uint16_t temp = port_from;
        port_from = port_to;
        port_to = temp;
    }

    if (error)
        *error = 2;

    /* maybe check for invalid IPs like 224+.x.y.z? if there is any IP set ever */
    if (!ip.isset()) {
        // Invalid address family
        return NULL;
    }

    if (networking_at_startup() != 0)
        return NULL;

    Networking_Core* net = new Networking_Core();

    net->family = (sa_family_t) ip.family;
    net->port = 0;

    size_t tx_rx_buff_size = 1024 * 1024 * 2;
    Socket net_socket(net->family, tx_rx_buff_size);
    net->sock = net_socket.fd;

    /* Check for socket error. */
    if ( !net_socket.is_valid() ) {
        kill_networking(net);

        if (error)
            *error = 1;

        return NULL;
    }

    /* iOS UDP sockets are weird and apparently can SIGPIPE */
    if ( !net_socket.set_nosigpipe() ) {
        kill_networking(net);

        if (error)
            *error = 1;

        return NULL;
    }

    /* Set socket nonblocking. */
    if ( !net_socket.set_nonblock() ) {
        kill_networking(net);

        if (error)
            *error = 1;

        return NULL;
    }

    if (ip.family == bitox::network::Family::FAMILY_AF_INET6) {
        if ( !net_socket.set_dualstack() ) {
            kill_networking(net);

            if (error)
                *error = 1;

            return NULL;
        }

        ipv6_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xFF;
        mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
        mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
        mreq.ipv6mr_interface = 0;

        const int ret = setsockopt(net_socket.fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
        if ( ret == -1 ) {
            kill_networking(net);

            if (error)
                *error = 1;

            return NULL;
        }

       // LOGGER_DEBUG(res < 0 ? "Failed to activate local multicast membership. (%u, %s)" :
       //              "Local multicast group FF02::1 joined successfully", errno, strerror(errno) );
    }

    /* a hanging program or a different user might block the standard port;
     * as long as it isn't a parameter coming from the commandline,
     * try a few ports after it, to see if we can find a "free" one
     *
     * if we go on without binding, the first sendto() automatically binds to
     * a free port chosen by the system (i.e. anything from 1024 to 65535)
     *
     * returning NULL after bind fails has both advantages and disadvantages:
     * advantage:
     *   we can rely on getting the port in the range 33445..33450, which
     *   enables us to tell joe user to open their firewall to a small range
     *
     * disadvantage:
     *   some clients might not test return of tox_new(), blindly assuming that
     *   it worked ok (which it did previously without a successful bind)
     */

    /* Bind our socket to port PORT and the given IP address (usually 0.0.0.0 or ::) */
    IPPort ip_port;
    ip_port.ip = ip;
    uint16_t port_to_try = port_from;

    for (int tries = 0; tries <= std::max(port_to-port_from, 10); tries++, port_to_try++) {
        if (port_to_try > port_to)
            port_to_try = port_from;
        ip_port.port = htons(port_to_try);

        const int ret = net_socket.bind(ip_port);
        if (!ret) {
            net->port = ip_port.port;

            //LOGGER_DEBUG("Bound successfully to %s:%u", ip_ntoa(&ip), ntohs(temp->port));

            /* errno isn't reset on success, only set on failure, the failed
             * binds with parallel clients yield a -EPERM to the outside if
             * errno isn't cleared here */
            errno = 0;

            if (error)
                *error = 0;

            return net;
        }
    }

    //LOGGER_ERROR("Failed to bind socket: %u, %s IP: %s port_from: %u port_to: %u", errno, strerror(errno),
    //             ip_ntoa(&ip), port_from, port_to);

    kill_networking(net);

    if (error)
        *error = 1;

    return NULL;
}

/* Function to cleanup networking stuff. */
void kill_networking(Networking_Core* net)
{
    delete net;
    return;
}


int ip_equal(const IP* a, const IP* b) {
    if (!a || !b)
        return 0;

    return *a == *b;
}

void ip_reset(IP* ip) {
    if (!ip)
        return;

    *ip = IP();
}

void ip_init(IP* ip, uint8_t ipv6enabled) {
    if (!ip)
        return;

    *ip = IP::create(ipv6enabled);
}

int ip_isset(const IP* ip) {
    if (!ip)
        return 0;

    return ip->isset();
}

void ip_copy(IP* target, const IP* source)
{
    if (!source || !target)
        return;

    *target = *source;
}

int ipport_equal(const IPPort* a, const IPPort* b) {
    if (!a || !b || !a->port)
        return 0;

    return *a == *b;
}

int ipport_isset(const IPPort* ipport)
{
    if (!ipport || !ipport->port)
        return 0;

    return ipport->ip.isset();
}

void ipport_copy(IPPort* target, const IPPort* source)
{
    if (!source || !target)
        return;

    *target = *source;
}

int ip_parse_addr(const IP* ip, char* address, size_t length)
{
    if (!address || !ip) {
        return 0;
    }

    if (ip->family == bitox::network::Family::FAMILY_AF_INET)
    {
        in_addr addr = ip->to_in_addr();
        return inet_ntop((int) ip->family, &addr, address, length) != NULL;
    } else if (ip->family == bitox::network::Family::FAMILY_AF_INET6) {
        in6_addr addr = ip->to_in6_addr();
        return inet_ntop((int) ip->family, &addr, address, length) != NULL;
    }
}

static char addresstext[96];
const char* ip_ntoa(const IP* ip)
{
    if (!ip) {
        snprintf(addresstext, sizeof(addresstext), "(IP invalid: NULL)");
        return addresstext;
    }

    char converted[INET6_ADDRSTRLEN];
    size_t converted_size = sizeof(converted);
    const int ret = ip_parse_addr(ip, converted, converted_size);
    if (ret == 0) {
        snprintf(addresstext, sizeof(addresstext), "(IP invalid, %s)", strerror(errno));
        return addresstext;
    }

    if (ip->family == bitox::network::Family::FAMILY_AF_INET) {
        /* returns standard quad-dotted notation */
        snprintf(addresstext, sizeof(addresstext), "%s", converted);
        return addresstext;
    } else if (ip->family == bitox::network::Family::FAMILY_AF_INET6) {
        /* returns hex-groups enclosed into square brackets */
        snprintf(addresstext, sizeof(addresstext), "[%s]", converted);
        return addresstext;
    } else {
        // should never happen because ip_parse_addr would have handled it
        return "";
    }
}

int addr_parse_ip(const char *address, IP *to)
{
    if (!address || !to)
        return 0;

    try
    {
        to->from_string(address);
    }
    catch (std::exception &e)
    {
        return 0;
    }
    
    if (to->address.is_v4())
    {
        to->family = bitox::network::Family::FAMILY_AF_INET;
        return 1;
    }
    else
    {
        to->family = bitox::network::Family::FAMILY_AF_INET6;
        return 1;
    }

    return 0;
}

int addr_resolve(const char* address, IP* to, IP* extra)
{
    if (!address || !to)
        return 0;

    if (networking_at_startup() != 0)
        return 0;

    const sa_family_t family = (sa_family_t) to->family;

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

    addrinfo* server = NULL;
    int rc = getaddrinfo(address, NULL, &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

    in_addr addr4;
    in6_addr addr6;
    for (const addrinfo* walker = server; (walker != NULL) && (rc != 3); walker = walker->ai_next) {
        switch (walker->ai_family) {
            case AF_INET: {
                if (walker->ai_family == family) { /* AF_INET requested, done */
                    const sockaddr_in* const addr = (sockaddr_in*) walker->ai_addr;
                    to->from_in_addr(addr->sin_addr);
                    rc = 3;
                } else if (!(rc & 1)) { /* AF_UNSPEC requested, store away */
                    const sockaddr_in* const addr = (sockaddr_in*) walker->ai_addr;
                    addr4 = addr->sin_addr;
                    rc |= 1;
                }
            } break;

            case AF_INET6: {
                if (walker->ai_family == family) { /* AF_INET6 requested, done */
                    if (walker->ai_addrlen == sizeof(sockaddr_in6)) {
                        const sockaddr_in6* const addr = (sockaddr_in6*) walker->ai_addr;
                        to->from_in6_addr(addr->sin6_addr);
                        rc = 3;
                    }
                } else if (!(rc & 2)) { /* AF_UNSPEC requested, store away */
                    if (walker->ai_addrlen == sizeof(sockaddr_in6)) {
                        const sockaddr_in6* const addr = (sockaddr_in6*) walker->ai_addr;
                        addr6= addr->sin6_addr;
                        rc |= 2;
                    }
                }
            } break;
        }
    }

    if (to->family == Family::FAMILY_NULL) {
        if (rc & 2) {
            to->family = Family::FAMILY_AF_INET6;
            to->from_in6_addr(addr6);

            if ((rc & 1) && (extra != NULL)) {
                extra->family = Family::FAMILY_AF_INET;
                extra->from_in_addr(addr4);
            }
        } else if (rc & 1) {
            to->family = Family::FAMILY_AF_INET;
            to->from_in_addr(addr4);
        } else
            rc = 0;
    }

    freeaddrinfo(server);
    return rc;
}

int addr_resolve_or_parse_ip(const char* address, IP* to, IP* extra)
{
    if (!addr_resolve(address, to, extra))
        if (!addr_parse_ip(address, to))
            return 0;

    return 1;
}

}
}