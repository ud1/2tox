/*  LAN_discovery.c
 *
 *  LAN discovery implementation.
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

#include "LAN_discovery.hpp"
#include "util.hpp"
#include <memory>
#include <cstring>
#include <cstdlib>

#include "protocol.hpp"

/* Used for get_broadcast(). */
#ifdef __linux
#include <sys/ioctl.h>
#include <arpa/inet.h>
//#include <linux/netdevice.h>
#include <unistd.h>
#endif

#define MAX_INTERFACES 16

using namespace bitox;
using namespace bitox::network;

static int     broadcast_count = -1;
static IPPort broadcast_ip_port[MAX_INTERFACES];

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)

#include <iphlpapi.h>

static void fetch_broadcast_info(uint16_t port)
{
    broadcast_count = 0;

    IP_ADAPTER_INFO *pAdapterInfo = malloc(sizeof(pAdapterInfo));
    unsigned long ulOutBufLen = sizeof(pAdapterInfo);

    if (pAdapterInfo == NULL) {
        return;
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = malloc(ulOutBufLen);

        if (pAdapterInfo == NULL) {
            return;
        }
    }

    int ret;

    if ((ret = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        IP_ADAPTER_INFO *pAdapter = pAdapterInfo;

        while (pAdapter) {
            IP gateway = {0}, subnet_mask = {0};

            if (addr_parse_ip(pAdapter->IpAddressList.IpMask.String, &subnet_mask)
                    && addr_parse_ip(pAdapter->GatewayList.IpAddress.String, &gateway)) {
                if (gateway.family == AF_INET && subnet_mask.family == AF_INET) {
                    IPPort *ip_port = &broadcast_ip_port[broadcast_count];
                    ip_port->ip.family = AF_INET;
                    uint32_t gateway_ip = ntohl(gateway.ip4.uint32), subnet_ip = ntohl(subnet_mask.ip4.uint32);
                    uint32_t broadcast_ip = gateway_ip + ~subnet_ip - 1;
                    ip_port->ip.ip4.uint32 = htonl(broadcast_ip);
                    ip_port->port = port;
                    broadcast_count++;

                    if (broadcast_count >= MAX_INTERFACES) {
                        return;
                    }
                }
            }

            pAdapter = pAdapter->Next;
        }
    }

    if (pAdapterInfo) {
        free(pAdapterInfo);
    }
}

#elif defined(__linux__)

static void fetch_broadcast_info(uint16_t port)
{
    /* Not sure how many platforms this will run on,
     * so it's wrapped in __linux for now.
     * Definitely won't work like this on Windows...
     */
    broadcast_count = 0;
    sock_t sock = 0;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return;

    /* Configure ifconf for the ioctl call. */
    struct ifreq i_faces[MAX_INTERFACES];
    memset(i_faces, 0, sizeof(struct ifreq) * MAX_INTERFACES);

    struct ifconf ifconf;
    ifconf.ifc_buf = (char *)i_faces;
    ifconf.ifc_len = sizeof(i_faces);

    if (ioctl(sock, SIOCGIFCONF, &ifconf) < 0) {
        close(sock);
        return;
    }

    /* ifconf.ifc_len is set by the ioctl() to the actual length used;
     * on usage of the complete array the call should be repeated with
     * a larger array, not done (640kB and 16 interfaces shall be
     * enough, for everybody!)
     */
    int i, count = ifconf.ifc_len / sizeof(struct ifreq);

    for (i = 0; i < count; i++) {
        /* there are interfaces with are incapable of broadcast */
        if (ioctl(sock, SIOCGIFBRDADDR, &i_faces[i]) < 0)
            continue;

        /* moot check: only AF_INET returned (backwards compat.) */
        if (i_faces[i].ifr_broadaddr.sa_family != AF_INET)
            continue;

        struct sockaddr_in *sock4 = (struct sockaddr_in *)&i_faces[i].ifr_broadaddr;

        if (broadcast_count >= MAX_INTERFACES) {
            close(sock);
            return;
        }

        IPPort *ip_port = &broadcast_ip_port[broadcast_count];
        ip_port->ip.family = Family::FAMILY_AF_INET;
        ip_port->ip.from_in_addr(sock4->sin_addr);

        if (ip_port->ip.is_unspecified()) {
            continue;
        }

        ip_port->port = port;
        broadcast_count++;
    }

    close(sock);
}

#else //TODO: Other platforms?

static void fetch_broadcast_info(uint16_t port)
{
    broadcast_count = 0;
}

#endif
/* Send packet to all IPv4 broadcast addresses
 *
 *  return 1 if sent to at least one broadcast target.
 *  return 0 on failure to find any valid broadcast target.
 */
static uint32_t send_broadcasts(Networking_Core *net, uint16_t port, const uint8_t *data, uint16_t length)
{
    /* fetch only once? on every packet? every X seconds?
     * old: every packet, new: once */
    if (broadcast_count < 0)
        fetch_broadcast_info(port);

    if (!broadcast_count)
        return 0;

    int i;

    for (i = 0; i < broadcast_count; i++)
        sendpacket(net, broadcast_ip_port[i], data, length);

    return 1;
}

/* Return the broadcast ip. */
static IP broadcast_ip(sa_family_t family_socket, sa_family_t family_broadcast)
{
    IP ip;
    ip_reset(&ip);

    if (family_socket == AF_INET6) {
        boost::asio::ip::address_v6::bytes_type bytes = ip.address.to_v6().to_bytes();
        
        if (family_broadcast == AF_INET6) {
            ip.family = Family::FAMILY_AF_INET6;
            /* FF02::1 is - according to RFC 4291 - multicast all-nodes link-local */
            /* FE80::*: MUST be exact, for that we would need to look over all
             * interfaces and check in which status they are */
            
            bytes[ 0] = 0xFF;
            bytes[ 1] = 0x02;
            bytes[15] = 0x01;
            ip.address = boost::asio::ip::address_v6(bytes);
        } else if (family_broadcast == AF_INET) {
            ip.family = Family::FAMILY_AF_INET6;
            bytes[0] = bytes[1] = bytes[2] = bytes[3] = 0;
            bytes[4] = bytes[5] = bytes[6] = bytes[7] = 0;
            bytes[8] = bytes[9] = 0;
            bytes[10] = bytes[11] = 0xff;
            bytes[12] = bytes[13] = bytes[14] = bytes[15] = 0xff;
            ip.address = boost::asio::ip::address_v6(bytes);
        }
    } else if (family_socket == AF_INET) {
        if (family_broadcast == AF_INET) {
            ip.family = Family::FAMILY_AF_INET;
            ip.from_uint32(INADDR_BROADCAST);
        }
    }

    return ip;
}

/* Is IP a local ip or not. */
bool Local_ip(IP ip)
{
    if (ip.address.is_loopback())
        return 1;
    
    if (ip.is_v4_mapped()) {
        ip.convert_to_v4();
        ip.family = Family::FAMILY_AF_INET;
        return Local_ip(ip);
    }

    return 0;
}

/*  return 0 if ip is a LAN ip.
 *  return -1 if it is not.
 */
int LAN_ip(IP ip)
{
    if (Local_ip(ip))
        return 0;

    if (ip.family == Family::FAMILY_AF_INET) {
        boost::asio::ip::address_v4::bytes_type ip4 = ip.address.to_v4().to_bytes();

        /* 10.0.0.0 to 10.255.255.255 range. */
        if (ip4[0] == 10)
            return 0;

        /* 172.16.0.0 to 172.31.255.255 range. */
        if (ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31)
            return 0;

        /* 192.168.0.0 to 192.168.255.255 range. */
        if (ip4[0] == 192 && ip4[1] == 168)
            return 0;

        /* 169.254.1.0 to 169.254.254.255 range. */
        if (ip4[0] == 169 && ip4[1] == 254 && ip4[2] != 0
                && ip4[2] != 255)
            return 0;

        /* RFC 6598: 100.64.0.0 to 100.127.255.255 (100.64.0.0/10)
         * (shared address space to stack another layer of NAT) */
        if ((ip4[0] == 100) && ((ip4[1] & 0xC0) == 0x40))
            return 0;

    } else if (ip.family == Family::FAMILY_AF_INET6) {

        boost::asio::ip::address_v6::bytes_type ip6 = ip.address.to_v6().to_bytes();
        /* autogenerated for each interface: FE80::* (up to FEBF::*)
           FF02::1 is - according to RFC 4291 - multicast all-nodes link-local */
        if (((ip6[0] == 0xFF) && (ip6[1] < 3) && (ip6[15] == 1)) ||
                ((ip6[0] == 0xFE) && ((ip6[1] & 0xC0) == 0x80)))
            return 0;

        /* embedded IPv4-in-IPv6 */
        if (ip.is_v4_mapped()) {
            IP ip4;
            ip4.family = Family::FAMILY_AF_INET;
            ip4 = ip;
            ip4.convert_to_v4();
            return LAN_ip(ip4);
        }
    }

    return -1;
}

int send_LANdiscovery(uint16_t port, DHT *dht)
{
    uint8_t data[crypto_box_PUBLICKEYBYTES + 1];
    data[0] = NET_PACKET_LAN_DISCOVERY;
    id_copy(data + 1, dht->self_public_key.data.data());

    send_broadcasts(dht->net, port, data, 1 + crypto_box_PUBLICKEYBYTES);

    int res = -1;
    IPPort ip_port;
    ip_port.port = port;

    /* IPv6 multicast */
    if (dht->net->family == AF_INET6) {
        ip_port.ip = broadcast_ip(AF_INET6, AF_INET6);

        if (ip_isset(&ip_port.ip))
            if (sendpacket(dht->net, ip_port, data, 1 + crypto_box_PUBLICKEYBYTES) > 0)
                res = 1;
    }

    /* IPv4 broadcast (has to be IPv4-in-IPv6 mapping if socket is AF_INET6 */
    ip_port.ip = broadcast_ip(dht->net->family, AF_INET);

    if (ip_isset(&ip_port.ip))
        if (sendpacket(dht->net, ip_port, data, 1 + crypto_box_PUBLICKEYBYTES))
            res = 1;

    return res;
}
