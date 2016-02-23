/*
 * ping.c -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
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

#include <stdint.h>

#include "DHT.hpp"
#include "ping.hpp"

#include "network.hpp"
#include "util.hpp"
#include "ping_array.hpp"
#include <cstring>

#include "protocol.hpp"

#define PING_NUM_MAX 512



/* Ping newly announced nodes to ping per TIME_TO_PING seconds*/
#define TIME_TO_PING 2

using namespace bitox;
using namespace bitox::network;

int PING::send_ping_request(IPPort ipp, const bitox::PublicKey &recepient_public_key)
{
    if (recepient_public_key == dht->self_public_key)
        return 1;

    PingRequestData ping_request;
    
    PING::PingData ping_data;
    ping_data.public_key = recepient_public_key;
    ping_data.ip_port = ipp;
    // Generate random ping_id.
    ping_request.ping_id = ping_array.add(std::move(ping_data));

    if (ping_request.ping_id == 0)
        return 1;

    OutputBuffer packet;
    if (!generateOutgoingPacket(*dht->crypto_manager.get(), recepient_public_key, ping_request, packet))
        return 1;
    
    return sendpacket(dht->net, ipp, packet.begin(), packet.size());
}

void PING::onPingRequest (const IPPort &source, const PublicKey &sender_public_key, const PingRequestData &data)
{
    if (sender_public_key == dht->self_public_key)
        return;
    
    PingResponseData response;
    response.ping_id = data.ping_id;
    
    OutputBuffer packet;
    if (!generateOutgoingPacket (*dht->crypto_manager.get(), sender_public_key, response, packet))
        return;
    
    sendpacket(dht->net, source, packet.begin(), packet.size());
    add_to_ping(sender_public_key, source);
}

void PING::onPingResponse (const IPPort &source, const bitox::PublicKey &sender_public_key, const bitox::PingResponseData &data)
{
    if (sender_public_key == dht->self_public_key)
        return;
    
    PING::PingData ping_data;
    if (!ping_array.check(ping_data, data.ping_id))
        return;
    
    if (sender_public_key != ping_data.public_key)
        return;

    if (!ipport_equal(&ping_data.ip_port, &source))
        return;

    dht->addto_lists(source, sender_public_key);
}

/* Check if public_key with ip_port is in the list.
 *
 * return 1 if it is.
 * return 0 if it isn't.
 */
static int in_list(const Client_data *list, uint16_t length, const bitox::PublicKey &public_key, IPPort ip_port)
{
    unsigned int i;

    for (i = 0; i < length; ++i) {
        if (list[i].public_key == public_key) {
            const IPPTsPng *ipptp;

            if (ip_port.ip.family == Family::FAMILY_AF_INET) {
                ipptp = &list[i].assoc4;
            } else {
                ipptp = &list[i].assoc6;
            }

            if (!is_timeout(ipptp->timestamp, BAD_NODE_TIMEOUT) && ipport_equal(&ipptp->ip_port, &ip_port))
                return 1;
        }
    }

    return 0;
}

/* Add nodes to the to_ping list.
 * All nodes in this list are pinged every TIME_TO_PING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our public_key are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int PING::add_to_ping(const bitox::PublicKey &public_key, IPPort ip_port)
{
    if (!ip_isset(&ip_port.ip))
        return -1;

    if (!dht->node_addable_to_close_list(public_key, ip_port))
        return -1;

    if (in_list(dht->close_clientlist, LCLIENT_LIST, public_key, ip_port))
        return -1;

    IPPort temp;

    if (dht->getfriendip(public_key, &temp) == 0) {
        send_ping_request(ip_port, public_key);
        return -1;
    }

    unsigned int i;

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (!ip_isset(&to_ping[i].ip_port.ip)) {
            to_ping[i].public_key = public_key;
            ipport_copy(&to_ping[i].ip_port, &ip_port);
            return 0;
        }

        if (to_ping[i].public_key == public_key) {
            return -1;
        }
    }

    if (add_to_list(to_ping, MAX_TO_PING, public_key, ip_port, dht->self_public_key))
        return 0;

    return -1;
}


/* Ping all the valid nodes in the to_ping list every TIME_TO_PING seconds.
 * This function must be run at least once every TIME_TO_PING seconds.
 */
void PING::do_to_ping()
{
    if (!is_timeout(last_to_ping, TIME_TO_PING))
        return;

    if (!ip_isset(&to_ping[0].ip_port.ip))
        return;

    unsigned int i;

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (!ip_isset(&to_ping[i].ip_port.ip))
            break;

        if (!dht->node_addable_to_close_list(to_ping[i].public_key, to_ping[i].ip_port))
            continue;

        send_ping_request(to_ping[i].ip_port, to_ping[i].public_key);
        ip_reset(&to_ping[i].ip_port.ip);
    }

    if (i != 0)
        last_to_ping = unix_time();
}


PING::PING(DHT *dht) :
    ping_array(PING_NUM_MAX, PING_TIMEOUT)
{
    this->dht = dht;
    dht->subscribe(this);
}

PING::~PING()
{
}
