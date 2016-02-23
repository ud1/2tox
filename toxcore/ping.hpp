/*
 * ping.h -- Buffered pinging using cyclic arrays.
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
 */
#ifndef __PING_H__
#define __PING_H__

/* Maximum newly announced nodes to ping per TIME_TO_PING seconds. */
constexpr size_t MAX_TO_PING = 32;

#include "protocol.hpp"

struct DHT;

struct PING : public bitox::network::IncomingPacketListener
{
    explicit PING (DHT *dht);
    ~PING();

    DHT *dht;

    struct PingData
    {
        bitox::PublicKey public_key;
        bitox::network::IPPort ip_port;
    };

    bitox::PingArray<PingData> ping_array;
    bitox::dht::NodeFormat to_ping[MAX_TO_PING];
    uint64_t    last_to_ping;

    int send_ping_request (bitox::network::IPPort ipp, const bitox::PublicKey &public_key);

    /* Add nodes to the to_ping list.
    * All nodes in this list are pinged every TIME_TOPING seconds
    * and are then removed from the list.
    * If the list is full the nodes farthest from our public_key are replaced.
    * The purpose of this list is to enable quick integration of new nodes into the
    * network while preventing amplification attacks.
    *
    *  return 0 if node was added.
    *  return -1 if node was not added.
    */
    int add_to_ping (const bitox::PublicKey &public_key, bitox::network::IPPort ip_port);
    
    void do_to_ping ();

    virtual void onPingRequest (const bitox::network::IPPort &source, const bitox::PublicKey &sender_public_key, const bitox::PingRequestData &data) override;
    virtual void onPingResponse (const bitox::network::IPPort &source, const bitox::PublicKey &sender_public_key, const bitox::PingResponseData &data) override;
};


#endif /* __PING_H__ */
