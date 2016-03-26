#include "event_dispatcher.hpp"
#include "ping.hpp"
#include "DHT.hpp"
#include "onion.hpp"
#include "onion_client.hpp"
#include "friend_connection.hpp"

namespace bitox
{
    
using namespace network;

void EventDispatcher::on_network_packet(const IPPort &ip_port, const uint8_t *data, uint16_t len)
{
    if (process_incoming_packet(ip_port, InputBuffer(data, len)))
        return;
    
    if (onion)
    {
        if (data[0] == PacketType::NET_PACKET_ONION_SEND_INITIAL)
        {
            onion->on_packet_send_initial(ip_port, data, len);
            return;
        }
        else if (data[0] == PacketType::NET_PACKET_ONION_SEND_1)
        {
            onion->on_packet_send_1(ip_port, data, len);
            return;
        }
        else if (data[0] == PacketType::NET_PACKET_ONION_SEND_2)
        {
            onion->on_packet_send_2(ip_port, data, len);
            return;
        }
        else if (data[0] == PacketType::NET_PACKET_ONION_RECV_3)
        {
            onion->on_packet_recv_3(ip_port, data, len);
            return;
        }
        else if (data[0] == PacketType::NET_PACKET_ONION_RECV_2)
        {
            onion->on_packet_recv_2(ip_port, data, len);
            return;
        }
        else if (data[0] == PacketType::NET_PACKET_ONION_RECV_1)
        {
            onion->on_packet_recv_1(ip_port, data, len);
            return;
        }
    }
    
    if (onion_client)
    {
        if (data[0] == PacketType::NET_PACKET_ANNOUNCE_RESPONSE)
        {
            onion_client->on_packet_announce_response(ip_port, data, len);
            return;
        }
        else if (data[0] == PacketType::NET_PACKET_ONION_DATA_RESPONSE)
        {
            onion_client->on_packet_data_response(ip_port, data, len);
            return;
        }
    }
    
    if (onion_announce)
    {
        if (data[0] == PacketType::NET_PACKET_ANNOUNCE_REQUEST)
        {
            onion_announce->on_packet_announce_request(ip_port, data, len);
            return;
        }
        else if (data[0] == PacketType::NET_PACKET_ONION_DATA_REQUEST)
        {
            onion_announce->on_packet_data_request(ip_port, data, len);
            return;
        }
    }
    
    if (dht)
    {
        if (data[0] == PacketType::NET_PACKET_LAN_DISCOVERY)
        {
            dht->on_packet_LAN_discovery(ip_port, data, len);
            return;
        }
    }
    
    if (net_crypto)
    {
        if (data[0] == PacketType::NET_PACKET_COOKIE_REQUEST)
        {
            net_crypto->on_packet_cookie_request(ip_port, data, len);
            return;
        }
        else if (
            data[0] == PacketType::NET_PACKET_COOKIE_RESPONSE ||
            data[0] == PacketType::NET_PACKET_CRYPTO_HS ||
            data[0] == PacketType::NET_PACKET_CRYPTO_DATA)
        {
            net_crypto->on_udp_packet(ip_port, data, len);
            return;
        }
    }
}

void EventDispatcher::on_tcp_onion(const uint8_t *data, uint16_t length)
{
    if (onion_client)
    {
        if (length == 0)
            return;

        IPPort ip_port;
        ip_port.port = 0;
        ip_port.ip.clear_v6();
        ip_port.ip.family = Family::FAMILY_TCP_FAMILY;

        if (data[0] == NET_PACKET_ANNOUNCE_RESPONSE)
        {
            onion_client->on_packet_announce_response(ip_port, data, length);
        }
        else if (data[0] == NET_PACKET_ONION_DATA_RESPONSE)
        {
            onion_client->on_packet_data_response(ip_port, data, length);
        }
    }
}

int EventDispatcher::on_net_crypto_new_connection(const New_Connection &new_connection)
{
    if (friend_connections)
        friend_connections->on_net_crypto_new_connection(new_connection);
}


    
void EventDispatcher::on_ping_request (const IPPort &source, const PublicKey &sender_public_key, const PingRequestData &data)
{
    if (ping)
        ping->on_ping_request(source, sender_public_key, data);
}

void EventDispatcher::on_ping_response (const IPPort &source, const PublicKey &sender_public_key, const PingResponseData &data)
{
    if (ping)
        ping->on_ping_response(source, sender_public_key, data);
}

void EventDispatcher::on_get_nodes_request (const IPPort &source, const PublicKey &sender_public_key, const GetNodesRequestData &data)
{
    if (dht)
        dht->on_get_nodes_request(source, sender_public_key, data);
}

void EventDispatcher::on_send_nodes (const IPPort &source, const PublicKey &sender_public_key, const SendNodesData &data)
{
    if (dht)
        dht->on_send_nodes(source, sender_public_key, data);
}

void EventDispatcher::on_announce_request (const IPPort &source, const PublicKey &sender_public_key, const AnnounceRequestData &data)
{
    if (onion_announce)
        onion_announce->on_announce_request(source, sender_public_key, data);
}

void EventDispatcher::on_NAT_ping (const IPPort &source, const PublicKey &sender_public_key, const NATPingCryptoData &data)
{
    if (dht)
        dht->on_NAT_ping(source, sender_public_key, data);
}

void EventDispatcher::reroute_incoming_packet(const PublicKey &public_key, InputBuffer &packet)
{
    if (dht)
        dht->reroute_incoming_packet(public_key, packet);
}
    
}