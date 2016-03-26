#ifndef EVENT_DISPATCHER_HPP
#define EVENT_DISPATCHER_HPP

#include "protocol.hpp"


class DHT;
class Onion;
class Onion_Client;
class TCP_Connections;
class Onion_Announce;
class Net_Crypto;
struct New_Connection;
class Friend_Connections;

namespace bitox
{

class Ping;

class EventDispatcher : private network::PacketDecoder
{
public:
    EventDispatcher(CryptoManager &crypto_manager) : PacketDecoder(crypto_manager) {}
    
    void on_network_packet(const network::IPPort &ip_port, const uint8_t *data, uint16_t len);
    void on_tcp_onion(const uint8_t *data, uint16_t length);
    
    /* Set function to be called when someone requests a new connection to us
     * return -1 on failure and 0 on success.
     */
    int on_net_crypto_new_connection(const New_Connection &new_connection);
    
    
    void set_ping(Ping *ping)
    {
        this->ping = ping;
    }
    
    void set_dht(DHT *dht)
    {
        this->dht = dht;
    }
    
    void set_onion(Onion *onion)
    {
        this->onion = onion;
    }
    
    void set_onion_client(Onion_Client *onion_client)
    {
        this->onion_client = onion_client;
    }
    
    void set_onion_announce(Onion_Announce *onion_announce)
    {
        this->onion_announce = onion_announce;
    }
    
    void set_net_crypto(Net_Crypto *net_crypto)
    {
        this->net_crypto = net_crypto;
    }
    
    void set_friend_connections(Friend_Connections *friend_connections)
    {
        this->friend_connections = friend_connections;
    }
    
    /*void set_tcp_connections(TCP_Connections *tcp_connections)
    {
        this->tcp_connections = tcp_connections;
    }*/
    
private:
    Ping *ping = nullptr;
    DHT *dht = nullptr;
    Onion *onion = nullptr;
    Onion_Client *onion_client = nullptr;
    Onion_Announce *onion_announce = nullptr;
    Net_Crypto *net_crypto = nullptr;
    Friend_Connections *friend_connections = nullptr;
    //TCP_Connections *tcp_connections = nullptr;
    
    virtual void on_ping_request (const network::IPPort &source, const PublicKey &sender_public_key, const PingRequestData &data) override;
    virtual void on_ping_response (const network::IPPort &source, const PublicKey &sender_public_key, const PingResponseData &data) override;
    virtual void on_get_nodes_request (const network::IPPort &source, const PublicKey &sender_public_key, const GetNodesRequestData &data) override;
    virtual void on_send_nodes (const network::IPPort &source, const PublicKey &sender_public_key, const SendNodesData &data) override;
    virtual void on_announce_request (const network::IPPort &source, const PublicKey &sender_public_key, const AnnounceRequestData &data) override;
    virtual void on_NAT_ping (const network::IPPort &source, const PublicKey &sender_public_key, const NATPingCryptoData &data) override;
    virtual void reroute_incoming_packet(const PublicKey &public_key, InputBuffer &packet) override;
};
    
    
}

#endif
