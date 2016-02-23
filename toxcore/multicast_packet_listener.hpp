#ifndef MULTICAST_PACKET_LISTENER_HPP
#define MULTICAST_PACKET_LISTENER_HPP

#include <set>

namespace bitox
{
namespace network
{

class MulticastPacketListener : public IncomingPacketListener
{
public:
    
    void subscribe (IncomingPacketListener *listener)
    {
        listeners.insert (listener);
    }

    void unsubscribe (IncomingPacketListener *listener)
    {
        listeners.erase (listener);
    }

    virtual void onPingRequest (const bitox::network::IPPort &source, const PublicKey &sender_public_key, const PingRequestData &data) override
    {
        for (IncomingPacketListener * listener : listeners)
        {
            listener->onPingRequest (source, sender_public_key, data);
        }
    }

    virtual void onPingResponse (const bitox::network::IPPort &source, const PublicKey &sender_public_key, const PingResponseData &data) override
    {
        for (IncomingPacketListener * listener : listeners)
        {
            listener->onPingResponse (source, sender_public_key, data);
        }
    }

    virtual void onGetNodesRequest (const bitox::network::IPPort &source, const PublicKey &sender_public_key, const GetNodesRequestData &data) override
    {
        for (IncomingPacketListener * listener : listeners)
        {
            listener->onGetNodesRequest (source, sender_public_key, data);
        }
    }
    
    virtual void onSendNodes (const bitox::network::IPPort &source, const PublicKey &sender_public_key, const SendNodesData &data) override
    {
        for (IncomingPacketListener * listener : listeners)
        {
            listener->onSendNodes (source, sender_public_key, data);
        }
    }
    
    virtual void onAnnounceRequest (const bitox::network::IPPort &source, const PublicKey &sender_public_key, const AnnounceRequestData &data) override
    {
        for (IncomingPacketListener * listener : listeners)
        {
            listener->onAnnounceRequest (source, sender_public_key, data);
        }
    }

private:
    std::set<IncomingPacketListener *>listeners;
};

}
}

#endif
