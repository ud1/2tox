#include <gtest/gtest.h>
#include <toxcore/protocol_impl.hpp>
#include <sodium.h>

using namespace bitox;
using namespace bitox::impl;
using namespace bitox::network;

struct PacketListener : public IncomingPacketListener
{
    PublicKey sender_public_key;
    PingRequestData ping_request_data;
    PingResponseData ping_response_data;
    GetNodesRequestData get_nodes_request_data;
    SendNodesData send_nodes_data;
    bool called = false;
    
    virtual void onPingRequest (const IPPort &source, const PublicKey &sender_public_key, const PingRequestData &data) override
    {
        this->sender_public_key = sender_public_key;
        this->ping_request_data = data;
        this->called = true;
    }
    
    virtual void onPingResponse (const IPPort &source, const PublicKey &sender_public_key, const PingResponseData &data) override
    {
        this->sender_public_key = sender_public_key;
        this->ping_response_data = data;
        this->called = true;
    }
    
    virtual void onGetNodesRequest (const IPPort &source, const PublicKey &sender_public_key, const GetNodesRequestData &data) override
    {
        this->sender_public_key = sender_public_key;
        this->get_nodes_request_data = data;
        this->called = true;
    }
    
    virtual void onSendNodes (const IPPort &source, const PublicKey &sender_public_key, const SendNodesData &data) override
    {
        this->sender_public_key = sender_public_key;
        this->send_nodes_data = data;
        this->called = true;
    }
};

TEST (protocol, test_packet_serialization_deserialization)
{
    SecretKey secret_key1;
    PublicKey public_key1;
    crypto_box_keypair(public_key1.data.data(), secret_key1.data.data());
    
    SecretKey secret_key2;
    PublicKey public_key2;
    crypto_box_keypair(public_key2.data.data(), secret_key2.data.data());
    
    CryptoManager manager1(secret_key1, public_key1);
    CryptoManager manager2(secret_key2, public_key2);
    
    IPPort ip_port;
    
    {
        SCOPED_TRACE ("Test PingRequest");
        
        PingRequestData packet_data;
        packet_data.ping_id = 12345;
        
        OutputBuffer packet;
        
        bool res = generateOutgoingPacket(manager1, manager2.get_self_public_key(), packet_data, packet);
        ASSERT_TRUE(res);
        
        PacketListener listener;
        res = processIncomingPacket(manager2, InputBuffer(packet.begin(), packet.size()), ip_port, listener);
        ASSERT_TRUE(res);
        ASSERT_TRUE(listener.called);
        ASSERT_EQ(12345, listener.ping_request_data.ping_id);
        ASSERT_EQ(manager1.get_self_public_key(), listener.sender_public_key);
    }
    
    {
        SCOPED_TRACE ("Test PingResponse");
        
        PingResponseData packet_data;
        packet_data.ping_id = 54321;
        
        OutputBuffer packet;
        
        bool res = generateOutgoingPacket(manager1, manager2.get_self_public_key(), packet_data, packet);
        ASSERT_TRUE(res);
        
        PacketListener listener;
        res = processIncomingPacket(manager2, InputBuffer(packet.begin(), packet.size()), ip_port, listener);
        ASSERT_TRUE(res);
        ASSERT_TRUE(listener.called);
        ASSERT_EQ(54321, listener.ping_response_data.ping_id);
        ASSERT_EQ(manager1.get_self_public_key(), listener.sender_public_key);
    }
    
    {
        SCOPED_TRACE ("Test GetNodesRequest");
        
        GetNodesRequestData packet_data;
        uint8_t num = 0;
        std::generate (packet_data.client_id.data.begin(), packet_data.client_id.data.end(), [&num]()
        {
            return num++;
        });
        packet_data.ping_id = 222333;
        
        OutputBuffer packet;
        
        bool res = generateOutgoingPacket(manager1, manager2.get_self_public_key(), packet_data, packet);
        ASSERT_TRUE(res);
        
        PacketListener listener;
        res = processIncomingPacket(manager2, InputBuffer(packet.begin(), packet.size()), ip_port, listener);
        ASSERT_TRUE(res);
        ASSERT_TRUE(listener.called);
        ASSERT_EQ(222333, listener.get_nodes_request_data.ping_id);
        ASSERT_EQ(packet_data.client_id, listener.get_nodes_request_data.client_id);
        ASSERT_EQ(manager1.get_self_public_key(), listener.sender_public_key);
    }
    
    {
        SCOPED_TRACE ("Test SendNodes");
        
        SendNodesData packet_data;
        dht::NodeFormat node_format;
        uint8_t num = 10;
        std::generate (node_format.public_key.data.begin(), node_format.public_key.data.end(), [&num]()
        {
            return num++;
        });
        node_format.ip_port.ip.family = bitox::network::Family::FAMILY_TCP_INET;
        node_format.ip_port.ip.address = boost::asio::ip::address::from_string("8.8.8.8");
        node_format.ip_port.port = 456;
        packet_data.nodes.push_back(node_format);
        packet_data.ping_id = 666555;
        
        OutputBuffer packet;
        
        bool res = generateOutgoingPacket(manager1, manager2.get_self_public_key(), packet_data, packet);
        ASSERT_TRUE(res);
        
        PacketListener listener;
        res = processIncomingPacket(manager2, InputBuffer(packet.begin(), packet.size()), ip_port, listener);
        ASSERT_TRUE(res);
        ASSERT_TRUE(listener.called);
        ASSERT_EQ(666555, listener.send_nodes_data.ping_id);
        ASSERT_EQ(1, listener.send_nodes_data.nodes.size());
        ASSERT_EQ(bitox::network::Family::FAMILY_TCP_INET, listener.send_nodes_data.nodes[0].ip_port.ip.family);
        ASSERT_EQ(node_format.ip_port.ip.address, listener.send_nodes_data.nodes[0].ip_port.ip.address);
        ASSERT_EQ(456, listener.send_nodes_data.nodes[0].ip_port.port);
        ASSERT_EQ(manager1.get_self_public_key(), listener.sender_public_key);
    }
}