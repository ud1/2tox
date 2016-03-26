#include "protocol_impl.hpp"

#include <algorithm>
#include <sodium.h>
#include "crypto_core.hpp"

namespace bitox
{
using namespace bitox::impl;

static_assert(PUBLIC_KEY_LEN == crypto_box_BEFORENMBYTES,  "Wrong PUBLIC_KEY_LEN constant value");
static_assert(SHARED_KEY_LEN == crypto_box_BEFORENMBYTES,  "Wrong SHARED_KEY_LEN constant value");
static_assert(SECRET_KEY_LEN == crypto_box_SECRETKEYBYTES, "Wrong SECRET_KEY_LEN constant value");
static_assert(NONCE_LEN      == crypto_box_NONCEBYTES,     "Wrong NONCE_LEN constant value");
static_assert(MAC_BYTES_LEN  == crypto_box_MACBYTES,       "Wrong MAC_BYTES_LEN constant value");

namespace network 
{

bool IP::operator==(const IP& other) const
{
    if (!isset() || !other.isset())
        return false;
    
    const bool self_v4 = address.is_v4();
    const bool other_v4 = other.address.is_v4();
    
    if (self_v4 && other_v4 || !self_v4 && !other_v4)
        return address == other.address;
    
    if (self_v4)
    {
        boost::asio::ip::address_v6 o = other.address.to_v6();
        if (o.is_v4_compatible() || o.is_v4_mapped())
            return address.to_v4() == o.to_v4();
    }
    else
    {
        boost::asio::ip::address_v6 s = address.to_v6();
        if (s.is_v4_compatible() || s.is_v4_mapped())
            return other.address.to_v4() == s.to_v4();
    }
    
    return false;
}    

    
}

    
Nonce Nonce::create_empty()
{
    Nonce result;
    result.data = {};
    return result;
}

Nonce Nonce::create_random()
{
    Nonce result;
    randombytes_buf(result.data.data(), NONCE_LEN);
    return result;
}

Nonce& Nonce::operator++()
{
    increment_nonce(data.data());
    return *this;
}

SymmetricKey SymmetricKey::create_random()
{
    SymmetricKey result;
    randombytes(result.data.data(), SHARED_KEY_LEN);
    return result;
}

namespace network
{
static void write_ipv6_address(OutputBuffer &buffer, const boost::asio::ip::address &address)
{
    boost::asio::ip::address_v6::bytes_type ip6_bytes = address.to_v6().to_bytes();
    buffer.write_bytes(ip6_bytes.begin(), ip6_bytes.end());
}

static void write_ipv4_address(OutputBuffer &buffer, const boost::asio::ip::address &address)
{
    boost::asio::ip::address_v4::bytes_type ip4_bytes = address.to_v4().to_bytes();
    buffer.write_bytes(ip4_bytes.begin(), ip4_bytes.end());
}

static void read_ipv6_address(InputBuffer &buffer, boost::asio::ip::address &out_address)
{
    boost::asio::ip::address_v6::bytes_type ip6_bytes;
    buffer.read_bytes(ip6_bytes.begin(), ip6_bytes.size());
    out_address = boost::asio::ip::address(boost::asio::ip::address_v6(ip6_bytes));
}

static void read_ipv4_address(InputBuffer &buffer, boost::asio::ip::address &out_address)
{
    boost::asio::ip::address_v4::bytes_type ip4_bytes;
    buffer.read_bytes(ip4_bytes.begin(), ip4_bytes.size());
    out_address = boost::asio::ip::address(boost::asio::ip::address_v4(ip4_bytes));
}

bool write_node_format (OutputBuffer &buffer, const dht::NodeFormat &node_format)
{
    bitox::impl::network::ToxFamily tox_family = bitox::impl::network::to_tox_family(node_format.ip_port.ip.family);
    
    if (node_format.ip_port.ip.family == bitox::network::Family::FAMILY_AF_INET6 || node_format.ip_port.ip.family == bitox::network::Family::FAMILY_TCP_INET6)
    {
        assert(node_format.ip_port.ip.address.is_v6() && "Address must be IPv6");
        
        buffer.write_byte(tox_family);
        write_ipv6_address(buffer, node_format.ip_port.ip.address);
        buffer << const_uint16_adapter(node_format.ip_port.port) << node_format.public_key;
    }
    else if (node_format.ip_port.ip.family == bitox::network::Family::FAMILY_AF_INET || node_format.ip_port.ip.family == bitox::network::Family::FAMILY_TCP_INET)
    {
        assert(node_format.ip_port.ip.address.is_v4() && "Address must be IPv4");
        
        buffer.write_byte(tox_family);
        write_ipv4_address(buffer, node_format.ip_port.ip.address);
        buffer << const_uint16_adapter(node_format.ip_port.port) << node_format.public_key;
    }
    else
    {
        assert(false && "Invalid node_format");
        return false;
    }
    
    return true;
}

static bool read_node_format (InputBuffer &buffer, dht::NodeFormat &out_node_format)
{
    bitox::impl::network::ToxFamily tox_family;
    buffer.read_byte((uint8_t &) tox_family);
    
    if (tox_family == bitox::impl::network::TOX_AF_INET6 || tox_family == bitox::impl::network::TOX_TCP_INET6)
    {
        out_node_format.ip_port.ip.family = bitox::impl::network::from_tox_family(tox_family);
        read_ipv6_address(buffer, out_node_format.ip_port.ip.address);
        buffer >> uint16_adapter(out_node_format.ip_port.port) >> out_node_format.public_key;
    }
    else if (tox_family == bitox::impl::network::TOX_AF_INET || tox_family == bitox::impl::network::TOX_TCP_INET)
    {
        out_node_format.ip_port.ip.family = bitox::impl::network::from_tox_family(tox_family);
        read_ipv4_address(buffer, out_node_format.ip_port.ip.address);
        buffer >> uint16_adapter(out_node_format.ip_port.port) >> out_node_format.public_key;
    }
    else
    {
        return false;
    }
    
    return !buffer.fail();
}

static bool generateOutgoingPacket(const CryptoManager &crypto_manager, PacketType packetType, OutputBuffer data_to_encrypt, const PublicKey &recipient_public_key, OutputBuffer &out_packet)
{
    Nonce nonce = Nonce::create_random();
    
    Buffer encrypted_data;
    if (!crypto_manager.encrypt_buffer(data_to_encrypt.get_buffer_data(), recipient_public_key, nonce, encrypted_data))
        return false;
        
    out_packet = OutputBuffer();
    out_packet << packetType << crypto_manager.get_self_public_key() << nonce;
    out_packet << encrypted_data;
    return true;
}

static bool generateOutgoingCryptoPacket(const CryptoManager &crypto_manager, OutputBuffer data_to_encrypt, const PublicKey &recipient_public_key, OutputBuffer &out_packet)
{
    Nonce nonce = Nonce::create_random();
    
    Buffer encrypted_data;
    if (!crypto_manager.encrypt_buffer(data_to_encrypt.get_buffer_data(), recipient_public_key, nonce, encrypted_data))
        return false;
        
    out_packet = OutputBuffer();
    out_packet << NET_PACKET_CRYPTO << recipient_public_key << crypto_manager.get_self_public_key() << nonce;
    out_packet << encrypted_data;
    return true;
}
    
bool generateOutgoingPacket(const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const PingRequestData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << NET_PACKET_PING_REQUEST << const_uint64_adapter(data.ping_id);
    
    return generateOutgoingPacket(crypto_manager, NET_PACKET_PING_REQUEST, data_to_encrypt, recipient_public_key, out_packet);
}

bool PacketDecoder::process_incoming_ping_request_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source)
{
    PacketType packet_type;
    PingRequestData ping_request;
    
    if ((decrypted_buffer >> packet_type >> uint64_adapter(ping_request.ping_id)).fail())
        return false;
    
    if (packet_type != NET_PACKET_PING_REQUEST)
        return false;
    
    on_ping_request(source, sender_public_key, ping_request);
    return true;
}

bool generateOutgoingPacket(const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const PingResponseData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << NET_PACKET_PING_RESPONSE << const_uint64_adapter(data.ping_id);
    
    return generateOutgoingPacket(crypto_manager, NET_PACKET_PING_RESPONSE, data_to_encrypt, recipient_public_key, out_packet);
}

bool PacketDecoder::process_incoming_ping_response_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source)
{
    PacketType packet_type;
    PingResponseData ping_response;
    
    if ((decrypted_buffer >> packet_type >> uint64_adapter(ping_response.ping_id)).fail())
        return false;
    
    if (packet_type != NET_PACKET_PING_RESPONSE)
        return false;
    
    on_ping_response(source, sender_public_key, ping_response);
    return true;
}

bool generateOutgoingPacket(const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const GetNodesRequestData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << data.client_id << const_uint64_adapter(data.ping_id);
    
    return generateOutgoingPacket(crypto_manager, NET_PACKET_GET_NODES, data_to_encrypt, recipient_public_key, out_packet);
}

bool PacketDecoder::process_get_nodes_request_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source)
{
    GetNodesRequestData get_nodes_request;
    
    if ((decrypted_buffer >> get_nodes_request.client_id >> uint64_adapter(get_nodes_request.ping_id)).fail())
        return false;
       
    on_get_nodes_request(source, sender_public_key, get_nodes_request);
    return true;
}

bool generateOutgoingPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const SendNodesData &data, OutputBuffer &out_packet)
{
    if (data.nodes.size() > MAX_SENT_NODES)
    {
        assert(false && "Invalid SendNodesData");
        return false;
    }
        
    OutputBuffer data_to_encrypt;
    data_to_encrypt.write_byte((uint8_t) data.nodes.size());
    
    for (const dht::NodeFormat &node_format : data.nodes)
    {
        if (!write_node_format(data_to_encrypt, node_format))
            return false;
    }
    
    data_to_encrypt << const_uint64_adapter(data.ping_id);
    
    return generateOutgoingPacket(crypto_manager, NET_PACKET_SEND_NODES_IPV6, data_to_encrypt, recipient_public_key, out_packet);
}

bool PacketDecoder::process_set_nodes_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source)
{
    SendNodesData send_nodes;
    uint8_t nodes_size;
    if (decrypted_buffer.read_byte(nodes_size).fail())
        return false;
    
    if (nodes_size == 0 || nodes_size > MAX_SENT_NODES)
        return false;
    
    for (size_t i = 0; i < nodes_size; ++i)
    {
        dht::NodeFormat node_format;
        
        if (!read_node_format(decrypted_buffer, node_format))
            return false;
        
        send_nodes.nodes.push_back(node_format);
    }
    
    if ((decrypted_buffer >> uint64_adapter(send_nodes.ping_id)).fail())
        return false;
       
    on_send_nodes(source, sender_public_key, send_nodes);
    return true;
}

bool generateOutgoingPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const AnnounceRequestData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << data.ping_id << data.client_id << data.data_public_key << const_uint64_adapter(data.sendback_data);
    return generateOutgoingPacket(crypto_manager, NET_PACKET_ANNOUNCE_REQUEST, data_to_encrypt, recipient_public_key, out_packet);
}

bool PacketDecoder::process_announce_request_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source)
{
    AnnounceRequestData announce;
    if ((decrypted_buffer >> announce.ping_id >> announce.client_id >> announce.data_public_key >> uint64_adapter(announce.sendback_data)).fail())
    {
        return false;
    }
    
    on_announce_request(source, sender_public_key, announce);
    return true;
}

bool generateOutgoingCryptoPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const NATPingCryptoData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << CRYPTO_PACKET_NAT_PING;
    data_to_encrypt.write_byte((uint8_t) data.type);
    data_to_encrypt << const_uint64_adapter(data.ping_id);
    return generateOutgoingCryptoPacket(crypto_manager, data_to_encrypt, recipient_public_key, out_packet);
}

bool PacketDecoder::process_NAT_ping_crypto_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source)
{
    NATPingCryptoData nat_ping;
    
    uint8_t type;
    if (decrypted_buffer.read_byte(type).fail())
        return false;
    
    if (type == 0 || type == 1)
        nat_ping.type = (NATPingCryptoData::Type) type;
    else
        return false;
    
    if ((decrypted_buffer >> uint64_adapter(nat_ping.ping_id)).fail())
        return false;
    
    on_NAT_ping(source, sender_public_key, nat_ping);
    return true;
}

enum HardeningPacketType : uint8_t
{
    //CHECK_TYPE_ROUTE_REQ = 0,
    //CHECK_TYPE_ROUTE_RES = 1,
    CHECK_TYPE_GETNODE_REQ = 2,
    CHECK_TYPE_GETNODE_RES = 3,
    //CHECK_TYPE_TEST_REQ = 4,
    //CHECK_TYPE_TEST_RES = 5,
};

constexpr size_t HARDREQ_DATA_SIZE = 384;

/**
 * Original TOX Node_Format:
 * 32 bytes - public_key
 * 1 byte - family
 * 7 bytes - padding
 * 16 bytes - ip4/ip6 bytes
 * 2 bytes - port
 * 6 bytes - padding
 */
bool generateOutgoingCryptoPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const GetNodeHardeningCryptoData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << CRYPTO_PACKET_HARDENING;
    data_to_encrypt.write_byte(CHECK_TYPE_GETNODE_REQ);
    
    // write NodeFormat
    data_to_encrypt << data.node_to_test.public_key;
    data_to_encrypt.write_byte((uint8_t) data.node_to_test.ip_port.ip.family);
    data_to_encrypt.write_zeros(7);
    if (data.node_to_test.ip_port.ip.address.is_v4())
    {
        write_ipv4_address(data_to_encrypt, data.node_to_test.ip_port.ip.address);
        data_to_encrypt.write_zeros(12);
    }
    else
    {
        write_ipv6_address(data_to_encrypt, data.node_to_test.ip_port.ip.address);
    }
    data_to_encrypt << const_uint16_adapter(data.node_to_test.ip_port.port);
    data_to_encrypt.write_zeros(6);
    
    data_to_encrypt << data.search_id;
    
    data_to_encrypt.write_zeros(HARDREQ_DATA_SIZE - 1 - data_to_encrypt.size());
    
    return generateOutgoingCryptoPacket(crypto_manager, data_to_encrypt, recipient_public_key, out_packet);
}

bool PacketDecoder::process_incoming_packet(const IPPort &source, InputBuffer &&packet)
{
    PacketType packet_type;
    if (!(packet >> packet_type).fail())
    {
        if (packet_type == NET_PACKET_CRYPTO)
        {
            NetCryptoHeader header;
            
            if ((packet >> header.receiver_dht_key).fail())
                return false;
            
            if (crypto_manager.get_self_public_key() != header.receiver_dht_key) // Check if request is not for us.
            {
                packet.rewind(1 + PUBLIC_KEY_LEN);
                reroute_incoming_packet(header.receiver_dht_key, packet);
                return true;
            }
            
            if ((packet >> header.sender_dht_key >> header.nonce).fail())
                return false;
            
            Buffer decrypted_data;
            if (!crypto_manager.decrypt_buffer(packet.get_buffer_data(), header.sender_dht_key, header.nonce, decrypted_data))
                return false;
            
            InputBuffer decrypted_buffer = InputBuffer(std::move(decrypted_data));
            
            NetCryptoPacketType net_crypto_packet_type;
            if ((decrypted_buffer >> net_crypto_packet_type).fail())
                return false;
            
            switch (net_crypto_packet_type)
            {
                case CRYPTO_PACKET_NAT_PING:
                    return process_NAT_ping_crypto_packet(header.sender_dht_key, decrypted_buffer, source);
            }
        }
        else
        {
            ToxHeader header;
            header.packet_type = packet_type;
            
            if ((packet >> header.public_key >> header.nonce).fail())
                return false;
            
            Buffer decrypted_data;
            if (!crypto_manager.decrypt_buffer(packet.get_buffer_data(), header.public_key, header.nonce, decrypted_data))
                return false;
            
            InputBuffer decrypted_buffer = InputBuffer(std::move(decrypted_data));
            
            switch(header.packet_type)
            {
                case NET_PACKET_PING_REQUEST:
                    return process_incoming_ping_request_data_packet(header.public_key, decrypted_buffer, source);
                    
                case NET_PACKET_PING_RESPONSE:
                    return process_incoming_ping_response_data_packet(header.public_key, decrypted_buffer, source);
                    
                case NET_PACKET_GET_NODES:
                    return process_get_nodes_request_data_packet(header.public_key, decrypted_buffer, source);
                    
                case NET_PACKET_SEND_NODES_IPV6:
                    return process_set_nodes_data_packet(header.public_key, decrypted_buffer, source);
            }
        }
    }
    
    return false;
}

PacketDecoder::PacketDecoder(CryptoManager &crypto_manager) : crypto_manager(crypto_manager)
{
}

}
}