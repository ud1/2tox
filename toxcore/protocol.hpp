#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <array>
#include <memory>
#include <boost/asio.hpp>

#include "buffer.hpp"
#include <tuple>

namespace bitox
{

enum PacketType : uint8_t
{
    // Ping request packet ID
    NET_PACKET_PING_REQUEST = 0,

    // Ping response packet ID
    NET_PACKET_PING_RESPONSE = 1,

    // Get nodes request packet ID
    NET_PACKET_GET_NODES = 2,

    // Send nodes response packet ID for other addresses
    NET_PACKET_SEND_NODES_IPV6 = 4,

    // Cookie request packet
    NET_PACKET_COOKIE_REQUEST = 24,

    // Cookie response packet
    NET_PACKET_COOKIE_RESPONSE = 25,

    // Crypto handshake packet
    NET_PACKET_CRYPTO_HS = 26,

    // Crypto data packet
    NET_PACKET_CRYPTO_DATA = 27,

    // Encrypted data packet ID
    NET_PACKET_CRYPTO = 32,

    // LAN discovery packet ID
    NET_PACKET_LAN_DISCOVERY = 33,

    NET_PACKET_ONION_SEND_INITIAL = 128,
    NET_PACKET_ONION_SEND_1 = 129,
    NET_PACKET_ONION_SEND_2 = 130,

    NET_PACKET_ANNOUNCE_REQUEST = 131,
    NET_PACKET_ANNOUNCE_RESPONSE = 132,
    NET_PACKET_ONION_DATA_REQUEST = 133,
    NET_PACKET_ONION_DATA_RESPONSE = 134,

    NET_PACKET_ONION_RECV_3 = 140,
    NET_PACKET_ONION_RECV_2 = 141,
    NET_PACKET_ONION_RECV_1 = 142,
};

enum NetCryptoPacketType : uint8_t
{
    // Friend request crypto packet ID
    CRYPTO_PACKET_FRIEND_REQ = 32,
    
    // Hardening crypto packet ID
    CRYPTO_PACKET_HARDENING = 48,
    
    CRYPTO_PACKET_DHTPK = 156,
    
    // NAT ping crypto packet ID
    CRYPTO_PACKET_NAT_PING = 254,
};

constexpr size_t PUBLIC_KEY_LEN = 32;
constexpr size_t SECRET_KEY_LEN = 32;
constexpr size_t ONION_PING_ID_LEN = 32;
constexpr size_t NONCE_LEN = 24;
constexpr size_t SHARED_KEY_LEN = 32;
constexpr size_t MAC_BYTES_LEN = 16;

/* The max number of nodes to send with send nodes. */
constexpr size_t MAX_SENT_NODES = 4;

struct PublicKey
{
    PublicKey() {}
    explicit PublicKey(const uint8_t *key_bytes)
    {
        std::copy(key_bytes, key_bytes + PUBLIC_KEY_LEN, data.data());
    }
    
    std::array<uint8_t, PUBLIC_KEY_LEN> data = {};
    
    bool operator == (const PublicKey &o) const
    {
        return data == o.data;
    }
    
    bool operator != (const PublicKey &o) const
    {
        return data != o.data;
    }
    
    bool operator < (const PublicKey &o) const
    {
        return data < o.data;
    }
};

struct Nonce
{
    std::array<uint8_t, NONCE_LEN> data;

    static Nonce create_empty();
    static Nonce create_random();
    
    Nonce& operator++();
private:
    Nonce() {}
};

struct SecretKey
{
    std::array<uint8_t, SECRET_KEY_LEN> data = {};
};

struct SymmetricKey
{
    static SymmetricKey create_random();
    std::array<uint8_t, SHARED_KEY_LEN> data = {};
};

struct SharedKey : SymmetricKey {};

struct OnionPingId
{
    OnionPingId() {}
    explicit OnionPingId(const PublicKey &o) : data(o.data) {}
    
    std::array<uint8_t, ONION_PING_ID_LEN> data = {};
};

class CryptoManager
{
public:
    CryptoManager (const SecretKey &secret_key, const PublicKey &self_public_key);
    ~CryptoManager();
    bool encrypt_buffer (const BufferDataRange &data_to_encrypt, const PublicKey &recipient_public_key, const Nonce &nonce, Buffer &out_encrypted_data) const;
    bool decrypt_buffer (const BufferDataRange &data_to_decrypt, const PublicKey &sender_public_key, const Nonce &nonce, Buffer &out_decrypted_data) const;
    const PublicKey &get_self_public_key() const;

private:
    class CryptoManagerImpl;
    std::unique_ptr<CryptoManagerImpl> pimpl;
};

namespace network
{
    
enum class Family
{
    FAMILY_NULL = AF_UNSPEC,
    FAMILY_AF_INET = AF_INET,
    FAMILY_AF_INET6 = AF_INET6,
    FAMILY_TCP_ONION_FAMILY = AF_INET6 + 1,
    FAMILY_TCP_INET = AF_INET6 + 2,
    FAMILY_TCP_INET6 = AF_INET6 + 3,
    FAMILY_TCP_FAMILY = AF_INET6 + 4
};

struct IP
{
    boost::asio::ip::address address;
    Family family = Family::FAMILY_NULL;
    
    bool operator==(const IP& other) const;
    
    bool isset() const
    {
        return family != Family::FAMILY_NULL;
    }
    
    in_addr to_in_addr() const;
    in6_addr to_in6_addr() const;
    void from_in_addr(in_addr addr);
    void from_in6_addr(in6_addr addr);
    void from_uint32(uint32_t ipv4_addr);
    uint32_t to_uint32() const;
    void from_string(const std::string &str);
    
    bool is_v4_mapped() const
    {
        return address.is_v6() && address.to_v6().is_v4_mapped();
    }
    
    void convert_to_v4()
    {
        address = address.to_v6().to_v4();
    }
    
    void clear_v6()
    {
        address = boost::asio::ip::address_v6();
    }
    
    bool is_unspecified() const
    {
        return address.is_v4() && address.to_v4().is_unspecified() || address.is_v6() && address.to_v6().is_unspecified();
    }
    
    static IP create_ip4();
    static IP create_ip6();
    static IP create(bool ipv6enabled);
    
    bool operator < (const IP &o) const
    {
        return std::tie(family, address) < std::tie(o.family, o.address);
    }
};

struct OnionIP
{
    uint32_t con_id = 0;
    uint64_t identifier = 0;
};

struct IPPort
{
    IP ip;
    OnionIP onion_ip;
    uint16_t port = 0; // port stored in network byte order
    
    sockaddr_storage to_addr_4() const;
    sockaddr_storage to_addr_6() const;
    static IPPort from_addr(const sockaddr_storage& addr);
    
    bool operator==(const IPPort& other) const
    {
        return port == other.port && ip == other.ip; // TODO onion_ip?
    }
    
    bool operator!=(const IPPort& other) const
    {
        return !(*this == other);
    }

    bool isset() const
    {
        return port != 0 && ip.isset();
    }
    
    bool operator < (const IPPort &o) const
    {
        return std::tie(port, ip) < std::tie(o.port, o.ip); // TODO onion_ip?
    }
};

}

namespace dht
{
    struct NodeFormat
    {
        NodeFormat() {}
        NodeFormat(const PublicKey &public_key, const network::IPPort &ip_port) : public_key(public_key), ip_port(ip_port) {}
        
        PublicKey public_key;
        network::IPPort ip_port;
    };
}

namespace network
{
    bool write_node_format (OutputBuffer &buffer, const bitox::dht::NodeFormat &node_format);
}

// ------------------------- Packets --------------------------------
struct PingRequestData
{
    uint64_t ping_id;
};

struct PingResponseData
{
    uint64_t ping_id;
};

struct GetNodesRequestData
{
    PublicKey client_id;
    uint64_t ping_id;
};

struct SendNodesData
{
    std::vector<dht::NodeFormat> nodes;
    uint64_t ping_id;
};

struct AnnounceRequestData
{
    OnionPingId ping_id;
    PublicKey client_id;
    PublicKey data_public_key;
    uint64_t sendback_data;
};

struct NATPingCryptoData
{
    enum class Type
    {
        NAT_PING_REQUEST = 0,
        NAT_PING_RESPONSE = 1,
    };
    
    Type type;
    uint64_t ping_id;
};

struct GetNodeHardeningCryptoData
{
    dht::NodeFormat node_to_test;
    PublicKey search_id;
};

namespace network
{
    
class PacketDecoder
{
public:
    PacketDecoder(CryptoManager &crypto_manager);
    
protected:
    bool process_incoming_packet(const IPPort &source, InputBuffer &&packet);
    
    virtual void on_ping_request (const IPPort &source, const PublicKey &sender_public_key, const PingRequestData &data) = 0;
    virtual void on_ping_response (const IPPort &source, const PublicKey &sender_public_key, const PingResponseData &data) = 0;
    virtual void on_get_nodes_request (const IPPort &source, const PublicKey &sender_public_key, const GetNodesRequestData &data) = 0;
    virtual void on_send_nodes (const IPPort &source, const PublicKey &sender_public_key, const SendNodesData &data) = 0;
    virtual void on_announce_request (const IPPort &source, const PublicKey &sender_public_key, const AnnounceRequestData &data) = 0;
    virtual void on_NAT_ping (const IPPort &source, const PublicKey &sender_public_key, const NATPingCryptoData &data) = 0;
    virtual void reroute_incoming_packet(const PublicKey &public_key, InputBuffer &packet) = 0;
    
private:
    CryptoManager &crypto_manager;
    
    bool process_incoming_ping_request_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source);
    bool process_incoming_ping_response_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source);
    bool process_get_nodes_request_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source);
    bool process_set_nodes_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source);
    bool process_announce_request_data_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source);
    bool process_NAT_ping_crypto_packet(const PublicKey &sender_public_key, InputBuffer &decrypted_buffer, const IPPort &source);
};

bool generateOutgoingPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const PingRequestData &data, OutputBuffer &out_packet);
bool generateOutgoingPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const PingResponseData &data, OutputBuffer &out_packet);
bool generateOutgoingPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const GetNodesRequestData &data, OutputBuffer &out_packet);
bool generateOutgoingPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const SendNodesData &data, OutputBuffer &out_packet);
bool generateOutgoingPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const AnnounceRequestData &data, OutputBuffer &out_packet);
bool generateOutgoingCryptoPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const NATPingCryptoData &data, OutputBuffer &out_packet);
bool generateOutgoingCryptoPacket (const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const GetNodeHardeningCryptoData &data, OutputBuffer &out_packet);
}

}
#endif
