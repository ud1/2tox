#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <array>
#include "buffer.hpp"

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

inline OutputBuffer &operator << (OutputBuffer &buffer, const PacketType packet_type)
{
    buffer.write_byte(packet_type);
    return buffer;
}

inline InputBuffer &operator >> (InputBuffer &buffer, PacketType &packet_type)
{
    uint8_t b;
    buffer.read_byte (b);
    packet_type = (PacketType) b;
    return buffer;
}

constexpr size_t PUBLIC_KEY_LEN = 32;
constexpr size_t SHARED_KEY_LEN = 32;
constexpr size_t NONCE_LEN = 24;

// ----- PublicKey
struct PublicKey
{
    std::array<uint8_t, PUBLIC_KEY_LEN> data = {};
};

inline OutputBuffer &operator << (OutputBuffer &buffer, const PublicKey &public_key)
{
    buffer.write_bytes (public_key.data.begin(), public_key.data.end());
    return buffer;
}

inline InputBuffer &operator >> (InputBuffer &buffer, PublicKey &public_key)
{
    buffer.read_bytes (public_key.data.begin(), public_key.data.size());
    return buffer;
}

// ----- Nonce
struct Nonce
{
    std::array<uint8_t, NONCE_LEN> data = {};
};

inline OutputBuffer &operator << (OutputBuffer &buffer, const Nonce &nonce)
{
    buffer.write_bytes (nonce.data.begin(), nonce.data.end());
    return buffer;
}

inline InputBuffer &operator >> (InputBuffer &buffer, Nonce &nonce)
{
    buffer.read_bytes (nonce.data.begin(), nonce.data.size());
    return buffer;
}

// ----- SharedKey

struct SharedKey
{
    std::array<uint8_t, SHARED_KEY_LEN> data = {};
};

// ----- ToxHeader

struct ToxHeader
{
    PacketType packet_type;
    PublicKey public_key;
    Nonce nonce;
};

inline OutputBuffer &operator << (OutputBuffer &buffer, const ToxHeader &header)
{
    buffer << header.packet_type << header.public_key << header.nonce;
    return buffer;
}

inline InputBuffer &operator >> (InputBuffer &buffer, ToxHeader &header)
{
    buffer >> header.packet_type >> header.public_key >> header.nonce;
    return buffer;
}

}
#endif
