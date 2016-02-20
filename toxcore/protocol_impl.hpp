#ifndef PROTOCOL_IMPL_HPP
#define PROTOCOL_IMPL_HPP

#include "protocol.hpp"

namespace bitox
{
namespace impl
{

constexpr size_t SHARED_KEY_LEN = 32;
constexpr size_t MAC_BYTES_LEN = 16;

struct const_uint64_adapter
{
    const_uint64_adapter(const uint64_t &value) : value(value) {}
    const uint64_t &value;
};

struct uint64_adapter
{
    uint64_adapter(uint64_t &value) : value(value) {}
    uint64_t &value;
};

inline OutputBuffer &operator << (OutputBuffer &buffer, const const_uint64_adapter &val)
{
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(&val.value);
    buffer.write_bytes (ptr, ptr + sizeof(uint64_t));
    return buffer;
}

inline InputBuffer &operator >> (InputBuffer &buffer, uint64_adapter val)
{
    uint8_t *ptr = reinterpret_cast<uint8_t *>(&val.value);
    buffer.read_bytes(ptr, sizeof(uint64_t));
    return buffer;
}


template<size_t N>
OutputBuffer &operator << (OutputBuffer &buffer, const std::array<uint8_t, N> arr)
{
    buffer.write_bytes (arr.begin(), arr.end());
    return buffer;
}

template<size_t N>
inline InputBuffer &operator >> (InputBuffer &buffer, std::array<uint8_t, N> &arr)
{
    buffer.read_bytes (arr.data(), N);
    return buffer;
}

inline OutputBuffer &operator << (OutputBuffer &buffer, const Buffer &arr)
{
    if (!arr.empty())
        buffer.write_bytes (arr.begin(), arr.end());
    
    return buffer;
}

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
    
inline OutputBuffer &operator << (OutputBuffer &buffer, const PublicKey &public_key)
{
    return buffer << public_key.data;
}

inline InputBuffer &operator >> (InputBuffer &buffer, PublicKey &public_key)
{
    return buffer >> public_key.data;
}

inline OutputBuffer &operator << (OutputBuffer &buffer, const Nonce &nonce)
{
    return buffer << nonce.data;
}

inline InputBuffer &operator >> (InputBuffer &buffer, Nonce &nonce)
{
    return buffer >> nonce.data;
}

struct SharedKey
{
    std::array<uint8_t, SHARED_KEY_LEN> data = {};
};

struct ToxHeader
{
    PacketType packet_type;
    PublicKey public_key;
    Nonce nonce = Nonce::create_empty();
};

inline InputBuffer &operator >> (InputBuffer &buffer, ToxHeader &header)
{
    buffer >> header.packet_type >> header.public_key >> header.nonce;
    return buffer;
}


    
}
}

#endif