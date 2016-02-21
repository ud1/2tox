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

struct const_uint16_adapter
{
    const_uint16_adapter(const uint16_t &value) : value(value) {}
    const uint16_t &value;
};

struct uint16_adapter
{
    uint16_adapter(uint16_t &value) : value(value) {}
    uint16_t &value;
};

inline OutputBuffer &operator << (OutputBuffer &buffer, const_uint64_adapter val)
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

inline OutputBuffer &operator << (OutputBuffer &buffer, const_uint16_adapter val)
{
    const uint8_t *ptr = reinterpret_cast<const uint8_t *>(&val.value);
    buffer.write_bytes (ptr, ptr + sizeof(uint16_t));
    return buffer;
}

inline InputBuffer &operator >> (InputBuffer &buffer, uint16_adapter val)
{
    uint8_t *ptr = reinterpret_cast<uint8_t *>(&val.value);
    buffer.read_bytes(ptr, sizeof(uint16_t));
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

namespace network
{
    
enum ToxFamily : uint8_t
{
    TOX_FAMILY_NULL = 0,
    TOX_AF_INET = 2,
    TOX_AF_INET6 = 10,
    TOX_TCP_INET = 130,
    TOX_TCP_INET6 = 138
};
    
inline ToxFamily to_tox_family(bitox::network::Family family)
{
    using namespace bitox::network;
    
    switch(family)
    {
        case Family::FAMILY_AF_INET:
            return TOX_AF_INET;
        case Family::FAMILY_AF_INET6:
            return TOX_AF_INET6;
        case Family::FAMILY_TCP_INET:
            return TOX_TCP_INET;
        case Family::FAMILY_TCP_INET6:
            return TOX_TCP_INET6;
        default:
            return TOX_FAMILY_NULL;
    }
}

inline bitox::network::Family from_tox_family(ToxFamily family)
{
    using namespace bitox::network;
    
    switch(family)
    {
        case TOX_AF_INET:
            return Family::FAMILY_AF_INET;
        case TOX_AF_INET6:
            return Family::FAMILY_AF_INET6;
        case TOX_TCP_INET:
            return Family::FAMILY_TCP_INET;
        case TOX_TCP_INET6:
            return Family::FAMILY_TCP_INET6;
        default:
            return Family::FAMILY_NULL;
    }
}

}
}
}

#endif