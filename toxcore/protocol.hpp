#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <array>
#include <memory>

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

constexpr size_t PUBLIC_KEY_LEN = 32;
constexpr size_t SECRET_KEY_LEN = 32;
constexpr size_t NONCE_LEN = 24;

struct PublicKey
{
    std::array<uint8_t, PUBLIC_KEY_LEN> data = {};
};

struct Nonce
{
    std::array<uint8_t, NONCE_LEN> data;
    
    static Nonce create_empty();
    static Nonce create_random();
private:
    Nonce() {}
};

struct SecretKey
{
    std::array<uint8_t, SECRET_KEY_LEN> data = {};
};

class CryptoManager
{
public:
    CryptoManager(const SecretKey &secret_key, const PublicKey &self_public_key);
    bool encrypt_buffer(const BufferDataRange &data_to_encrypt, const PublicKey &recipient_public_key, const Nonce &nonce, Buffer &out_encrypted_data) const;
    bool decrypt_buffer(const BufferDataRange &data_to_decrypt, const PublicKey &sender_public_key, const Nonce &nonce, Buffer &out_decrypted_data) const;
    const PublicKey &get_self_public_key() const;
    
private:
    class CryptoManagerImpl;
    std::unique_ptr<CryptoManagerImpl> pimpl;
};


// ------------------------- Packets --------------------------------
struct PingRequestData
{
    uint64_t ping_id;
};

class IncomingPacketListener
{
public:
    virtual void onPingRequest(const PublicKey &sender_public_key, const PingRequestData &data) = 0;
};


bool generateOutgoingPacket(const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const PingRequestData &data, OutputBuffer &out_packet);
bool processIncomingPacket(const CryptoManager &crypto_manager, InputBuffer &packet, IncomingPacketListener &listener);

}
#endif
