#include "protocol_impl.hpp"

#include <algorithm>
#include <sodium.h>

namespace bitox
{
using namespace bitox::impl;

static_assert(PUBLIC_KEY_LEN == crypto_box_BEFORENMBYTES,  "Wrong PUBLIC_KEY_LEN constant value");
static_assert(SHARED_KEY_LEN == crypto_box_BEFORENMBYTES,  "Wrong SHARED_KEY_LEN constant value");
static_assert(SECRET_KEY_LEN == crypto_box_SECRETKEYBYTES, "Wrong SECRET_KEY_LEN constant value");
static_assert(NONCE_LEN      == crypto_box_NONCEBYTES,     "Wrong NONCE_LEN constant value");
static_assert(MAC_BYTES_LEN  == crypto_box_MACBYTES,       "Wrong MAC_BYTES_LEN constant value");

    
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
    
bool generateOutgoingPacket(const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const PingRequestData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << NET_PACKET_PING_REQUEST << const_uint64_adapter(data.ping_id);
    
    return generateOutgoingPacket(crypto_manager, NET_PACKET_PING_REQUEST, data_to_encrypt, recipient_public_key, out_packet);
}

bool generateOutgoingPacket(const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const PingResponseData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << NET_PACKET_PING_RESPONSE << const_uint64_adapter(data.ping_id);
    
    return generateOutgoingPacket(crypto_manager, NET_PACKET_PING_RESPONSE, data_to_encrypt, recipient_public_key, out_packet);
}

bool generateOutgoingPacket(const CryptoManager &crypto_manager, const PublicKey &recipient_public_key, const GetNodesRequestData &data, OutputBuffer &out_packet)
{
    OutputBuffer data_to_encrypt;
    data_to_encrypt << data.client_id << const_uint64_adapter(data.ping_id);
    
    return generateOutgoingPacket(crypto_manager, NET_PACKET_GET_NODES, data_to_encrypt, recipient_public_key, out_packet);
}

static bool processIncomingPingRequestDataPacket(const ToxHeader header, InputBuffer &decrypted_buffer, IncomingPacketListener &listener)
{
    PacketType packet_type;
    PingRequestData ping_request;
    
    if ((decrypted_buffer >> packet_type >> uint64_adapter(ping_request.ping_id)).fail())
        return false;
    
    if (packet_type != NET_PACKET_PING_REQUEST)
        return false;
    
    listener.onPingRequest(header.public_key, ping_request);
}

static bool processIncomingPingResponseDataPacket(const ToxHeader header, InputBuffer &decrypted_buffer, IncomingPacketListener &listener)
{
    PacketType packet_type;
    PingResponseData ping_response;
    
    if ((decrypted_buffer >> packet_type >> uint64_adapter(ping_response.ping_id)).fail())
        return false;
    
    if (packet_type != NET_PACKET_PING_RESPONSE)
        return false;
    
    listener.onPingResponse(header.public_key, ping_response);
}

static bool processGetNodesRequestDataPacket(const ToxHeader header, InputBuffer &decrypted_buffer, IncomingPacketListener &listener)
{
    GetNodesRequestData get_nodes_request;
    
    if ((decrypted_buffer >> get_nodes_request.client_id >> uint64_adapter(get_nodes_request.ping_id)).fail())
        return false;
       
    listener.onGetNodesRequest(header.public_key, get_nodes_request);
}

bool processIncomingPacket(const CryptoManager &crypto_manager, InputBuffer &packet, IncomingPacketListener &listener)
{
    ToxHeader header;
    if ((packet >> header).fail())
        return false;
    
    Buffer decrypted_data;
    if (!crypto_manager.decrypt_buffer(packet.get_buffer_data(), header.public_key, header.nonce, decrypted_data))
        return false;
    
    InputBuffer decrypted_buffer = InputBuffer(std::move(decrypted_data));
    
    switch(header.packet_type)
    {
        case NET_PACKET_PING_REQUEST:
            return processIncomingPingRequestDataPacket(header, decrypted_buffer, listener);
            
        case NET_PACKET_PING_RESPONSE:
            return processIncomingPingResponseDataPacket(header, decrypted_buffer, listener);
            
        case NET_PACKET_GET_NODES:
            return processGetNodesRequestDataPacket(header, decrypted_buffer, listener);
    }
    
    return false;
}

}