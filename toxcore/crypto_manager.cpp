#include "protocol_impl.hpp"
#include "crypto_core.hpp"
#include <cassert>

namespace bitox
{
    using namespace bitox::impl;
    
    class CryptoManager::CryptoManagerImpl
    {
    public:
        CryptoManagerImpl(const SecretKey &secret_key, const PublicKey &self_public_key) :
            secret_key(secret_key), self_public_key(self_public_key)
        {
            
        }
        
        bool encrypt_buffer(const BufferDataRange &data_to_encrypt, const PublicKey &recipient_public_key, const Nonce &nonce, Buffer &out_encrypted_data) const
        {
            assert((data_to_encrypt.second > data_to_encrypt.first) && "Data range to encrypt must not be empty or negative");
            
            size_t length = data_to_encrypt.second - data_to_encrypt.first;
            out_encrypted_data.resize(length + MAC_BYTES_LEN);
            
            SharedKey shared_key = get_shared_key(recipient_public_key);
            return encrypt_data_symmetric(shared_key.data.data(), nonce.data.data(), data_to_encrypt.first, length, out_encrypted_data.data()) > 0;
        }
        
        bool decrypt_buffer(const BufferDataRange &data_to_decrypt, const PublicKey &sender_public_key, const Nonce &nonce, Buffer &out_decrypted_data) const
        {
            assert((data_to_decrypt.second > data_to_decrypt.first + MAC_BYTES_LEN) && "Data range to decrypt must not be empty or negative");
            
            size_t length = data_to_decrypt.second - data_to_decrypt.first;
            out_decrypted_data.resize(length - MAC_BYTES_LEN);
            
            SharedKey shared_key = get_shared_key(sender_public_key);
            return decrypt_data_symmetric(shared_key.data.data(), nonce.data.data(), data_to_decrypt.first, length, out_decrypted_data.data()) > 0;
        }
        
        const PublicKey &get_self_public_key() const
        {
            return self_public_key;
        }
        
        const SharedKey get_shared_key(const PublicKey &recipient_public_key) const
        {
            // TODO cache results
            SharedKey result;
            encrypt_precompute (recipient_public_key.data.data(), secret_key.data.data(), result.data.data());
            return result;
        }
        
    private:
        SecretKey secret_key;
        PublicKey self_public_key;
    };
    
    
    CryptoManager::CryptoManager(const SecretKey &secret_key, const PublicKey &self_public_key) : pimpl(new CryptoManagerImpl(secret_key, self_public_key)) {}
    
    bool CryptoManager::encrypt_buffer(const BufferDataRange &data_to_encrypt, const PublicKey &recipient_public_key, const Nonce &nonce, Buffer &out_encrypted_data) const
    {
        return pimpl->encrypt_buffer(data_to_encrypt, recipient_public_key, nonce, out_encrypted_data);
    }
    
    bool CryptoManager::decrypt_buffer(const BufferDataRange &data_to_decrypt, const PublicKey &sender_public_key, const Nonce &nonce, Buffer &out_decrypted_data) const
    {
        return pimpl->decrypt_buffer(data_to_decrypt, sender_public_key, nonce, out_decrypted_data);
    }
    
    const PublicKey &CryptoManager::get_self_public_key() const
    {
        return pimpl->get_self_public_key();
    }
    
}