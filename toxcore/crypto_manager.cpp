#include "protocol_impl.hpp"
#include "crypto_core.hpp"
#include <cassert>

#include "util.hpp"

namespace
{
    
/* struct to store some shared keys so we don't have to regenerate them for each request. */
constexpr unsigned MAX_KEYS_PER_SLOT = 4;
constexpr unsigned KEYS_TIMEOUT = 600;
struct Shared_Keys
{
    struct
    {
        bitox::PublicKey public_key;
        bitox::SharedKey shared_key;
        uint32_t times_requested = 0;
        bool stored = false; /* 0 if not, 1 if is */
        uint64_t time_last_requested = 0;
    } keys[256 * MAX_KEYS_PER_SLOT];
    
    void get_shared_key (bitox::SharedKey &out_shared_key, const bitox::SecretKey &secret_key, const bitox::PublicKey &public_key)
    {
        uint32_t i, num = ~0, curr = 0;

        for (i = 0; i < MAX_KEYS_PER_SLOT; ++i)
        {
            int index = public_key.data[30] * MAX_KEYS_PER_SLOT + i;

            if (keys[index].stored)
            {
                if (public_key == keys[index].public_key)
                {
                    out_shared_key = keys[index].shared_key;
                    ++keys[index].times_requested;
                    keys[index].time_last_requested = unix_time();
                    return;
                }

                if (num != 0)
                {
                    if (is_timeout (keys[index].time_last_requested, KEYS_TIMEOUT))
                    {
                        num = 0;
                        curr = index;
                    }
                    else if (num > keys[index].times_requested)
                    {
                        num = keys[index].times_requested;
                        curr = index;
                    }
                }
            }
            else
            {
                if (num != 0)
                {
                    num = 0;
                    curr = index;
                }
            }
        }

        encrypt_precompute (public_key, secret_key, out_shared_key.data.data());

        if (num != (uint32_t) ~0)
        {
            keys[curr].stored = true;
            keys[curr].times_requested = 1;
            keys[curr].public_key = public_key;
            keys[curr].shared_key = out_shared_key;
            keys[curr].time_last_requested = unix_time();
        }
    }
};

}

namespace bitox
{
using namespace bitox::impl;

class CryptoManager::CryptoManagerImpl
{
public:
    CryptoManagerImpl (const SecretKey &secret_key, const PublicKey &self_public_key) :
        secret_key (secret_key), self_public_key (self_public_key)
    {

    }

    bool encrypt_buffer (const BufferDataRange &data_to_encrypt, const PublicKey &recipient_public_key, const Nonce &nonce, Buffer &out_encrypted_data) const
    {
        assert ( (data_to_encrypt.second > data_to_encrypt.first) && "Data range to encrypt must not be empty or negative");

        size_t length = data_to_encrypt.second - data_to_encrypt.first;
        out_encrypted_data.resize (length + MAC_BYTES_LEN);

        SharedKey shared_key = get_shared_key (recipient_public_key);
        return encrypt_data_symmetric (shared_key.data.data(), nonce.data.data(), data_to_encrypt.first, length, out_encrypted_data.data()) > 0;
    }

    bool decrypt_buffer (const BufferDataRange &data_to_decrypt, const PublicKey &sender_public_key, const Nonce &nonce, Buffer &out_decrypted_data) const
    {
        assert ( (data_to_decrypt.second > data_to_decrypt.first + MAC_BYTES_LEN) && "Data range to decrypt must not be empty or negative");

        size_t length = data_to_decrypt.second - data_to_decrypt.first;
        out_decrypted_data.resize (length - MAC_BYTES_LEN);

        SharedKey shared_key = get_shared_key (sender_public_key);
        return decrypt_data_symmetric (shared_key.data.data(), nonce.data.data(), data_to_decrypt.first, length, out_decrypted_data.data()) > 0;
    }

    const PublicKey &get_self_public_key() const
    {
        return self_public_key;
    }

    const SharedKey get_shared_key (const PublicKey &recipient_public_key) const
    {
        SharedKey result;
        shared_key_cache.get_shared_key(result, secret_key, recipient_public_key);
        return result;
    }

private:
    SecretKey secret_key;
    PublicKey self_public_key;
    mutable Shared_Keys shared_key_cache;
};


CryptoManager::CryptoManager (const SecretKey &secret_key, const PublicKey &self_public_key) : pimpl (new CryptoManagerImpl (secret_key, self_public_key)) {}
CryptoManager::~CryptoManager() {}

bool CryptoManager::encrypt_buffer (const BufferDataRange &data_to_encrypt, const PublicKey &recipient_public_key, const Nonce &nonce, Buffer &out_encrypted_data) const
{
    return pimpl->encrypt_buffer (data_to_encrypt, recipient_public_key, nonce, out_encrypted_data);
}

bool CryptoManager::decrypt_buffer (const BufferDataRange &data_to_decrypt, const PublicKey &sender_public_key, const Nonce &nonce, Buffer &out_decrypted_data) const
{
    return pimpl->decrypt_buffer (data_to_decrypt, sender_public_key, nonce, out_decrypted_data);
}

const PublicKey &CryptoManager::get_self_public_key() const
{
    return pimpl->get_self_public_key();
}

}