#include <gtest/gtest.h>
#include <toxcore/protocol_impl.hpp>

#include <algorithm>

using namespace bitox::impl;

TEST (buffer, test_pub_key_and_nonce)
{
    {
        SCOPED_TRACE ("Public key to bytes");

        bitox::OutputBuffer output_buffer;
        bitox::PublicKey public_key;
        bitox::Nonce nonce = bitox::Nonce::create_empty();

        uint8_t num = 0;
        std::generate (public_key.data.begin(), public_key.data.end(), [&num]()
        {
            return num++;
        });

        num = 100;
        std::generate (nonce.data.begin(), nonce.data.end(), [&num]()
        {
            return num++;
        });

        output_buffer << public_key << nonce;
        ASSERT_EQ (32 + 24, output_buffer.size());

        for (uint8_t i = 0; i < 32; ++i)
        {
            ASSERT_EQ (i, * (output_buffer.begin() + i));
        }

        for (uint8_t i = 0; i < 24; ++i)
        {
            ASSERT_EQ (100 + i, * (output_buffer.begin() + i + 32));
        }

        bitox::InputBuffer input_buffer (output_buffer.begin(), output_buffer.size());
        bitox::PublicKey public_key2;
        bitox::Nonce nonce2 = bitox::Nonce::create_empty();

        input_buffer >> public_key2 >> nonce2;
        ASSERT_FALSE (input_buffer.fail());

        bitox::PacketType b;
        input_buffer >> b;
        ASSERT_TRUE (input_buffer.fail());
        ASSERT_TRUE (input_buffer.eof());

        for (uint8_t i = 0; i < 32; ++i)
        {
            ASSERT_EQ (i, * (public_key2.data.begin() + i));
        }

        for (uint8_t i = 0; i < 24; ++i)
        {
            ASSERT_EQ (100 + i, * (nonce2.data.begin() + i));
        }
    }
}

TEST (pub_key_and_nonce, test_is_zero_initialized)
{
    {
        SCOPED_TRACE ("Public key and nonce are zero initialized");
        bitox::PublicKey public_key;
        bitox::Nonce nonce = bitox::Nonce::create_empty();

        for (uint8_t i = 0; i < 32; ++i)
        {
            ASSERT_EQ (0, * (public_key.data.begin() + i));
        }

        for (uint8_t i = 0; i < 24; ++i)
        {
            ASSERT_EQ (0, * (nonce.data.begin() + i));
        }
    }
}

