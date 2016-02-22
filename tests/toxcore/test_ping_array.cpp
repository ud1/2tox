#include <gtest/gtest.h>
#include <toxcore/ping_array.hpp>

TEST(PING_ARRAY, test)
{
	{
		Ping_Array array(2, 1000);
		
		std::string data = "Hello world!";
		std::string data2 = "Hello world2!";
		std::string data3 = "Hello world3!";
		
		uint64_t ping_id = array.add(reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
		ASSERT_NE(0, ping_id);
		
		char ret_data[100];
		
		{
			SCOPED_TRACE("too small buffer");
			int ret_len = array.check(reinterpret_cast<uint8_t *>(ret_data), 3, ping_id);
			ASSERT_EQ(-1, ret_len);
		}
		
		{
			SCOPED_TRACE("wrong ping_id");
			int ret_len = array.check(reinterpret_cast<uint8_t *>(ret_data), 100, 12345);
			ASSERT_EQ(-1, ret_len);
		}
		
		{
			SCOPED_TRACE("OK");
			int ret_len = array.check(reinterpret_cast<uint8_t *>(ret_data), 100, ping_id);
			
			ASSERT_EQ(data.length(), ret_len);
			ASSERT_EQ(data, std::string(ret_data, ret_len));
		}
		
		int ret_len = array.check(reinterpret_cast<uint8_t *>(ret_data), 100, ping_id);
		ASSERT_EQ(-1, ret_len);
		
		ping_id = array.add(reinterpret_cast<const uint8_t *>(data.c_str()), data.length());
		ASSERT_NE(0, ping_id);
		
		uint64_t ping_id2 = array.add(reinterpret_cast<const uint8_t *>(data2.c_str()), data2.length());
		ASSERT_NE(0, ping_id2);
		ASSERT_NE(ping_id, ping_id2);
		
		uint64_t ping_id3 = array.add(reinterpret_cast<const uint8_t *>(data3.c_str()), data3.length());
		ASSERT_NE(0, ping_id3);
		ASSERT_NE(ping_id2, ping_id3);
		
		{
			SCOPED_TRACE("Old record removed");
			int ret_len = array.check(reinterpret_cast<uint8_t *>(ret_data), 100, ping_id);
			
			ASSERT_EQ(-1, ret_len);
		}
		
		{
			SCOPED_TRACE("Remove second record");
			
			int ret_len = array.check(reinterpret_cast<uint8_t *>(ret_data), 100, ping_id2);
			
			ASSERT_EQ(data2.length(), ret_len);
			ASSERT_EQ(data2, std::string(ret_data, ret_len));
		}
	}
}