#include <gtest/gtest.h>
#include <toxcore/ping_array.hpp>

TEST(PING_ARRAY, test)
{
	{
		bitox::PingArray<std::string> array(2, 1000);
		
		std::string data = "Hello world!";
		std::string data2 = "Hello world2!";
		std::string data3 = "Hello world3!";
		
		uint64_t ping_id = array.add(std::string(data));
		ASSERT_NE(0, ping_id);
		
		std::string ret_data;
		
		{
			SCOPED_TRACE("wrong ping_id");
			bool res = array.check(ret_data, 12345);
			ASSERT_EQ(false, res);
		}
		
		{
			SCOPED_TRACE("OK");
			bool res = array.check(ret_data, ping_id);
			
			ASSERT_EQ(true, res);
			ASSERT_EQ(data, ret_data);
		}
		
		bool res = array.check(ret_data, ping_id);
		ASSERT_EQ(false, res);
		
		ping_id = array.add(std::string(data));
		ASSERT_NE(0, ping_id);
		
		uint64_t ping_id2 = array.add(std::string(data2));
		ASSERT_NE(0, ping_id2);
		ASSERT_NE(ping_id, ping_id2);
		
		uint64_t ping_id3 = array.add(std::string(data3));
		ASSERT_NE(0, ping_id3);
		ASSERT_NE(ping_id2, ping_id3);
		
		{
			SCOPED_TRACE("Old record removed");
			bool res = array.check(ret_data, ping_id);
			
			ASSERT_EQ(false, res);
		}
		
		{
			SCOPED_TRACE("Remove second record");
			
			bool res = array.check(ret_data, ping_id2);
			
			ASSERT_EQ(data2, ret_data);
		}
	}
}