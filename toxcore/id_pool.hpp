#ifndef ID_POOL_HPP
#define ID_POOL_HPP

#include <cstdint>
#include <vector>

class IDPool
{
public:
    uint32_t next()
    {
        if (free_ids.empty())
            return sequence++;
        
        uint32_t res = free_ids[free_ids.size() - 1];
        free_ids.pop_back();
        return res;
    }
    
    void release(uint32_t id)
    {
        free_ids.push_back(id);
    }
    
private:
    uint32_t sequence = 0;
    std::vector<uint32_t> free_ids;
};

#endif
