/* ping_array.h
 *
 * Implementation of an efficient array to store that we pinged something.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef PING_ARRAY_H
#define PING_ARRAY_H

#include "network.hpp"
#include "util.hpp"
#include "crypto_core.hpp"
#include <cstdlib>

#include <vector>

namespace bitox
{
    template<typename Data>
    struct PingArray
    {
        PingArray(size_t size, uint32_t timeout) : last_deleted(0), last_added(0), timeout(timeout)
        {
            assert(size && "Size must be not 0");
            assert(timeout && "Timeout must be not 0");
            entries.resize(size);
        }
        
        uint64_t add(Data &&data)
        {
            clear_timedout();
            uint32_t index = last_added % entries.size();

            if (entries[index].has_value)
            {
                last_deleted = last_added - entries.size();
                clear_entry(index);
            }

            PingArrayEntry &entry = entries[index];
            entry.data = std::move(data);
            entry.time = unix_time();
            ++last_added;
            uint64_t ping_id = random_64b();
            ping_id /= entries.size();
            ping_id *= entries.size();
            ping_id += index;

            if (ping_id == 0)
                ping_id += entries.size();

            entry.ping_id = ping_id;
            entry.has_value = true;
            return ping_id;
        }
        
        bool check(Data &data, uint64_t ping_id)
        {
            Data *result = peek(ping_id);
            if (!result)
                return false;
            
            uint32_t index = ping_id % entries.size();

            data = std::move(entries[index].data);
            clear_entry(index);
            return true;
        }
        
        Data *peek(uint64_t ping_id)
        {
            if (ping_id == 0)
                return nullptr;

            uint32_t index = ping_id % entries.size();

            if (entries[index].ping_id != ping_id)
                return nullptr;

            if (is_timeout(entries[index].time, timeout))
                return nullptr;

            return &entries[index].data;
        }
        
    private:
        void clear_entry(uint32_t index)
        {
            entries[index] = PingArrayEntry();
        }
        
        void clear_timedout()
        {
            while (last_deleted != last_added) {
                uint32_t index = last_deleted % entries.size();

                if (!is_timeout(entries[index].time, timeout))
                    break;

                clear_entry(index);
                ++last_deleted;
            }
        }
        
        struct PingArrayEntry
        {
            Data data;
            uint64_t time = 0;
            uint64_t ping_id = 0;
            bool has_value = false;
        };
        
        std::vector<PingArrayEntry> entries;
        uint32_t last_deleted; /* number representing the next entry to be deleted. */
        uint32_t last_added; /* number representing the last entry to be added. */
        uint32_t timeout; /* The timeout after which entries are cleared. */
    };
}

#endif
