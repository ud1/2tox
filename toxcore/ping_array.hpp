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

#include <vector>

struct Ping_Array
{
    explicit Ping_Array (size_t size, uint32_t timeout);
    ~Ping_Array();

    /* Add a data with length to the Ping_Array list and return a ping_id.
    *
    * return ping_id on success.
    * return 0 on failure.
    */
    uint64_t add (const uint8_t *data, uint32_t length);
    
    /* Check if ping_id is valid and not timed out.
    *
    * On success, copies the data into data of length,
    *
    * return length of data copied on success.
    * return -1 on failure.
    */
    int check (uint8_t *data, uint32_t length, uint64_t ping_id);

private:
    void clear_entry(uint32_t index);
    void clear_timedout();
    
    struct Ping_Array_Entry
    {
        void *data = nullptr;
        uint32_t length = 0;
        uint64_t time = 0;
        uint64_t ping_id = 0;
    };

    std::vector<Ping_Array_Entry> entries;
    uint32_t last_deleted; /* number representing the next entry to be deleted. */
    uint32_t last_added; /* number representing the last entry to be added. */
    uint32_t timeout; /* The timeout after which entries are cleared. */
};

#endif
