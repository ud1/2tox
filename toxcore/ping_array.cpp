/* ping_array.c
 *
 * Implementation of an efficient array to store that we pinged something.
 *
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ping_array.hpp"
#include "crypto_core.hpp"
#include "util.hpp"

#include <cstdlib>
#include <memory>
#include <cstring>
#include <cassert>

void Ping_Array::clear_entry(uint32_t index)
{
    free(entries[index].data);
    entries[index].data = nullptr;
    entries[index].length =
        entries[index].time =
            entries[index].ping_id = 0;
}

/* Clear timed out entries.
 */
void Ping_Array::clear_timedout()
{
    while (last_deleted != last_added) {
        uint32_t index = last_deleted % entries.size();

        if (!is_timeout(entries[index].time, timeout))
            break;

        clear_entry(index);
        ++last_deleted;
    }
}

/* Add a data with length to the Ping_Array list and return a ping_id.
 *
 * return ping_id on success.
 * return 0 on failure.
 */
uint64_t Ping_Array::add(const uint8_t *data, uint32_t length)
{
    clear_timedout();
    uint32_t index = last_added % entries.size();

    if (entries[index].data != nullptr) {
        last_deleted = last_added - entries.size();
        clear_entry(index);
    }

    entries[index].data = malloc(length);

    if (entries[index].data == nullptr)
        return 0;

    memcpy(entries[index].data, data, length);
    entries[index].length = length;
    entries[index].time = unix_time();
    ++last_added;
    uint64_t ping_id = random_64b();
    ping_id /= entries.size();
    ping_id *= entries.size();
    ping_id += index;

    if (ping_id == 0)
        ping_id += entries.size();

    entries[index].ping_id = ping_id;
    return ping_id;
}


/* Check if ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * return length of data copied on success.
 * return -1 on failure.
 */
int Ping_Array::check(uint8_t *data, uint32_t length, uint64_t ping_id)
{
    if (ping_id == 0)
        return -1;

    uint32_t index = ping_id % entries.size();

    if (entries[index].ping_id != ping_id)
        return -1;

    if (is_timeout(entries[index].time, timeout))
        return -1;

    if (entries[index].length > length)
        return -1;

    if (entries[index].data == nullptr)
        return -1;

    memcpy(data, entries[index].data, entries[index].length);
    uint32_t len = entries[index].length;
    clear_entry(index);
    return len;
}

/* Initialize a Ping_Array.
 * size represents the total size of the array and should be a power of 2.
 * timeout represents the maximum timeout in seconds for the entry.
 *
 * return 0 on success.
 * return -1 on failure.
 */
Ping_Array::Ping_Array(size_t size, uint32_t timeout) : last_deleted(0), last_added(0), timeout(timeout)
{
    assert(size && "Size must be not 0");
    assert(timeout && "Timeout must be not 0");
    entries.resize(size);
}

/* Free all the allocated memory in a Ping_Array.
 */
Ping_Array::~Ping_Array()
{
    while (last_deleted != last_added) {
        uint32_t index = last_deleted % entries.size();
        clear_entry(index);
        ++last_deleted;
    }
}

