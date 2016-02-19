#ifndef BUFFER_HPP
#define BUFFER_HPP

#include <vector>
#include <cstddef>
#include <cstdint>
#include <bitset>
#include <algorithm>

namespace bitox
{

class OutputBuffer
{
public:

    template<typename ByteIter>
    void add_bytes (ByteIter begin, ByteIter end)
    {
        buffer.insert (buffer.end(), begin, end);
    }

    size_t size() const
    {
        return buffer.size();
    }

    const uint8_t *begin() const
    {
        return buffer.data();
    }

    const uint8_t *end() const
    {
        return begin() + size();
    }

private:
    std::vector<uint8_t> buffer;
};

inline OutputBuffer &operator << (OutputBuffer &buffer, uint8_t b)
{
    buffer.add_bytes (&b, &b + 1);
    return buffer;
}

class InputBuffer
{
public:
    explicit InputBuffer (const uint8_t *buf, size_t size)
    {
        buffer.insert (buffer.end(), buf, buf + size);
    }

    template<typename ByteIter>
    void read_bytes (ByteIter *out, size_t count)
    {
        if (fail_bit || eof() || count > size())
        {
            fail_bit = true;
            return;
        }

        fail_bit = false;
        std::copy (buffer.begin() + offset, buffer.begin() + offset + count, out);
        offset += count;
    }

    size_t size() const
    {
        return buffer.size() - offset;
    }

    void reset()
    {
        fail_bit = false;
    }

    bool eof() const
    {
        return !size();
    }

    bool fail() const
    {
        return fail_bit;
    }

private:
    std::vector<uint8_t> buffer;
    size_t offset = 0;

    bool fail_bit = false;
};

inline InputBuffer &operator >> (InputBuffer &buffer, uint8_t &b)
{
    buffer.read_bytes (&b, 1);
    return buffer;
}

}

#endif
