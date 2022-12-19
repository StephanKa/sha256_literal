#pragma once

#include <cstdint>
#include <cstring>
#include <type_traits>

namespace intmem {

// bswap functions. Uses GCC/clang/MSVC intrinsics.
#ifdef _MSC_VER
#include <stdlib.h>
static uint8_t bswap(uint8_t v) { return v; }
static uint16_t bswap(unsigned short v) { return _byteswap_ushort(v); }
static_assert(sizeof(uint32_t) == sizeof(unsigned long), "unsigned long isn't 32-bit wide!");
static uint32_t bswap(uint32_t v) { return _byteswap_ulong(v); }
static uint64_t bswap(uint64_t v) { return _byteswap_uint64(v); }
#else
[[maybe_unused]] static uint8_t bswap(uint8_t v) { return v; }
[[maybe_unused]] static uint16_t bswap(uint16_t v) { return __builtin_bswap16(v); }
[[maybe_unused]] static uint32_t bswap(uint32_t v) { return __builtin_bswap32(v); }
[[maybe_unused]] static uint64_t bswap(uint64_t v) { return __builtin_bswap64(v); }
#endif

[[maybe_unused]] static int8_t bswap(int8_t v) { return v; }
[[maybe_unused]] static int16_t bswap(int16_t v) { return static_cast<int16_t>(bswap(static_cast<uint16_t>(v))); }
[[maybe_unused]] static int32_t bswap(int32_t v) { return static_cast<int32_t>(bswap(static_cast<uint32_t>(v))); }
[[maybe_unused]] static int64_t bswap(int64_t v) { return static_cast<int64_t>(bswap(static_cast<uint64_t>(v))); }

template<class T> static T loadu(const void* ptr)
{
    static_assert(std::is_integral<T>::value, "T must be an integer!");
    T ret;
    memcpy(&ret, ptr, sizeof(T));
    return ret;
}

template<class T> static void storeu(void* ptr, T const v)
{
    static_assert(std::is_integral<T>::value, "T must be an integer!");
    memcpy(ptr, &v, sizeof(v));
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
template<class T> static T bswapLe(T const v) { return v; }

template<class T> static T bswapBe(T const v) { return bswap(v); }
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
template<class T> static T bswap_le(T const v) { return bswap(v); }

template<class T> static T bswap_be(T const v) { return v; }
#else
#error Unsupported endianess!
#endif

template<class T> static T loaduLe(const void* ptr) { return bswapLe(loadu<T>(ptr)); }

template<class T> static T loaduBe(const void* ptr) { return bswapBe(loadu<T>(ptr)); }

template<class T> static void storeuLe(void* ptr, T const v) { storeu(ptr, bswapLe(v)); }

template<class T> static void storeuBe(void* ptr, T const v) { storeu(ptr, bswapBe(v)); }

template<class T> static T loadLe(const T* ptr) { return bswapLe(*ptr); }

template<class T> static T loadBe(const T* ptr) { return bswapBe(*ptr); }

template<class T> static void storeLe(T* ptr, T const v) { *ptr = bswapLe(v); }

template<class T> static void storeBe(T* ptr, T const v) { *ptr = bswapBe(v); }

}  // namespace intmem
