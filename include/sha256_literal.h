#pragma once
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace sha256_literal {

static constexpr uint32_t SHA256_K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                                          0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                                          0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                                          0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                          0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                                          0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

using StateType = std::array<uint32_t, 8>;
using BlockType = std::array<uint32_t, 16>;
using WType = std::array<uint32_t, 64>;
using HashType = std::array<uint8_t, sizeof(StateType)>;

namespace details {

template<class F, class T, size_t N, class... Args> static constexpr auto mapZip(F const f, std::array<T, N> const data, Args const... arrays)
{
    std::array<decltype(f(data[0], arrays[0]...)), N> out = {0};
    auto* itOut = &std::get<0>(out);
    for (size_t i = 0; i < N; ++i)
        itOut[i] = f(data[i], arrays[i]...);
    return out;
}

template<class F, class T, size_t N, class... Args> static constexpr auto map(F const f, std::array<T, N> const data, Args const... args)
{
    using RetType = decltype(f(std::declval<T>(), args...));
    std::array<RetType, N> out = {0};
    auto* itOut = &std::get<0>(out);
    for (size_t i = 0; i < N; ++i)
        itOut[i] = f(data[i], args...);
    return out;
}

template<class F, class T, class... Args> static constexpr auto map(F const f, std::array<T, 0> const, Args const... args)
{
    using RetType = decltype(f(std::declval<T>(), args...));
    return std::array<RetType, 0>{};
}

// BlockType constexpr helpers

static constexpr uint32_t xorImpl(uint32_t a, uint32_t b) { return a ^ b; }
[[maybe_unused]] static constexpr BlockType blocktypeXor(BlockType const A, uint8_t const B)
{
    const uint32_t B32 = static_cast<uint32_t>(B);
    const uint32_t B32X4 = B32 | (B32 << 8) | (B32 << 16) | (B32 << 24);
    return map(xorImpl, A, B32X4);
}

static constexpr uint32_t u8x4ToBeU32(uint8_t const a, uint8_t const b, uint8_t const c, uint8_t const d)
{
    return (static_cast<uint32_t>(d)) | ((static_cast<uint32_t>(c)) << 8) | ((static_cast<uint32_t>(b)) << 16) | ((static_cast<uint32_t>(a)) << 24);
}

// SHA256 routines
// Based on code from https://github.com/thomdixon/pysha2/blob/master/sha2/sha256.py

static constexpr uint32_t rotr(uint32_t const v, int off) { return (v >> off) | (v << (32 - off)); }

static constexpr uint32_t sum(uint32_t const a, uint32_t const b) { return a + b; }

static constexpr StateType transform(StateType const s, BlockType const data)
{
    WType w = {0};
    auto* itW = &std::get<0>(w);
    auto const* cItW = &std::get<0>(w);
    for (size_t i = 0; i < data.size(); ++i)
    {
        itW[i] = data[i];
    }

    for (size_t i = 16; i < 64; ++i)
    {
        const uint32_t S0 = rotr(cItW[i - 15], 7) ^ rotr(cItW[i - 15], 18) ^ (cItW[i - 15] >> 3);
        const uint32_t S1 = rotr(cItW[i - 2], 17) ^ rotr(cItW[i - 2], 19) ^ (cItW[i - 2] >> 10);
        itW[i] = (cItW[i - 16] + S0 + cItW[i - 7] + S1);
    }

    StateType inS = s;
    auto const* cInS = &std::get<0>(inS);
    for (size_t i = 0; i < 64; ++i)
    {
        const uint32_t S0 = rotr(cInS[0], 2) ^ rotr(cInS[0], 13) ^ rotr(cInS[0], 22);
        const uint32_t MAJ = (cInS[0] & cInS[1]) ^ (cInS[0] & cInS[2]) ^ (cInS[1] & cInS[2]);
        const uint32_t T2 = S0 + MAJ;
        const uint32_t S1 = rotr(cInS[4], 6) ^ rotr(cInS[4], 11) ^ rotr(cInS[4], 25);
        const uint32_t CH = (cInS[4] & cInS[5]) ^ ((~cInS[4]) & cInS[6]);
        const uint32_t T1 = cInS[7] + S1 + CH + SHA256_K[i] + cItW[i];

        inS = {T1 + T2, cInS[0], cInS[1], cInS[2], cInS[3] + T1, cInS[4], cInS[5], cInS[6]};
    }

    return mapZip(sum, s, inS);
}

static auto constexpr u8ToBlock(uint8_t const* it)
{
    BlockType b = {0};
    auto* itB = &std::get<0>(b);
    for (size_t i = 0; i < std::tuple_size<BlockType>(); i++)
    {
        itB[i] = u8x4ToBeU32(it[i * sizeof(uint32_t)], it[i * sizeof(uint32_t) + 1], it[i * sizeof(uint32_t) + 2], it[i * sizeof(uint32_t) + 3]);
    }
    return b;
}

template<uint64_t BlockCount, typename Ar> [[maybe_unused]] constexpr std::enable_if_t<BlockCount != 0, std::array<BlockType, BlockCount>> u8ToBlocks_(Ar const data)
{
    std::array<BlockType, BlockCount> ret = {{0}};
    auto* itRet = &std::get<0>(ret);
    for (uint64_t i = 0; i < BlockCount; ++i)
    {
        itRet[i] = u8_to_block(&data[i * sizeof(BlockType)]);
    }
    return ret;
}

template<uint64_t BlockCount, typename Ar> [[maybe_unused]] constexpr std::enable_if_t<BlockCount == 0, std::array<BlockType, 0>> u8ToBlocks_(Ar const __attribute__((unused)) data)
{
    return std::array<BlockType, 0>{};
}

template<size_t Len_> [[maybe_unused]] constexpr auto u8ToBlocks(std::array<uint8_t, Len_> const data)
{
    constexpr uint64_t LEN = Len_;
    constexpr uint64_t BLOCK_COUNT = LEN / sizeof(BlockType);
    return u8ToBlocks_<BLOCK_COUNT>(data);
}

static constexpr HashType stateToHash(StateType const s)
{
    HashType ret = {0};
    auto* itRet = &std::get<0>(ret);
    for (size_t i = 0; i < std::tuple_size<StateType>(); ++i)
    {
        uint32_t const V = s[i];
        itRet[i * sizeof(uint32_t)] = static_cast<uint8_t>(V >> 24u) & 0xff;
        itRet[i * sizeof(uint32_t) + 1] = (V >> 16u) & 0xff;
        itRet[i * sizeof(uint32_t) + 2] = (V >> 8u) & 0xff;
        itRet[i * sizeof(uint32_t) + 3] = (V) &0xff;
    }
    return ret;
}

template<class InputIt, class OutputIt> static constexpr OutputIt constexprCopy(InputIt first, InputIt last, OutputIt dFirst)
{
    for (; first != last; ++first)
    {
        *dFirst = *first;
        ++dFirst;
    }
    return dFirst;
}

template<class T, size_t N> constexpr auto* getArrayIt(std::array<T, N> const& data) { return &std::get<0>(data); }

template<class T> constexpr T* getArrayIt(std::array<T, 0> const&)
{
    // Do not use nullptr here, because it is of type "nullptr_t", and this will
    // give erros for the pointer arithmetics done in sha256.
    // This would be much easier with "if constexpr" in C++17!
    return 0;
}

template<size_t Len_> static constexpr HashType sha256(std::array<uint8_t, Len_> const data)
{
    constexpr StateType STATE_ORG = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    StateType state = STATE_ORG;
    constexpr uint64_t LEN = Len_;
    constexpr uint64_t BLOCK_COUNT = LEN / sizeof(BlockType);

    auto const BLOCKS = u8ToBlocks(data);

    for (size_t i = 0; i < BLOCKS.size(); ++i)
    {
        state = transform(state, BLOCKS[i]);
    }

    struct
    {
        uint8_t Data[64];
    } lastB = {0};

    auto* const IT_LAST_B_BEGIN = &lastB.Data[0];
    auto* itLastB = IT_LAST_B_BEGIN;

    auto* itData = getArrayIt(data);
    if (itData != 0)
    {
        itLastB = constexprCopy(itData + BLOCK_COUNT * sizeof(BlockType), itData + LEN, itLastB);
    }
    *itLastB = 0x80;

    constexpr uint64_t REM = LEN - BLOCK_COUNT * sizeof(BlockType);
    if (REM >= 56)
    {
        BlockType const LAST_B = u8ToBlock(IT_LAST_B_BEGIN);
        state = transform(state, LAST_B);
        lastB = {0};
    }
    constexpr uint64_t LEN3 = LEN << 3;
    for (size_t i = 0; i < sizeof(uint64_t); ++i)
    {
        lastB.Data[56 + i] = (LEN3 >> (56 - (i * 8))) & 0xff;
    }
    BlockType const LAST_B = u8ToBlock(IT_LAST_B_BEGIN);
    state = transform(state, LAST_B);

    return stateToHash(state);
}

static constexpr uint8_t charToU8(char const v) { return static_cast<uint8_t>(v); }

template<size_t N, typename T, size_t N_, size_t... I> static constexpr auto getArray(T const (&data)[N_], std::index_sequence<I...>) { return std::array<T, N>{data[I]...}; }

template<size_t N, typename T, size_t N_> [[maybe_unused]] static constexpr auto getArray(T const (&data)[N_]) { return getArray<N>(data, std::make_index_sequence<N>()); }

template<typename T, size_t N> [[maybe_unused]] static constexpr auto getArray(T const (&data)[N]) { return getArray<N>(data); }

}  // namespace details

template<size_t N> static constexpr auto compute(std::array<uint8_t, N> const data) { return details::sha256(data); }

template<size_t N> static constexpr auto compute(char const (&data)[N])
{
    auto const AR = details::getArray(data);
    return details::sha256(details::map(details::charToU8, AR));
}

template<size_t N> [[maybe_unused]] static constexpr auto computeStr(char const (&data)[N])
{
    auto const AR = details::getArray<N - 1>(data);
    return details::sha256(details::map(details::charToU8, AR));
}

}  // namespace sha256_literal

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wgnu-string-literal-operator-template"
#endif
template<typename CharT, CharT... Cs> static constexpr auto operator"" _sha256()
{
    static_assert(std::is_same<CharT, char>::value, "only support 8-bit strings");
    const char data[] = {Cs...};
    return sha256_literal::compute(data);
}
#pragma GCC diagnostic pop
