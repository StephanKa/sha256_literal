#include "sha256.h"

#include "intmem.h"

#include <array>
#include <cstdint>
#include <cstring>

static const uint32_t SHA256_K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
                                      0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
                                      0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
                                      0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                                      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                                      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

using StateType = std::array<uint32_t, 8>;
using BlockType = std::array<uint32_t, 16>;
using WType = std::array<uint32_t, 64>;

static uint32_t rotr(uint32_t const v, int off) { return (v >> off) | (v << (32 - off)); }

static void transform(StateType& s, uint8_t const* data)
{
    WType w = {0};

    for (size_t i = 0; i < 16; ++i)
    {
        w[i] = intmem::loaduBe<uint32_t>(&data[i * sizeof(uint32_t)]);
    }

    for (size_t i = 16; i < 64; ++i)
    {
        const uint32_t S0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t S1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = (w[i - 16] + S0 + w[i - 7] + S1);
    }

    StateType inS = s;
    for (size_t i = 0; i < 64; ++i)
    {
        uint32_t const s0 = rotr(inS[0], 2) ^ rotr(inS[0], 13) ^ rotr(inS[0], 22);
        uint32_t const maj = (inS[0] & inS[1]) ^ (inS[0] & inS[2]) ^ (inS[1] & inS[2]);
        uint32_t const t2 = s0 + maj;
        uint32_t const s1 = rotr(inS[4], 6) ^ rotr(inS[4], 11) ^ rotr(inS[4], 25);
        uint32_t const ch = (inS[4] & inS[5]) ^ ((~inS[4]) & inS[6]);
        uint32_t const t1 = inS[7] + s1 + ch + SHA256_K[i] + w[i];

        inS[7] = inS[6];
        inS[6] = inS[5];
        inS[5] = inS[4];
        inS[4] = (inS[3] + t1);
        inS[3] = inS[2];
        inS[2] = inS[1];
        inS[1] = inS[0];
        inS[0] = (t1 + t2);
    }

    for (size_t i = 0; i < std::tuple_size<StateType>(); ++i)
    {
        s[i] += inS[i];
    }
}

sha256::HashType sha256::compute(const uint8_t* data, const uint64_t len)
{
    StateType state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const uint64_t BLOCK_COUNT = len / sizeof(BlockType);
    for (uint64_t i = 0; i < BLOCK_COUNT; ++i)
    {
        transform(state, &data[i * sizeof(BlockType)]);
    }

    const uint64_t REM = len - BLOCK_COUNT * sizeof(BlockType);

    uint8_t lastBlock[sizeof(BlockType)];
    memset(&lastBlock, 0, sizeof(lastBlock));
    memcpy(&lastBlock[0], &data[BLOCK_COUNT * sizeof(BlockType)], REM);
    lastBlock[REM] = 0x80;
    if (REM >= 56)
    {
        transform(state, lastBlock);
        memset(&lastBlock, 0, sizeof(lastBlock));
    }
    intmem::storeuBe(&lastBlock[56], len << 3);
    transform(state, lastBlock);

    HashType ret;
    static_assert(sizeof(HashType) == sizeof(StateType), "bad definition of HashType");
    for (size_t i = 0; i < 8; ++i)
    {
        intmem::storeuBe(&ret[i * sizeof(uint32_t)], state[i]);
    }
    return ret;
}
