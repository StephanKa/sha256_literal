#pragma once
#include <array>
#include <cstdint>

namespace sha256 {

static constexpr uint32_t FOUR_BYTE_OFFSET = 32;
using HashType = std::array<uint8_t, FOUR_BYTE_OFFSET>;
HashType compute(const uint8_t* data, const uint64_t len);

}  // namespace sha256
