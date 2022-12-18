#pragma once
#include <array>
#include <cstdint>

namespace Sha256 {

using HashType = std::array<uint8_t, 32>;
HashType compute(const uint8_t* data, const uint64_t len);

}  // namespace Sha256
