#include "sha256.h"
#include "sha256_literal.h"

#include <fmt/format.h>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        fmt::print("[ERROR]Usage: {0} pwd\n", argv[0]);
        return 2;
    }

    static constexpr auto PASSWORD_HASH = "myverysecretpassword"_sha256;
    const uint8_t* pwd = reinterpret_cast<const uint8_t*>(argv[1]);
    if (Sha256::compute(pwd, strlen(reinterpret_cast<const char*>(pwd))) == PASSWORD_HASH)
    {
        fmt::print("good password!");
        return 0;
    }

    fmt::print("bad password!");
    return 1;
}
