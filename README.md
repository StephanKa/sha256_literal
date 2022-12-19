Header-only constexpr SHA256 C++ 14 literal
===========================================

[![C/C++ CMake CI](https://github.com/StephanKa/sha256_literal/actions/workflows/build_cmake.yml/badge.svg?branch=master)](https://github.com/StephanKa/sha256_literal/actions/workflows/build_cmake.yml)

THis is a C++17 constexpr implementation of SHA256, which allows (among others)
the usage of a "_sha256" literal to get compile-time SHA256 hashes:

```cpp

    #include "sha256_literal.h"

    static constexpr sha256::HashType H = "mypassword"_sha256;
    // HashType is a std::array<uint8_t, 32>
```

More "low-level" API are also provided:

```cpp

    static constexpr auto H0 = sha256::compute_str("hello");
    static constexpr auto H1 = sha256::compute({'A','B'});
```

This can be used for instance to compare user-provided passwords to a
hard-coded one in a binary (although this is not recommended to do so
directly, passwords should always be salted when hashed!):

```cpp

    #include "sha256.h"
    #include "sha256_literal.h"

    bool isGoodPwd(const char* Pwd) {
      static constexpr auto PASSWORD_HASH = "myverysecretpassword"_sha256;
      return sha256::compute(pwd, strlen(reinterpret_cast<const char*>(pwd))) == PASSWORD_HASH;
    }
```

See the ``tests.cpp`` file for tests, and the ``example.cpp`` for a usage example.

A runtime implementation of SHA256 is also provided in ``sha256.cpp``. This
does not respect the NIST API standards, and is only there for convience.

This has been tested with clang 12.0 | 13.0 | 14.0 | 15.0 and GCC 10 | 11 under linux.
