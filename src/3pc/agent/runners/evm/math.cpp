// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "math.hpp"

#include <limits>

namespace cbdc::threepc::agent::runner {
    auto operator+(const evmc::uint256be& lhs, const evmc::uint256be& rhs)
        -> evmc::uint256be {
        auto ret = evmc::uint256be{};
        auto tmp = uint64_t{};
        auto carry = uint8_t{};
        constexpr uint64_t max_val = std::numeric_limits<uint8_t>::max();
        for(int i = sizeof(lhs.bytes) - 1; i >= 0; i--) {
            tmp = lhs.bytes[i] + rhs.bytes[i] + carry;
            carry = (tmp > max_val);
            ret.bytes[i] = (tmp & max_val);
        }
        return ret;
    }

    auto operator-(const evmc::uint256be& lhs, const evmc::uint256be& rhs)
        -> evmc::uint256be {
        auto ret = evmc::uint256be{};
        auto tmp1 = uint64_t{};
        auto tmp2 = uint64_t{};
        auto res = uint64_t{};
        auto borrow = uint8_t{};
        constexpr uint64_t max_val = std::numeric_limits<uint8_t>::max();
        for(int i = sizeof(lhs.bytes) - 1; i >= 0; i--) {
            tmp1 = lhs.bytes[i] + (max_val + 1);
            tmp2 = rhs.bytes[i] + borrow;
            res = tmp1 - tmp2;
            ret.bytes[i] = (res & max_val);
            borrow = (res <= max_val);
        }
        return ret;
    }

    auto operator*(const evmc::uint256be& lhs, const evmc::uint256be& rhs)
        -> evmc::uint256be {
        auto ret = evmc::uint256be{};
        for(int i = sizeof(lhs.bytes) - 1; i >= 0; i--) {
            auto row = evmc::uint256be{};
            for(int j = sizeof(rhs.bytes) - 1; j >= 0; j--) {
                if(i + j < static_cast<int>(sizeof(rhs.bytes))) {
                    uint64_t intermediate = lhs.bytes[i] * rhs.bytes[j];
                    auto tmp = evmc::uint256be(intermediate);
                    tmp = tmp >> static_cast<size_t>(i + j);
                    row = row + tmp;
                }
            }
            ret = ret + row;
        }
        return ret;
    }

    auto operator>>(const evmc::uint256be& lhs, size_t count)
        -> evmc::uint256be {
        auto ret = evmc::uint256be{};
        if(count >= sizeof(lhs.bytes)) {
            return ret;
        }
        for(size_t i = 0; i < sizeof(lhs.bytes) - count; i++) {
            ret.bytes[i] = lhs.bytes[i + count];
        }
        for(size_t i = sizeof(lhs.bytes) - count; i < sizeof(lhs.bytes); i++) {
            ret.bytes[i] = 0;
        }
        return ret;
    }
}
