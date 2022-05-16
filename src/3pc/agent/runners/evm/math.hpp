// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_MATH_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_MATH_H_

#include <evmc/evmc.hpp>

namespace cbdc::threepc::agent::runner {
    auto operator+(const evmc::uint256be& lhs, const evmc::uint256be& rhs)
        -> evmc::uint256be;

    auto operator-(const evmc::uint256be& lhs, const evmc::uint256be& rhs)
        -> evmc::uint256be;

    auto operator*(const evmc::uint256be& lhs, const evmc::uint256be& rhs)
        -> evmc::uint256be;

    auto operator<<(const evmc::uint256be& lhs, size_t count)
        -> evmc::uint256be;
}

#endif
