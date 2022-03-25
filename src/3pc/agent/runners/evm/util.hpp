// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_UTIL_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_UTIL_H_

#include "messages.hpp"
#include "util/common/buffer.hpp"
#include "util/common/hash.hpp"
#include "util/common/keys.hpp"

#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <memory>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_recovery.h>

namespace cbdc::threepc::agent::runner {
    auto to_uint64(const evmc::uint256be& v) -> uint64_t;

    template<typename T>
    auto to_hex(const T& v) -> std::string {
        return evmc::hex(evmc::bytes(v.bytes, sizeof(v.bytes)));
    }

    /// Parses hexadecimal representation in string format to T
    /// \param hex hex string to parse. May be prefixed with 0x
    /// \return object containing the parsed T or std::nullopt if
    /// parse failed
    template<typename T>
    auto from_hex(const std::string& hex) ->
        typename std::enable_if_t<std::is_same<T, evmc::bytes32>::value
                                      || std::is_same<T, evmc::address>::value,
                                  std::optional<T>> {
        auto maybe_bytes = cbdc::buffer::from_hex_prefixed(hex);
        if(!maybe_bytes.has_value()) {
            return std::nullopt;
        }
        if(maybe_bytes.value().size() != sizeof(T)) {
            return std::nullopt;
        }

        auto val = T();
        std::memcpy(val.bytes,
                    maybe_bytes.value().data(),
                    maybe_bytes.value().size());
        return val;
    }

    auto tx_id(const evm_tx& tx) -> cbdc::buffer;
}

#endif
