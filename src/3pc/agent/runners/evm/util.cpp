// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.hpp"

#include "crypto/sha256.h"
#include "format.hpp"
#include "hash.hpp"
#include "rlp.hpp"
#include "util/common/hash.hpp"
#include "util/serialization/util.hpp"

#include <optional>
#include <secp256k1.h>

namespace cbdc::threepc::agent::runner {
    auto to_uint64(const evmc::uint256be& v) -> uint64_t {
        return evmc::load64be(&v.bytes[sizeof(v.bytes) - sizeof(uint64_t)]);
    }

    auto to_hex(const evmc::address& addr) -> std::string {
        return evmc::hex(evmc::bytes(addr.bytes, sizeof(addr.bytes)));
    }

    auto to_hex(const evmc::bytes32& b) -> std::string {
        return evmc::hex(evmc::bytes(b.bytes, sizeof(b.bytes)));
    }

    auto parse_bytes32(const std::string& bytes)
        -> std::optional<evmc::bytes32> {
        static constexpr size_t bytes_size = 32;
        if(bytes.size() < bytes_size * 2) {
            return std::nullopt;
        }

        auto bytes_to_parse = bytes;
        if(bytes_to_parse.substr(0, 2) == "0x") {
            bytes_to_parse = bytes_to_parse.substr(2);
        }
        auto maybe_bytes = cbdc::buffer::from_hex(bytes_to_parse);
        if(!maybe_bytes.has_value()) {
            return std::nullopt;
        }
        if(maybe_bytes.value().size() != bytes_size) {
            return std::nullopt;
        }

        auto bytes_val = evmc::bytes32();
        std::memcpy(bytes_val.bytes,
                    maybe_bytes.value().data(),
                    maybe_bytes.value().size());
        return bytes_val;
    }
}
