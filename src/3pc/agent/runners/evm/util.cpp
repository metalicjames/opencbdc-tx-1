// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.hpp"

#include "crypto/sha256.h"
#include "format.hpp"
#include "util/common/hash.hpp"
#include "util/serialization/util.hpp"

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

    auto tx_id(const evm_tx& tx) -> cbdc::buffer {
        auto buf = make_buffer(tx);
        auto s = CSHA256();
        s.Write(buf.c_ptr(), buf.size());
        auto h = hash_t();
        s.Finalize(h.data());
        auto ret = cbdc::buffer();
        ret.append(h.data(), h.size());
        return ret;
    }
}
