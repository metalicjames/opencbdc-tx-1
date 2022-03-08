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

    auto contract_address(const evmc::address& sender,
                          const evmc::uint256be& nonce) -> evmc::address {
        auto new_addr = evmc::address();
        auto buf = make_buffer(make_rlp_array(make_rlp_value(sender),
                                              make_rlp_value(nonce, true)));
        auto addr_hash = keccak_data(buf.data(), buf.size());
        constexpr auto addr_offset = addr_hash.size() - sizeof(new_addr.bytes);
        std::memcpy(new_addr.bytes,
                    addr_hash.data() + addr_offset,
                    sizeof(new_addr.bytes));
        return new_addr;
    }

    auto contract_address2(const evmc::address& sender,
                           const evmc::bytes32& salt,
                           const cbdc::hash_t& bytecode_hash)
        -> evmc::address {
        auto new_addr = evmc::address();
        auto buf = cbdc::buffer();
        static constexpr uint8_t contract_address2_preimage_prefix = 0xFF;
        auto b = std::byte(contract_address2_preimage_prefix);
        buf.append(&b, sizeof(b));
        buf.append(sender.bytes, sizeof(sender.bytes));
        buf.append(salt.bytes, sizeof(salt.bytes));
        buf.append(bytecode_hash.data(), bytecode_hash.size());

        auto addr_hash = keccak_data(buf.data(), buf.size());
        constexpr auto addr_offset = addr_hash.size() - sizeof(new_addr.bytes);
        std::memcpy(new_addr.bytes,
                    addr_hash.data() + addr_offset,
                    sizeof(new_addr.bytes));
        return new_addr;
    }
}
