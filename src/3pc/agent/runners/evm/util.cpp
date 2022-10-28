// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.hpp"

#include "3pc/util.hpp"
#include "crypto/sha256.h"
#include "format.hpp"
#include "hash.hpp"
#include "init_addresses.hpp"
#include "math.hpp"
#include "rlp.hpp"
#include "util/common/hash.hpp"
#include "util/serialization/util.hpp"

#include <future>
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

    auto to_hex_trimmed(const evmc::bytes32& b, const std::string& prefix)
        -> std::string {
        size_t offset = 0;
        while(b.bytes[offset] == 0x00) {
            offset++;
        }
        if(offset >= sizeof(b.bytes)) {
            return prefix + "0";
        } else {
            auto str = evmc::hex(
                evmc::bytes(&b.bytes[offset], sizeof(b.bytes) - offset));
            if(str.substr(0, 1) == "0") {
                str = str.substr(1);
            }
            return prefix + str;
        }
    }

    // Taken from: ethereum.github.io/execution-specs/autoapi/ethereum/
    // frontier/bloom/index.html#logs-bloom
    void add_to_bloom(cbdc::buffer& bloom, const cbdc::buffer& entry) {
        auto hash = cbdc::make_buffer(keccak_data(entry.data(), entry.size()));

        for(size_t i = 0; i <= 4; i += 2) {
            auto uint16_buf = cbdc::buffer();
            uint16_buf.extend(2);
            std::memcpy(uint16_buf.data(), hash.data_at(i), 2);
            uint16_t byte_pair
                = cbdc::from_buffer<uint16_t>(uint16_buf).value();
            static constexpr uint16_t bloom_bits = 0x07FF;
            auto bit_to_set = byte_pair & bloom_bits;
            auto bit_index = 0x07FF - bit_to_set;
            auto byte_index = bit_index / 8;
            uint8_t bit_value
                = static_cast<uint8_t>(1 << (7 - (bit_index % 8)));
            uint8_t bloom_byte{};
            std::memcpy(&bloom_byte, bloom.data_at(byte_index), 1);
            bloom_byte |= bit_value;
            std::memcpy(bloom.data_at(byte_index), &bloom_byte, 1);
        }
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

    auto uint256be_from_hex(const std::string& hex)
        -> std::optional<evmc::uint256be> {
        auto maybe_bytes = cbdc::buffer::from_hex_prefixed(hex);
        if(!maybe_bytes.has_value()) {
            return std::nullopt;
        }
        auto ret = evmc::uint256be();
        auto& bytes = maybe_bytes.value();
        if(bytes.size() > sizeof(ret)) {
            return std::nullopt;
        }
        auto tmp = cbdc::buffer();
        tmp.extend(sizeof(ret));
        std::memcpy(tmp.data_at(sizeof(ret) - bytes.size()),
                    bytes.data(),
                    bytes.size());
        std::memcpy(&ret.bytes[0], tmp.data(), tmp.size());
        return ret;
    }

    auto mint_initial_accounts(
        const std::shared_ptr<logging::log>& log,
        const std::shared_ptr<threepc::broker::interface>& broker) -> bool {
        log->info("Initializing init addresses");

        auto acc = cbdc::threepc::agent::runner::evm_account();
        static constexpr uint64_t decimals = 1000000000000000000;
        static constexpr uint64_t initial_mint = 1000000;
        acc.m_balance
            = evmc::uint256be(initial_mint) * evmc::uint256be(decimals);
        auto acc_buf = cbdc::make_buffer(acc);

        auto successes = std::vector<std::future<bool>>();

        for(const auto& init_addr_hex : cbdc::threepc::agent::init_addresses) {
            log->info("Seeding address ", init_addr_hex);
            auto init_addr = cbdc::buffer::from_hex(init_addr_hex).value();
            auto seed_success = std::make_shared<std::promise<bool>>();
            auto seed_fut = seed_success->get_future();
            successes.emplace_back(std::move(seed_fut));
            auto success
                = cbdc::threepc::put_row(broker,
                                         init_addr,
                                         acc_buf,
                                         [seed_success](bool s) {
                                             seed_success->set_value(s);
                                         });
            if(!success) {
                log->error("Error requesting seeding account");
                return false;
            }
        }

        for(auto& f : successes) {
            auto seed_res = f.get();
            if(!seed_res) {
                log->error("Error during seeding");
                return false;
            }
        }

        return true;
    }
}
