// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_UTIL_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_UTIL_H_

#include "messages.hpp"
#include "util/common/buffer.hpp"

#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <util/common/hash.hpp>

namespace cbdc::threepc::agent::runner {
    auto to_uint64(const evmc::uint256be& v) -> uint64_t;

    template<typename T>
    auto to_hex(const T& v) -> std::string {
        return evmc::hex(evmc::bytes(v.bytes, sizeof(v.bytes)));
    }

    auto tx_id(const evm_tx& tx) -> cbdc::buffer;

    /// Calculates a contract address for the CREATE call
    /// keccak256(rlp([sender,nonce]))
    /// \param sender the sender account creating the contract
    /// \param nonce the account nonce of the sender at the time of creation
    /// \return the contract address
    auto contract_address(const evmc::address& sender,
                          const evmc::uint256be& nonce) -> evmc::address;

    /// Calculates a contract address for the CREATE2 call
    /// keccak256(0xFF | sender | salt | keccak256(bytecode))
    /// \param sender the sender account creating the contract
    /// \param salt the salt value
    /// \param bytecode_hash the keccak256 hash of the bytecode of the contract
    /// \return the contract address
    auto contract_address2(const evmc::address& sender,
                           const evmc::bytes32& salt,
                           const cbdc::hash_t& bytecode_hash) -> evmc::address;
}

#endif
