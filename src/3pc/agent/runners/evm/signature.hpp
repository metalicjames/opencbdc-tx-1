// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_SIGNATURE_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_SIGNATURE_H_

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
    /// Signs a hash using a privkey_t using ecdsa and produces an evm_sig
    /// struct Used primarily in unit tests for signature checking
    /// \param key key to sign with
    /// \param hash hash to sign
    /// \param ctx secp256k1 context to use
    /// \return the signature value encoded in r,s,v values in an evm_sig struct
    auto
    eth_sign(const privkey_t& key,
             hash_t& hash,
             evm_tx_type type,
             uint64_t chain_id,
             const std::unique_ptr<secp256k1_context,
                                   decltype(&secp256k1_context_destroy)>& ctx)
        -> evm_sig;

    /// Checks the signature of an EVM transaction
    /// \param tx transaction to check signature for
    /// \param from address expected to have sent the transaction
    /// \param ctx secp256k1 context to use
    /// \return true if valid, false otherwise
    auto check_signature(
        const std::shared_ptr<cbdc::threepc::agent::runner::evm_tx>& tx,
        uint64_t chain_id,
        const std::unique_ptr<secp256k1_context,
                              decltype(&secp256k1_context_destroy)>& ctx)
        -> bool;

    /// Calculates the hash for creating / validating the signature
    /// \param tx transaction to calculate the sighash for
    /// \return the sighash of the transaction
    auto
    sig_hash(const std::shared_ptr<cbdc::threepc::agent::runner::evm_tx>& tx,
             uint64_t chain_id) -> hash_t;

}
#endif
