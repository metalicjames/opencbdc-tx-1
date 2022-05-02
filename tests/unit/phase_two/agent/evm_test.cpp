// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../util.hpp"
#include "3pc/agent/impl.hpp"
#include "3pc/agent/runners/evm/address.hpp"
#include "3pc/agent/runners/evm/format.hpp"
#include "3pc/agent/runners/evm/hash.hpp"
#include "3pc/agent/runners/evm/impl.hpp"
#include "3pc/agent/runners/evm/messages.hpp"
#include "3pc/agent/runners/evm/rlp.hpp"
#include "3pc/agent/runners/evm/serialization.hpp"
#include "3pc/agent/runners/evm/signature.hpp"
#include "3pc/agent/runners/evm/util.hpp"
#include "3pc/broker/impl.hpp"
#include "3pc/directory/impl.hpp"
#include "3pc/runtime_locking_shard/impl.hpp"
#include "3pc/ticket_machine/impl.hpp"

#include <future>
#include <gtest/gtest.h>
#include <secp256k1.h>
#include <thread>

class evm_test : public ::testing::Test {
  protected:
    void SetUp() override {
        auto priv_buf = cbdc::buffer::from_hex(
                            "32a49a8408806e7a2862bca482c7aabd27e846f673edc8fb1"
                            "4501cab0d1d8ebe2c5c3a79e8151c68c0d0fd54f9b4b0d26a"
                            "d4777bc9a4f7a283d237f5a23a448985d819879b00c340e9b"
                            "e3f321df85bd38f22e5197195f39c40ee1b6fa3ed1751")
                            .value();
        std::memcpy(m_priv0.data(), priv_buf.data(), 32);
        std::memcpy(m_priv1.data(), priv_buf.data_at(32), 32);
        std::memcpy(m_priv2.data(), priv_buf.data_at(64), 32);
        m_addr0_addr
            = cbdc::threepc::agent::runner::eth_addr(m_priv0, m_secp_context);
        m_addr1_addr
            = cbdc::threepc::agent::runner::eth_addr(m_priv1, m_secp_context);
        m_addr2_addr
            = cbdc::threepc::agent::runner::eth_addr(m_priv2, m_secp_context);

        m_addr0.append(m_addr0_addr.bytes, 20);
        m_addr1.append(m_addr1_addr.bytes, 20);
        m_addr2.append(m_addr2_addr.bytes, 20);

        auto contract
            = cbdc::buffer::from_hex("4360005543600052596000f3").value();

        auto acc = cbdc::threepc::agent::runner::evm_account();
        acc.m_balance = evmc::uint256be(1000000);
        acc.m_code.resize(contract.size());
        std::memcpy(acc.m_code.data(), contract.data(), contract.size());
        auto acc_buf = cbdc::make_buffer(acc);
        cbdc::test::add_to_shard(m_broker, m_addr0, acc_buf);

        auto acc1 = cbdc::threepc::agent::runner::evm_account();
        acc1.m_balance = evmc::uint256be(1000000);
        auto acc1_buf = cbdc::make_buffer(acc1);
        cbdc::test::add_to_shard(m_broker, m_addr1, acc1_buf);

        auto acc2 = cbdc::threepc::agent::runner::evm_account();
        acc2.m_balance = evmc::uint256be(1000000);
        auto acc2_buf = cbdc::make_buffer(acc2);
        cbdc::test::add_to_shard(m_broker, m_addr2, acc2_buf);
    }

    std::shared_ptr<cbdc::logging::log> m_log{
        std::make_shared<cbdc::logging::log>(cbdc::logging::log_level::trace)};
    cbdc::threepc::config m_cfg{};
    std::shared_ptr<cbdc::threepc::runtime_locking_shard::interface> m_shard0{
        std::make_shared<cbdc::threepc::runtime_locking_shard::impl>(m_log)};
    std::shared_ptr<cbdc::threepc::ticket_machine::interface> m_ticketer{
        std::make_shared<cbdc::threepc::ticket_machine::impl>(m_log, 1)};
    std::shared_ptr<cbdc::threepc::directory::interface> m_directory{
        std::make_shared<cbdc::threepc::directory::impl>(1)};
    std::shared_ptr<cbdc::threepc::broker::interface> m_broker{
        std::make_shared<cbdc::threepc::broker::impl>(
            0,
            std::vector<std::shared_ptr<
                cbdc::threepc::runtime_locking_shard::interface>>({m_shard0}),
            m_ticketer,
            m_directory,
            m_log)};

    std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)>
        m_secp_context{secp256k1_context_create(SECP256K1_CONTEXT_SIGN
                                                | SECP256K1_CONTEXT_VERIFY),
                       &secp256k1_context_destroy};
    cbdc::privkey_t m_priv0;
    cbdc::privkey_t m_priv1;
    cbdc::privkey_t m_priv2;
    cbdc::buffer m_addr0;
    cbdc::buffer m_addr1;
    cbdc::buffer m_addr2;
    evmc::address m_addr0_addr;
    evmc::address m_addr1_addr;
    evmc::address m_addr2_addr;
    static constexpr uint64_t default_chain_id = 1;
};

TEST_F(evm_test, initial_test) {
    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_from = m_addr1_addr;
    tx->m_to = m_addr0_addr;
    tx->m_nonce = evmc::uint256be(1);
    tx->m_value = evmc::uint256be(1000);
    tx->m_gas_price = evmc::uint256be(1);
    tx->m_gas_limit = evmc::uint256be(200000);
    auto sighash
        = cbdc::threepc::agent::runner::sig_hash(tx, default_chain_id);
    tx->m_sig = cbdc::threepc::agent::runner::eth_sign(m_priv1,
                                                       sighash,
                                                       tx->m_type,
                                                       default_chain_id,
                                                       m_secp_context);
    auto params = cbdc::make_buffer(*tx);

    auto prom = std::promise<void>();
    auto fut = prom.get_future();
    auto agent = std::make_shared<cbdc::threepc::agent::impl>(
        m_log,
        m_cfg,
        &cbdc::threepc::agent::runner::factory<
            cbdc::threepc::agent::runner::evm_runner>::create,
        m_broker,
        m_addr1,
        params,
        [&](const cbdc::threepc::agent::interface::exec_return_type& res) {
            ASSERT_TRUE(
                std::holds_alternative<cbdc::threepc::agent::return_type>(
                    res));
            prom.set_value();
        },
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type,
        false);
    ASSERT_TRUE(agent->exec());
    auto res = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(res, std::future_status::ready);
}

TEST_F(evm_test, host_storage) {
    const auto addr1 = evmc::address{};
    const auto addr2 = evmc::address{0xffffff};
    const auto addr3 = evmc::address{0xffffff1};
    const auto val1 = evmc::bytes32{};
    const auto val2 = evmc::bytes32{2};
    const auto val3 = evmc::bytes32{3};

    auto tx_ctx = evmc_tx_context();

    auto m = std::unordered_map<cbdc::buffer,
                                cbdc::buffer,
                                cbdc::hashing::const_sip_hash<cbdc::buffer>>();

    auto host = cbdc::threepc::agent::runner::evm_host(
        m_log,
        [&](const cbdc::threepc::runtime_locking_shard::key_type& k,
            cbdc::threepc::broker::lock_type /* locktype */,
            const cbdc::threepc::broker::interface::try_lock_callback_type&
                cb) {
            cb(m[k]);
            return true;
        },
        tx_ctx,
        nullptr,
        {},
        false);
    ASSERT_EQ(host.set_storage(addr3, val2, val2), EVMC_STORAGE_ADDED);
    ASSERT_FALSE(host.should_retry());
    m = host.get_state_updates();

    host = cbdc::threepc::agent::runner::evm_host(
        m_log,
        [&](const cbdc::threepc::runtime_locking_shard::key_type& k,
            cbdc::threepc::broker::lock_type /* locktype */,
            const cbdc::threepc::broker::interface::try_lock_callback_type&
                cb) {
            cb(m[k]);
            return true;
        },
        tx_ctx,
        nullptr,
        {},
        false);
    const auto& chost = host;

    // Null bytes returned for non-existing accounts.
    EXPECT_EQ(chost.get_storage(addr1, {}), evmc::bytes32{});
    EXPECT_EQ(chost.get_storage(addr2, {}), evmc::bytes32{});

    // Set storage on non-existing account creates the account.
    EXPECT_EQ(host.set_storage(addr1, val1, val2), EVMC_STORAGE_ADDED);
    EXPECT_EQ(chost.get_storage(addr2, val1), evmc::bytes32{});
    EXPECT_EQ(host.set_storage(addr2, val1, val2), EVMC_STORAGE_ADDED);
    EXPECT_EQ(chost.get_storage(addr2, val1), val2);
    EXPECT_EQ(host.set_storage(addr2, val1, val2), EVMC_STORAGE_UNCHANGED);
    EXPECT_EQ(chost.get_storage(addr2, val1), val2);
    EXPECT_EQ(host.set_storage(addr2, val1, val3),
              EVMC_STORAGE_MODIFIED_AGAIN);
    EXPECT_EQ(chost.get_storage(addr2, val1), val3);
    EXPECT_EQ(host.set_storage(addr2, val1, val1),
              EVMC_STORAGE_MODIFIED_AGAIN);
    EXPECT_EQ(chost.get_storage(addr2, val1), val1);

    EXPECT_EQ(chost.get_storage(addr2, val3), evmc::bytes32{});
    EXPECT_EQ(host.set_storage(addr2, val3, evmc::bytes32{}),
              EVMC_STORAGE_UNCHANGED);
    EXPECT_EQ(chost.get_storage(addr2, val3), evmc::bytes32{});
    EXPECT_EQ(host.set_storage(addr2, val3, val3), EVMC_STORAGE_MODIFIED);
    EXPECT_EQ(chost.get_storage(addr2, val3), val3);
    EXPECT_EQ(host.set_storage(addr2, val3, val1),
              EVMC_STORAGE_MODIFIED_AGAIN);
    EXPECT_EQ(chost.get_storage(addr2, val3), val1);

    // Set storage to zero on an existing storage location deletes it
    EXPECT_EQ(host.set_storage(addr3, val2, val1), EVMC_STORAGE_DELETED);
}

TEST_F(evm_test, simple_send) {
    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_from = m_addr1_addr;
    tx->m_to = m_addr2_addr;
    tx->m_nonce = evmc::uint256be(1);
    tx->m_value = evmc::uint256be(1000);
    tx->m_gas_price = evmc::uint256be(1);
    tx->m_gas_limit = evmc::uint256be(21000);
    auto sighash
        = cbdc::threepc::agent::runner::sig_hash(tx, default_chain_id);
    tx->m_sig = cbdc::threepc::agent::runner::eth_sign(m_priv1,
                                                       sighash,
                                                       tx->m_type,
                                                       default_chain_id,
                                                       m_secp_context);
    auto params = cbdc::make_buffer(*tx);

    auto prom = std::promise<void>();
    auto fut = prom.get_future();
    auto agent = std::make_shared<cbdc::threepc::agent::impl>(
        m_log,
        m_cfg,
        &cbdc::threepc::agent::runner::factory<
            cbdc::threepc::agent::runner::evm_runner>::create,
        m_broker,
        m_addr1,
        params,
        [&](const cbdc::threepc::agent::interface::exec_return_type& res) {
            ASSERT_TRUE(
                std::holds_alternative<cbdc::threepc::agent::return_type>(
                    res));
            prom.set_value();
        },
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type,
        false);
    ASSERT_TRUE(agent->exec());
    auto res = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(res, std::future_status::ready);

    // Test send not working, not enough gas
    tx->m_gas_limit = evmc::uint256be(20999);
    tx->m_nonce = evmc::uint256be(2);
    auto sighash2
        = cbdc::threepc::agent::runner::sig_hash(tx, default_chain_id);
    tx->m_sig = cbdc::threepc::agent::runner::eth_sign(m_priv1,
                                                       sighash2,
                                                       tx->m_type,
                                                       1,
                                                       m_secp_context);
    params = cbdc::make_buffer(*tx);
    prom = std::promise<void>();
    fut = prom.get_future();
    agent = std::make_shared<cbdc::threepc::agent::impl>(
        m_log,
        m_cfg,
        &cbdc::threepc::agent::runner::factory<
            cbdc::threepc::agent::runner::evm_runner>::create,
        m_broker,
        m_addr1,
        params,
        [&](const cbdc::threepc::agent::interface::exec_return_type& r) {
            ASSERT_TRUE(std::holds_alternative<
                        cbdc::threepc::agent::interface::error_code>(r));
            prom.set_value();
        },
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type,
        false);
    ASSERT_TRUE(agent->exec());
    res = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(res, std::future_status::ready);
}

TEST_F(evm_test, contract_deploy) {
    auto bytecode
        = cbdc::buffer::from_hex(
              "608060405234801561001057600080fd5b5061002d61002261003260201b602"
              "01c565b61003a60201b60201c565b6100fe565b600033905090565b60008060"
              "009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1"
              "69050816000806101000a81548173ffffffffffffffffffffffffffffffffff"
              "ffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021"
              "79055508173ffffffffffffffffffffffffffffffffffffffff168173ffffff"
              "ffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd"
              "0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a350"
              "50565b6106958061010d6000396000f3fe60806040523480156100105760008"
              "0fd5b50600436106100575760003560e01c80632e64cec11461005c57806360"
              "57361d1461007a578063715018a6146100965780638da5cb5b146100a057806"
              "3f2fde38b146100be575b600080fd5b6100646100da565b6040516100719190"
              "610551565b60405180910390f35b610094600480360381019061008f9190610"
              "469565b6100e4565b005b61009e6101a1565b005b6100a8610229565b604051"
              "6100b591906104f6565b60405180910390f35b6100d86004803603810190610"
              "0d39190610440565b610252565b005b6000600154905090565b6100ec61034a"
              "565b73ffffffffffffffffffffffffffffffffffffffff1661010a610229565"
              "b73ffffffffffffffffffffffffffffffffffffffff1614610160576040517f"
              "08c379a00000000000000000000000000000000000000000000000000000000"
              "0815260040161015790610531565b60405180910390fd5b806001819055507f"
              "93fe6d397c74fdf1402a8b72e47b68512f0510d7b98a4bc4cbdf6ac7108b3c5"
              "9816040516101969190610551565b60405180910390a150565b6101a961034a"
              "565b73ffffffffffffffffffffffffffffffffffffffff166101c7610229565"
              "b73ffffffffffffffffffffffffffffffffffffffff161461021d576040517f"
              "08c379a00000000000000000000000000000000000000000000000000000000"
              "0815260040161021490610531565b60405180910390fd5b6102276000610352"
              "565b565b60008060009054906101000a900473fffffffffffffffffffffffff"
              "fffffffffffffff16905090565b61025a61034a565b73ffffffffffffffffff"
              "ffffffffffffffffffffff16610278610229565b73fffffffffffffffffffff"
              "fffffffffffffffffff16146102ce576040517f08c379a00000000000000000"
              "000000000000000000000000000000000000000081526004016102c59061053"
              "1565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffff"
              "ffffff168173ffffffffffffffffffffffffffffffffffffffff16141561033"
              "e576040517f08c379a000000000000000000000000000000000000000000000"
              "000000000000815260040161033590610511565b60405180910390fd5b61034"
              "781610352565b50565b600033905090565b60008060009054906101000a9004"
              "73ffffffffffffffffffffffffffffffffffffffff169050816000806101000"
              "a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ff"
              "ffffffffffffffffffffffffffffffffffffff1602179055508173fffffffff"
              "fffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffff"
              "ffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3d"
              "aafe3b4186f6b6457e060405160405180910390a35050565b60008135905061"
              "042581610631565b92915050565b60008135905061043a81610648565b92915"
              "050565b60006020828403121561045257600080fd5b60006104608482850161"
              "0416565b91505092915050565b60006020828403121561047b57600080fd5b6"
              "0006104898482850161042b565b91505092915050565b61049b8161057d565b"
              "82525050565b60006104ae60268361056c565b91506104b9826105b9565b604"
              "082019050919050565b60006104d160208361056c565b91506104dc82610608"
              "565b602082019050919050565b6104f0816105af565b82525050565b6000602"
              "08201905061050b6000830184610492565b92915050565b6000602082019050"
              "818103600083015261052a816104a1565b9050919050565b600060208201905"
              "0818103600083015261054a816104c4565b9050919050565b60006020820190"
              "5061056660008301846104e7565b92915050565b60008282526020820190509"
              "2915050565b60006105888261058f565b9050919050565b600073ffffffffff"
              "ffffffffffffffffffffffffffffff82169050919050565b600081905091905"
              "0565b7f4f776e61626c653a206e6577206f776e657220697320746865207a65"
              "726f206160008201527f6464726573730000000000000000000000000000000"
              "000000000000000000000602082015250565b7f4f776e61626c653a2063616c"
              "6c6572206973206e6f7420746865206f776e6572600082015250565b61063a8"
              "161057d565b811461064557600080fd5b50565b610651816105af565b811461"
              "065c57600080fd5b5056fea2646970667358221220d1d385c015549fffb510d"
              "bf5df48c9f7404bfa5d2fc9bb7c0784d513dc5859c464736f6c634300080400"
              "33")
              .value();

    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_from = m_addr1_addr;
    tx->m_nonce = evmc::uint256be(1);
    tx->m_value = evmc::uint256be(0);
    tx->m_gas_price = evmc::uint256be(1);
    tx->m_gas_limit = evmc::uint256be(100000);
    tx->m_input.resize(bytecode.size());
    std::memcpy(tx->m_input.data(), bytecode.data(), bytecode.size());

    auto sighash
        = cbdc::threepc::agent::runner::sig_hash(tx, default_chain_id);
    tx->m_sig = cbdc::threepc::agent::runner::eth_sign(m_priv1,
                                                       sighash,
                                                       tx->m_type,
                                                       1,
                                                       m_secp_context);

    auto contract_addr = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "8d1ec7694e13bf51041920b5cf4e1668b0e267a9");

    auto params = cbdc::make_buffer(*tx);

    auto deploy_txid = cbdc::threepc::agent::runner::tx_id(*tx);

    auto prom = std::promise<cbdc::threepc::agent::runner::evm_tx_receipt>();
    auto fut = prom.get_future();
    auto agent = std::make_shared<cbdc::threepc::agent::impl>(
        m_log,
        m_cfg,
        &cbdc::threepc::agent::runner::factory<
            cbdc::threepc::agent::runner::evm_runner>::create,
        m_broker,
        m_addr1,
        params,
        [&](cbdc::threepc::agent::interface::exec_return_type res) {
            ASSERT_TRUE(
                std::holds_alternative<cbdc::threepc::agent::return_type>(
                    res));
            auto& r = std::get<cbdc::threepc::agent::return_type>(res);
            auto it = r.find(deploy_txid);
            ASSERT_NE(it, r.end());
            auto maybe_receipt = cbdc::from_buffer<
                cbdc::threepc::agent::runner::evm_tx_receipt>(it->second);
            ASSERT_TRUE(maybe_receipt.has_value());
            auto& receipt = maybe_receipt.value();
            prom.set_value(receipt);
        },
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type,
        false);
    ASSERT_TRUE(agent->exec());
    auto res = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(res, std::future_status::ready);
    auto receipt = fut.get();
    ASSERT_TRUE(receipt.m_create_address.has_value());
    ASSERT_EQ(receipt.m_create_address, contract_addr);

    tx->m_to = contract_addr;
    tx->m_nonce = evmc::uint256be(2);
    auto store_input
        = cbdc::buffer::from_hex("6057361d000000000000000000000000000000000000"
                                 "000000000000000000000000002a")
              .value();
    tx->m_input.resize(store_input.size());
    std::memcpy(tx->m_input.data(), store_input.data(), store_input.size());

    auto sighash2
        = cbdc::threepc::agent::runner::sig_hash(tx, default_chain_id);
    tx->m_sig = cbdc::threepc::agent::runner::eth_sign(m_priv1,
                                                       sighash2,
                                                       tx->m_type,
                                                       1,
                                                       m_secp_context);

    params = cbdc::make_buffer(*tx);

    auto store_txid = cbdc::threepc::agent::runner::tx_id(*tx);

    prom = std::promise<cbdc::threepc::agent::runner::evm_tx_receipt>();
    fut = prom.get_future();
    agent = std::make_shared<cbdc::threepc::agent::impl>(
        m_log,
        m_cfg,
        &cbdc::threepc::agent::runner::factory<
            cbdc::threepc::agent::runner::evm_runner>::create,
        m_broker,
        m_addr1,
        params,
        [&](cbdc::threepc::agent::interface::exec_return_type r) {
            ASSERT_TRUE(
                std::holds_alternative<cbdc::threepc::agent::return_type>(r));
            auto& ret = std::get<cbdc::threepc::agent::return_type>(r);
            auto it = ret.find(store_txid);
            ASSERT_NE(it, ret.end());
            auto maybe_receipt = cbdc::from_buffer<
                cbdc::threepc::agent::runner::evm_tx_receipt>(it->second);
            ASSERT_TRUE(maybe_receipt.has_value());
            auto& rec = maybe_receipt.value();
            prom.set_value(rec);
        },
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type,
        false);
    ASSERT_TRUE(agent->exec());
    res = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(res, std::future_status::ready);

    receipt = fut.get();
    ASSERT_TRUE(receipt.m_tx.m_to.has_value());
    ASSERT_EQ(receipt.m_tx.m_to.value(), contract_addr);

    ASSERT_EQ(receipt.m_logs.size(), 1);
    auto& l = receipt.m_logs[0];
    auto exp_data = std::vector<uint8_t>();
    exp_data.resize(32);
    exp_data.back() = 42;
    ASSERT_EQ(l.m_data, exp_data);

    auto exp_topic = cbdc::buffer::from_hex("93fe6d397c74fdf1402a8b72e47b68512"
                                            "f0510d7b98a4bc4cbdf6ac7108b3c59")
                         .value();
    auto exp_bytes = evmc::bytes32();
    std::memcpy(exp_bytes.bytes, exp_topic.data(), exp_topic.size());
    ASSERT_EQ(l.m_topics.size(), 1);
    ASSERT_EQ(l.m_topics[0], exp_bytes);
    ASSERT_EQ(l.m_addr, contract_addr);

    auto retrieve_input
        = cbdc::buffer::from_hex("2e64cec1000000000000000000000000000000000000"
                                 "0000000000000000000000000000")
              .value();
    tx->m_input.resize(retrieve_input.size());
    std::memcpy(tx->m_input.data(),
                retrieve_input.data(),
                retrieve_input.size());
    params = cbdc::make_buffer(*tx);

    auto retrieve_txid = cbdc::threepc::agent::runner::tx_id(*tx);

    prom = std::promise<cbdc::threepc::agent::runner::evm_tx_receipt>();
    fut = prom.get_future();
    agent = std::make_shared<cbdc::threepc::agent::impl>(
        m_log,
        m_cfg,
        &cbdc::threepc::agent::runner::factory<
            cbdc::threepc::agent::runner::evm_runner>::create,
        m_broker,
        cbdc::buffer(),
        params,
        [&](cbdc::threepc::agent::interface::exec_return_type r) {
            ASSERT_TRUE(
                std::holds_alternative<cbdc::threepc::agent::return_type>(r));
            auto& ret = std::get<cbdc::threepc::agent::return_type>(r);
            auto it = ret.find(retrieve_txid);
            ASSERT_NE(it, ret.end());
            auto maybe_receipt = cbdc::from_buffer<
                cbdc::threepc::agent::runner::evm_tx_receipt>(it->second);
            ASSERT_TRUE(maybe_receipt.has_value());
            auto& rec = maybe_receipt.value();
            prom.set_value(rec);
        },
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type,
        true);
    ASSERT_TRUE(agent->exec());
    res = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(res, std::future_status::ready);

    receipt = fut.get();
    ASSERT_TRUE(receipt.m_tx.m_to.has_value());
    ASSERT_EQ(receipt.m_tx.m_to.value(), contract_addr);

    auto output = evmc::uint256be();
    ASSERT_EQ(receipt.m_output_data.size(), sizeof(output));
    std::memcpy(output.bytes,
                receipt.m_output_data.data(),
                receipt.m_output_data.size());
    auto exp = evmc::uint256be(42);
    ASSERT_EQ(output, exp);
}

TEST_F(evm_test, rlp_serialize_length_test) {
    auto buf = cbdc::buffer();
    auto ser = cbdc::buffer_serializer(buf);
    serialize_rlp_length(ser, 0, 0x80);
    serialize_rlp_length(ser, 25, 0x80);
    serialize_rlp_length(ser, 55, 0x80);
    serialize_rlp_length(ser, 255, 0x80);
    serialize_rlp_length(ser, 65535, 0x80);
    auto expected = cbdc::buffer::from_hex("8099b7b8ffb9ffff").value();
    ASSERT_EQ(expected, buf);
}

TEST_F(evm_test, rlp_serialize_buffer_test) {
    auto dummy_addr
        = cbdc::buffer::from_hex("f2fd57a860750107b19eff5a94ad4ce24e69da11")
              .value();
    auto dummy = evmc::address();
    std::memcpy(dummy.bytes, dummy_addr.data(), dummy_addr.size());
    auto rlp_val = cbdc::make_rlp_value(dummy);

    auto buf = cbdc::buffer();
    auto ser = cbdc::buffer_serializer(buf);
    ser << rlp_val;

    auto expected
        = cbdc::buffer::from_hex("94f2fd57a860750107b19eff5a94ad4ce24e69da11")
              .value();
    ASSERT_EQ(expected, buf);
}

TEST_F(evm_test, keccak_test) {
    auto hash_input = cbdc::buffer::from_hex("48656c6c6f20576f726c64").value();
    auto result = cbdc::keccak_data(hash_input.data(), hash_input.size());
    auto expected_hash
        = cbdc::buffer::from_hex("592fa743889fc7f92ac2a37bb1f5ba1daf2a5c84741c"
                                 "a0e0061d243a2e6707ba")
              .value();
    cbdc::hash_t expected;
    std::memcpy(expected.data(), expected_hash.data(), expected_hash.size());
    ASSERT_EQ(result, expected);
}

TEST_F(evm_test, rlp_serialize_array_test) {
    auto dummy_addr
        = cbdc::buffer::from_hex("fefd57a860750107b19eff5a94ad4ce24e69da11")
              .value();
    auto dummy = evmc::address();
    std::memcpy(dummy.bytes, dummy_addr.data(), dummy_addr.size());
    auto rlp_val = cbdc::make_rlp_value(dummy);
    auto rlp_arr
        = cbdc::make_rlp_array(rlp_val, rlp_val, rlp_val, rlp_val, rlp_val);

    auto buf = cbdc::buffer();
    auto ser = cbdc::buffer_serializer(buf);
    ser << rlp_arr;

    auto expected
        = cbdc::buffer::from_hex(
              "f86994fefd57a860750107b19eff5a94ad4ce24e69da1194fefd57a86075010"
              "7b19eff5a94ad4ce24e69da1194fefd57a860750107b19eff5a94ad4ce24e69"
              "da1194fefd57a860750107b19eff5a94ad4ce24e69da1194fefd57a86075010"
              "7b19eff5a94ad4ce24e69da11")
              .value();
    ASSERT_EQ(expected, buf);
}

TEST_F(evm_test, contract_address_test) {
    auto expected = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "8d1ec7694e13bf51041920b5cf4e1668b0e267a9");
    ASSERT_EQ(
        expected,
        cbdc::threepc::agent::runner::contract_address(m_addr1_addr,
                                                       evmc::uint256be(1)));
}

/// Tests contract address for CREATE2 based on Example 5 from EIP-1014:
/// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1014.md
TEST_F(evm_test, contract_address2_test) {
    auto contract_code = cbdc::buffer::from_hex(
                             "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                             "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                             .value();

    auto contract_code_hash
        = cbdc::keccak_data(contract_code.data(), contract_code.size());

    auto salt = cbdc::buffer::from_hex("00000000000000000000000000000000000000"
                                       "000000000000000000cafebabe")
                    .value();
    auto sender
        = cbdc::buffer::from_hex("00000000000000000000000000000000deadbeef")
              .value();
    auto sender_addr = evmc::address();
    std::memcpy(sender_addr.bytes, sender.data(), sender.size());

    auto salt_bytes = evmc::bytes32();
    std::memcpy(salt_bytes.bytes, salt.data(), salt.size());

    auto expected_addr
        = cbdc::buffer::from_hex("1d8bfdc5d46dc4f61d6b6115972536ebe6a8854c")
              .value();
    auto expected = evmc::address();
    std::memcpy(expected.bytes, expected_addr.data(), expected_addr.size());

    ASSERT_EQ(
        expected,
        cbdc::threepc::agent::runner::contract_address2(sender_addr,
                                                        salt_bytes,
                                                        contract_code_hash));
}

TEST_F(evm_test, sighash_check) {
    // Values from https://ethereum.stackexchange.com/a/47984
    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_nonce = evmc::uint256be(0);
    tx->m_gas_price = evmc::uint256be(50000000000);
    tx->m_gas_limit = evmc::uint256be(21000);
    tx->m_to = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "7917bc33eea648809c285607579c9919fb864f8f");
    tx->m_value = evmc::uint256be(1050000000000000);

    auto expected_hash
        = cbdc::buffer::from_hex("a4060d01d4add248db470b4121616cbe5b2015daf328"
                                 "809000ec9a1d0954d649")
              .value();
    cbdc::hash_t expected;
    std::memcpy(expected.data(), expected_hash.data(), expected_hash.size());

    ASSERT_EQ(expected,
              cbdc::threepc::agent::runner::sig_hash(tx, default_chain_id));
}

TEST_F(evm_test, address_test) {
    cbdc::privkey_t priv;
    auto priv_buf = cbdc::buffer::from_hex("e7327b67184ab4239959b6628186a075ab"
                                           "ee983094141e530ac3684520862098")
                        .value();
    std::memcpy(priv.data(), priv_buf.data(), priv.size());
    auto expected_addr = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "92ecb2f4d3280b94b583f54af9177fd7ef9fe845");
    auto addr = cbdc::threepc::agent::runner::eth_addr(priv, m_secp_context);
    ASSERT_EQ(addr, expected_addr);
}

TEST_F(evm_test, signature_check) {
    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_nonce = evmc::uint256be(0);
    tx->m_gas_price = evmc::uint256be(50000000000);
    tx->m_gas_limit = evmc::uint256be(21000);
    tx->m_to = m_addr1_addr;
    tx->m_from = m_addr0_addr;

    tx->m_value = evmc::uint256be(1050000000000000);

    auto sighash
        = cbdc::threepc::agent::runner::sig_hash(tx, default_chain_id);
    tx->m_sig = cbdc::threepc::agent::runner::eth_sign(m_priv0,
                                                       sighash,
                                                       tx->m_type,
                                                       default_chain_id,
                                                       m_secp_context);

    ASSERT_TRUE(cbdc::threepc::agent::runner::check_signature(tx,
                                                              default_chain_id,
                                                              m_secp_context));
    tx->m_sig.m_r = evmc::uint256be(0);
    ASSERT_FALSE(
        cbdc::threepc::agent::runner::check_signature(tx,
                                                      default_chain_id,
                                                      m_secp_context));
}

// from: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-155.md#example
TEST_F(evm_test, signature_check_2) {
    cbdc::privkey_t priv;
    auto priv_bytes
        = cbdc::buffer::from_hex("46464646464646464646464646464646464646464646"
                                 "46464646464646464646")
              .value();
    std::memcpy(priv.data(), priv_bytes.data(), priv_bytes.size());

    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_from = cbdc::threepc::agent::runner::eth_addr(priv, m_secp_context);
    tx->m_to = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "3535353535353535353535353535353535353535");
    tx->m_nonce = evmc::uint256be(9);
    tx->m_gas_price = evmc::uint256be(20000000000);
    tx->m_gas_limit = evmc::uint256be(21000);

    auto val_bytes = cbdc::buffer::from_hex("000000000000000000000000000000000"
                                            "0000000000000000de0b6b3a7640000")
                         .value();
    std::memcpy(tx->m_value.bytes, val_bytes.data(), val_bytes.size());

    tx->m_sig.m_v = evmc::uint256be(37);

    auto r_bytes = cbdc::buffer::from_hex("766263aa200659e163ff713c5da1e103608"
                                          "6677553fe9521bc39d90b3461ef28")
                       .value();
    auto s_bytes = cbdc::buffer::from_hex("836d3b6a96b17f294b2164dcf3c955f5cc0"
                                          "0384b3003b7ec1a767f99d8e9cb67")
                       .value();

    std::memcpy(tx->m_sig.m_r.bytes, r_bytes.data(), r_bytes.size());
    std::memcpy(tx->m_sig.m_s.bytes, s_bytes.data(), s_bytes.size());

    auto sighash
        = cbdc::threepc::agent::runner::sig_hash(tx, default_chain_id);
    auto sig = cbdc::threepc::agent::runner::eth_sign(priv,
                                                      sighash,
                                                      tx->m_type,
                                                      default_chain_id,
                                                      m_secp_context);

    ASSERT_EQ(tx->m_sig.m_r, sig.m_r);
    ASSERT_EQ(tx->m_sig.m_s, sig.m_s);
    ASSERT_EQ(tx->m_sig.m_v, sig.m_v);

    ASSERT_TRUE(cbdc::threepc::agent::runner::check_signature(tx,
                                                              default_chain_id,
                                                              m_secp_context));
}

// From the Box.store example of hardhat
// https://docs.openzeppelin.com/learn/deploying-and-interacting
TEST_F(evm_test, signature_check_3) {
    static constexpr uint64_t hardhat_chain_id = 31337;
    cbdc::privkey_t priv;
    auto priv_bytes
        = cbdc::buffer::from_hex("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed"
                                 "5efcae784d7bf4f2ff80")
              .value();
    std::memcpy(priv.data(), priv_bytes.data(), priv_bytes.size());

    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_from = cbdc::threepc::agent::runner::eth_addr(priv, m_secp_context);

    tx->m_to = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "5FbDB2315678afecb367f032d93F642f64180aa3");
    tx->m_nonce = evmc::uint256be(1);
    tx->m_gas_price = evmc::uint256be(766614414);
    tx->m_gas_tip_cap = evmc::uint256be(0);
    tx->m_gas_fee_cap = evmc::uint256be(970246367);
    tx->m_gas_limit = evmc::uint256be(44915);
    tx->m_type = cbdc::threepc::agent::runner::evm_tx_type::dynamic_fee;

    auto input_bytes
        = cbdc::buffer::from_hex("6057361d000000000000000000000000000000000000"
                                 "000000000000000000000000002a")
              .value();
    tx->m_input = std::vector<uint8_t>();
    tx->m_input.resize(input_bytes.size());
    std::memcpy(tx->m_input.data(), input_bytes.data(), input_bytes.size());

    tx->m_value = evmc::uint256be(0);

    tx->m_sig.m_v = evmc::uint256be(1);

    auto r_bytes = cbdc::buffer::from_hex("4557c7824a3fc7c7519af4a13d0f47e74fd"
                                          "84d7e144d2684c72d3ca47e953da9")
                       .value();
    auto s_bytes = cbdc::buffer::from_hex("98e68f815d764b8fd341f0b6e82cd67c3be"
                                          "6ff4405d1a37b90678c2305f46a25")
                       .value();

    std::memcpy(tx->m_sig.m_r.bytes, r_bytes.data(), r_bytes.size());
    std::memcpy(tx->m_sig.m_s.bytes, s_bytes.data(), s_bytes.size());

    auto sighash
        = cbdc::threepc::agent::runner::sig_hash(tx, hardhat_chain_id);
    auto sig = cbdc::threepc::agent::runner::eth_sign(priv,
                                                      sighash,
                                                      tx->m_type,
                                                      hardhat_chain_id,
                                                      m_secp_context);

    ASSERT_EQ(tx->m_sig.m_r, sig.m_r);
    ASSERT_EQ(tx->m_sig.m_s, sig.m_s);
    ASSERT_EQ(tx->m_sig.m_v, sig.m_v);

    ASSERT_TRUE(cbdc::threepc::agent::runner::check_signature(tx,
                                                              hardhat_chain_id,
                                                              m_secp_context));
}

// Using TX 0xb4b7a6679ab790549dc3324a7239a6bf7a87ffd4c4c092df523a5b0697763db7
TEST_F(evm_test, test_encode_tx_legacy) {
    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_from = cbdc::threepc::agent::runner::from_hex<evmc::address>(
                     "0x5699bb600962bc92cb874b2d5c73bb5d502a42ce")
                     .value();
    tx->m_to = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "0xf8d3d485f86228a653d58903a2bf956fab7cd9d3");
    tx->m_value = evmc::uint256be(72967931316403995);
    tx->m_nonce = evmc::uint256be(6);
    tx->m_gas_price = evmc::uint256be(63800000000); // 63.8 GWei
    tx->m_gas_limit = evmc::uint256be(21000);

    tx->m_sig.m_v = evmc::uint256be(37);
    tx->m_sig.m_r = evmc::uint256be(0);
    tx->m_sig.m_s = evmc::uint256be(0);

    auto r_bytes = cbdc::buffer::from_hex("4c7437092b6606aef7865971bde4cf7f8a4"
                                          "41bc084979ba6b008211000f18492")
                       .value();
    auto s_bytes = cbdc::buffer::from_hex("6f308c16e2cec1d768e6c20e3688eb4972a"
                                          "2afaf36be7fba3be44e8639c77a19")
                       .value();

    std::memcpy(tx->m_sig.m_r.bytes, r_bytes.data(), r_bytes.size());
    std::memcpy(tx->m_sig.m_s.bytes, s_bytes.data(), s_bytes.size());

    auto buf = cbdc::threepc::agent::runner::tx_encode(tx, 1);

    // https://etherscan.io/getRawTx?tx=
    // 0xb4b7a6679ab790549dc3324a7239a6bf7a87ffd4c4c092df523a5b0697763db7
    auto expected = cbdc::buffer::from_hex(
        "f86c06850edac6be0082520894f8d3d485f86228a653d58903a2bf956fab7cd9d3880"
        "1033bf26a1bff1b8025a04c7437092b6606aef7865971bde4cf7f8a441bc084979ba6"
        "b008211000f18492a06f308c16e2cec1d768e6c20e3688eb4972a2afaf36be7fba3be"
        "44e8639c77a19");

    ASSERT_EQ(buf, expected);

    auto tx_id = cbdc::threepc::agent::runner::tx_id(tx, 1);
    auto expected_id_buf
        = cbdc::buffer::from_hex("b4b7a6679ab790549dc3324a7239a6bf7a87ffd4c4c0"
                                 "92df523a5b0697763db7")
              .value();
    auto expected_id = cbdc::hash_t();

    std::memcpy(expected_id.data(),
                expected_id_buf.data(),
                expected_id_buf.size());

    ASSERT_EQ(tx_id, expected_id);
}

// Using TX 0x7169cc1d3b1bd3b8379d69b2f0490330cfcb98b019a9c607b48d99b9d44dedde
TEST_F(evm_test, test_encode_tx_dynamic_fee) {
    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_type = cbdc::threepc::agent::runner::evm_tx_type::dynamic_fee;
    tx->m_from = cbdc::threepc::agent::runner::from_hex<evmc::address>(
                     "0x236139118b84bd2594051b0b2424f7ebca27a282")
                     .value();
    tx->m_to = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "0xcfef8857e9c80e3440a823971420f7fa5f62f020");
    tx->m_value = evmc::uint256be(0);
    tx->m_nonce = evmc::uint256be(1051);
    tx->m_gas_fee_cap = evmc::uint256be(51396523910); // 51.39652391 GWei
    tx->m_gas_tip_cap = evmc::uint256be(1500000000);  // 1.5 GWei
    tx->m_gas_price = evmc::uint256be(45095785012);   // 45.095785012 GWei
    tx->m_gas_limit = evmc::uint256be(51735);

    auto input_bytes = cbdc::buffer::from_hex(
                           "a9059cbb000000000000000000000000c8803d21a704bfebdb"
                           "c394bd16501a4b36ad3a2d0000000000000000000000000000"
                           "00000000000000000003747202a5f45fdaa8")
                           .value();
    tx->m_input = std::vector<uint8_t>();
    tx->m_input.resize(input_bytes.size());
    std::memcpy(tx->m_input.data(), input_bytes.data(), input_bytes.size());

    tx->m_sig.m_v = evmc::uint256be(1);
    tx->m_sig.m_r = evmc::uint256be(0);
    tx->m_sig.m_s = evmc::uint256be(0);

    auto s_bytes = cbdc::buffer::from_hex("43aa1bff7ee82b5e3415fed5225ec081b9f"
                                          "e2ce15db5c09ae9d624cc0790a464")
                       .value();
    auto r_bytes = cbdc::buffer::from_hex("39cb2a30ae0bb582c6e2a2f976905d00e9c"
                                          "5a451204c1daffb9c6e332a21c527")
                       .value();

    std::memcpy(tx->m_sig.m_r.bytes, r_bytes.data(), r_bytes.size());
    std::memcpy(tx->m_sig.m_s.bytes, s_bytes.data(), s_bytes.size());

    auto buf = cbdc::threepc::agent::runner::tx_encode(tx, 1);

    // https://etherscan.io/getRawTx?tx=
    // 0x7169cc1d3b1bd3b8379d69b2f0490330cfcb98b019a9c607b48d99b9d44dedde
    auto expected = cbdc::buffer::from_hex(
        "02f8b20182041b8459682f00850bf778b78682ca1794cfef8857e9c80e3440a823971"
        "420f7fa5f62f02080b844a9059cbb000000000000000000000000c8803d21a704bfeb"
        "dbc394bd16501a4b36ad3a2d000000000000000000000000000000000000000000000"
        "003747202a5f45fdaa8c001a039cb2a30ae0bb582c6e2a2f976905d00e9c5a451204c"
        "1daffb9c6e332a21c527a043aa1bff7ee82b5e3415fed5225ec081b9fe2ce15db5c09"
        "ae9d624cc0790a464");

    ASSERT_EQ(buf, expected);

    auto tx_id = cbdc::threepc::agent::runner::tx_id(tx, 1);
    auto expected_id_buf
        = cbdc::buffer::from_hex("7169cc1d3b1bd3b8379d69b2f0490330cfcb98b019a9"
                                 "c607b48d99b9d44dedde")
              .value();
    auto expected_id = cbdc::hash_t();

    std::memcpy(expected_id.data(),
                expected_id_buf.data(),
                expected_id_buf.size());

    ASSERT_EQ(tx_id, expected_id);
}

// Using TX 0x2695ed62cf8cb7759d651c43dc28ffc1dd6a26103841c223721b081b55f4d0b5
TEST_F(evm_test, test_encode_tx_access_list) {
    auto tx = std::make_shared<cbdc::threepc::agent::runner::evm_tx>();
    tx->m_type = cbdc::threepc::agent::runner::evm_tx_type::access_list;
    tx->m_from = cbdc::threepc::agent::runner::from_hex<evmc::address>(
                     "0x000000007cb2bd00ae5eb839930bb7847ae5b039")
                     .value();
    tx->m_to = cbdc::threepc::agent::runner::from_hex<evmc::address>(
        "0x11b1f53204d03e5529f09eb3091939e4fd8c9cf3");
    tx->m_value = evmc::uint256be(0);
    tx->m_nonce = evmc::uint256be(24084);
    tx->m_gas_price = evmc::uint256be(911752427978); // 911.752427978 GWei
    tx->m_gas_limit = evmc::uint256be(565146);

    tx->m_access_list.push_back(cbdc::threepc::agent::runner::evm_access_tuple{
        cbdc::threepc::agent::runner::from_hex<evmc::address>(
            "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
            .value(),
        std::vector<evmc::bytes32>{
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "2ee79dc23d6c13edb1608e2e16eee0e5fe994c46c052a"
                "900ce432a6a733faa88")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "6eeabe5c63f3d0417dd0e83521a7158c1403fd1857156"
                "a1663d93ddd5ce324ad")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "32f00a85f22bf566874963d108eef7a5849bdc0aff29f"
                "d9e4fba7a4ca9b25972")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "4bea0bbbfe1207d935c3c22ccdd4c0e9d76cba8d9249a"
                "d821f2d207045b3cba6")
                .value()}});

    tx->m_access_list.push_back(cbdc::threepc::agent::runner::evm_access_tuple{
        cbdc::threepc::agent::runner::from_hex<evmc::address>(
            "0x0f5d2fb29fb7d3cfee444a200298f468908cc942")
            .value(),
        std::vector<evmc::bytes32>{
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "149301982a2541c22d14e4a7edde07d33766add09e919"
                "225c441856470a1f9b7")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "0958fe90732c073894bbab469409b16bbadc3b80f6d04"
                "a5d3b19436654d47636")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "000000000000000000000000000000000000000000000"
                "0000000000000000003")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "74cece5c9a88511447f6977a207255d8267a1b70f8ea4"
                "62864df11f2e32d3f3f")
                .value()}});

    tx->m_access_list.push_back(cbdc::threepc::agent::runner::evm_access_tuple{
        cbdc::threepc::agent::runner::from_hex<evmc::address>(
            "0x8661ae7918c0115af9e3691662f605e9c550ddc9")
            .value(),
        std::vector<evmc::bytes32>{
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "c626a27156226a4e7a2efc9720ec5bfb2e17309513243"
                "2577475fab25f4ee221")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "000000000000000000000000000000000000000000000"
                "0000000000000000000")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "c626a27156226a4e7a2efc9720ec5bfb2e17309513243"
                "2577475fab25f4ee223")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "c626a27156226a4e7a2efc9720ec5bfb2e17309513243"
                "2577475fab25f4ee224")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "9b637a02e6f8cc8aa1e3935c0b27bde663b11428c7707"
                "039634076a3fb8a0c48")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "000000000000000000000000000000000000000000000"
                "0000000000000000001")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "000000000000000000000000000000000000000000000"
                "0000000000000000002")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "c626a27156226a4e7a2efc9720ec5bfb2e17309513243"
                "2577475fab25f4ee222")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "000000000000000000000000000000000000000000000"
                "0000000000000000004")
                .value(),
            cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                "000000000000000000000000000000000000000000000"
                "0000000000000000008")
                .value()}});

    tx->m_access_list.push_back(cbdc::threepc::agent::runner::evm_access_tuple{
        cbdc::threepc::agent::runner::from_hex<evmc::address>(
            "0x230000377650db9ca400d3fdff49000076852100")
            .value(),
        std::vector<evmc::bytes32>{}});

    auto input_bytes
        = cbdc::buffer::from_hex(
              "022c0d9f0000000000000000000000000000000000000000000004902e37004"
              "6efc47d66000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000230000377650db9ca400d3fdff490"
              "000768521000000000000000000000000000000000000000000000000000000"
              "000000000080000000000000000000000000000000000000000000000000000"
              "000000000007c8661ae7918c0115af9e3691662f605e9c550ddc90f5d2fb29f"
              "b7d3cfee444a200298f468908cc942c02aaa39b223fe8d0a0e5c4f27ead9083"
              "c756cc20000000000000000000000000000000000000000000000004c9b4d61"
              "92749ec7000000000000000000000000000000000000000000000000029d25c"
              "ab783fb5900000000")
              .value();
    tx->m_input = std::vector<uint8_t>();
    tx->m_input.resize(input_bytes.size());
    std::memcpy(tx->m_input.data(), input_bytes.data(), input_bytes.size());

    tx->m_sig.m_v = evmc::uint256be(0);
    tx->m_sig.m_r = evmc::uint256be(0);
    tx->m_sig.m_s = evmc::uint256be(0);

    auto s_bytes = cbdc::buffer::from_hex("0e39381a67a32a4625b11821180b4129184"
                                          "f9dd9cff410eed7f0360bbddef05f")
                       .value();
    auto r_bytes = cbdc::buffer::from_hex("35f32a35698e10055162c49e941ea7c1117"
                                          "5da87f2910d3474a2e22df92908f0")
                       .value();

    std::memcpy(tx->m_sig.m_r.bytes, r_bytes.data(), r_bytes.size());
    std::memcpy(tx->m_sig.m_s.bytes, s_bytes.data(), s_bytes.size());

    auto buf = cbdc::threepc::agent::runner::tx_encode(tx, 1);

    // https://etherscan.io/getRawTx?tx=
    // 0x2695ed62cf8cb7759d651c43dc28ffc1dd6a26103841c223721b081b55f4d0b5
    auto expected = cbdc::buffer::from_hex(
        "01f9044701825e1485d448adf9ca83089f9a9411b1f53204d03e5529f09eb3091939e"
        "4fd8c9cf380b90124022c0d9f00000000000000000000000000000000000000000000"
        "04902e370046efc47d660000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000230000377650db9ca400d3fdff4900"
        "007685210000000000000000000000000000000000000000000000000000000000000"
        "00080000000000000000000000000000000000000000000000000000000000000007c"
        "8661ae7918c0115af9e3691662f605e9c550ddc90f5d2fb29fb7d3cfee444a200298f"
        "468908cc942c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000"
        "0000000000000000000000000000004c9b4d6192749ec700000000000000000000000"
        "0000000000000000000000000029d25cab783fb5900000000f902b6f89b94c02aaa39"
        "b223fe8d0a0e5c4f27ead9083c756cc2f884a02ee79dc23d6c13edb1608e2e16eee0e"
        "5fe994c46c052a900ce432a6a733faa88a06eeabe5c63f3d0417dd0e83521a7158c14"
        "03fd1857156a1663d93ddd5ce324ada032f00a85f22bf566874963d108eef7a5849bd"
        "c0aff29fd9e4fba7a4ca9b25972a04bea0bbbfe1207d935c3c22ccdd4c0e9d76cba8d"
        "9249ad821f2d207045b3cba6f89b940f5d2fb29fb7d3cfee444a200298f468908cc94"
        "2f884a0149301982a2541c22d14e4a7edde07d33766add09e919225c441856470a1f9"
        "b7a00958fe90732c073894bbab469409b16bbadc3b80f6d04a5d3b19436654d47636a"
        "00000000000000000000000000000000000000000000000000000000000000003a074"
        "cece5c9a88511447f6977a207255d8267a1b70f8ea462864df11f2e32d3f3ff901629"
        "48661ae7918c0115af9e3691662f605e9c550ddc9f9014aa0c626a27156226a4e7a2e"
        "fc9720ec5bfb2e173095132432577475fab25f4ee221a000000000000000000000000"
        "00000000000000000000000000000000000000000a0c626a27156226a4e7a2efc9720"
        "ec5bfb2e173095132432577475fab25f4ee223a0c626a27156226a4e7a2efc9720ec5"
        "bfb2e173095132432577475fab25f4ee224a09b637a02e6f8cc8aa1e3935c0b27bde6"
        "63b11428c7707039634076a3fb8a0c48a000000000000000000000000000000000000"
        "00000000000000000000000000001a000000000000000000000000000000000000000"
        "00000000000000000000000002a0c626a27156226a4e7a2efc9720ec5bfb2e1730951"
        "32432577475fab25f4ee222a000000000000000000000000000000000000000000000"
        "00000000000000000004a000000000000000000000000000000000000000000000000"
        "00000000000000008d694230000377650db9ca400d3fdff49000076852100c080a035"
        "f32a35698e10055162c49e941ea7c11175da87f2910d3474a2e22df92908f0a00e393"
        "81a67a32a4625b11821180b4129184f9dd9cff410eed7f0360bbddef05f");

    ASSERT_EQ(buf, expected);

    auto tx_id = cbdc::threepc::agent::runner::tx_id(tx, 1);
    auto expected_id_buf
        = cbdc::buffer::from_hex("2695ed62cf8cb7759d651c43dc28ffc1dd6a26103841"
                                 "c223721b081b55f4d0b5")
              .value();
    auto expected_id = cbdc::hash_t();

    std::memcpy(expected_id.data(),
                expected_id_buf.data(),
                expected_id_buf.size());

    ASSERT_EQ(tx_id, expected_id);
}

TEST_F(evm_test, decode_rlp_test) {
    auto buf
        = cbdc::buffer::from_hex(
              "f907fe84deadbeef80849502f900849502f90082ffff8080b907a2608060405"
              "234801561001057600080fd5b5061002d61002261003260201b60201c565b61"
              "003a60201b60201c565b6100fe565b600033905090565b60008060009054906"
              "101000a900473ffffffffffffffffffffffffffffffffffffffff1690508160"
              "00806101000a81548173ffffffffffffffffffffffffffffffffffffffff021"
              "916908373ffffffffffffffffffffffffffffffffffffffff16021790555081"
              "73ffffffffffffffffffffffffffffffffffffffff168173fffffffffffffff"
              "fffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419"
              "497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b610"
              "6958061010d6000396000f3fe608060405234801561001057600080fd5b5060"
              "0436106100575760003560e01c80632e64cec11461005c5780636057361d146"
              "1007a578063715018a6146100965780638da5cb5b146100a0578063f2fde38b"
              "146100be575b600080fd5b6100646100da565b6040516100719190610551565"
              "b60405180910390f35b610094600480360381019061008f9190610469565b61"
              "00e4565b005b61009e6101a1565b005b6100a8610229565b6040516100b5919"
              "06104f6565b60405180910390f35b6100d860048036038101906100d3919061"
              "0440565b610252565b005b6000600154905090565b6100ec61034a565b73fff"
              "fffffffffffffffffffffffffffffffffffff1661010a610229565b73ffffff"
              "ffffffffffffffffffffffffffffffffff1614610160576040517f08c379a00"
              "000000000000000000000000000000000000000000000000000000081526004"
              "0161015790610531565b60405180910390fd5b806001819055507f93fe6d397"
              "c74fdf1402a8b72e47b68512f0510d7b98a4bc4cbdf6ac7108b3c5981604051"
              "6101969190610551565b60405180910390a150565b6101a961034a565b73fff"
              "fffffffffffffffffffffffffffffffffffff166101c7610229565b73ffffff"
              "ffffffffffffffffffffffffffffffffff161461021d576040517f08c379a00"
              "000000000000000000000000000000000000000000000000000000081526004"
              "0161021490610531565b60405180910390fd5b6102276000610352565b565b6"
              "0008060009054906101000a900473ffffffffffffffffffffffffffffffffff"
              "ffffff16905090565b61025a61034a565b73fffffffffffffffffffffffffff"
              "fffffffffffff16610278610229565b73ffffffffffffffffffffffffffffff"
              "ffffffffff16146102ce576040517f08c379a00000000000000000000000000"
              "000000000000000000000000000000081526004016102c590610531565b6040"
              "5180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168"
              "173ffffffffffffffffffffffffffffffffffffffff16141561033e57604051"
              "7f08c379a000000000000000000000000000000000000000000000000000000"
              "000815260040161033590610511565b60405180910390fd5b61034781610352"
              "565b50565b600033905090565b60008060009054906101000a900473fffffff"
              "fffffffffffffffffffffffffffffffff169050816000806101000a81548173"
              "ffffffffffffffffffffffffffffffffffffffff021916908373fffffffffff"
              "fffffffffffffffffffffffffffff1602179055508173ffffffffffffffffff"
              "ffffffffffffffffffffff168173fffffffffffffffffffffffffffffffffff"
              "fffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b418"
              "6f6b6457e060405160405180910390a35050565b60008135905061042581610"
              "631565b92915050565b60008135905061043a81610648565b92915050565b60"
              "006020828403121561045257600080fd5b600061046084828501610416565b9"
              "1505092915050565b60006020828403121561047b57600080fd5b6000610489"
              "8482850161042b565b91505092915050565b61049b8161057d565b825250505"
              "65b60006104ae60268361056c565b91506104b9826105b9565b604082019050"
              "919050565b60006104d160208361056c565b91506104dc82610608565b60208"
              "2019050919050565b6104f0816105af565b82525050565b6000602082019050"
              "61050b6000830184610492565b92915050565b6000602082019050818103600"
              "083015261052a816104a1565b9050919050565b600060208201905081810360"
              "0083015261054a816104c4565b9050919050565b60006020820190506105666"
              "0008301846104e7565b92915050565b60008282526020820190509291505056"
              "5b60006105888261058f565b9050919050565b600073fffffffffffffffffff"
              "fffffffffffffffffffff82169050919050565b6000819050919050565b7f4f"
              "776e61626c653a206e6577206f776e657220697320746865207a65726f20616"
              "0008201527f6464726573730000000000000000000000000000000000000000"
              "000000000000602082015250565b7f4f776e61626c653a2063616c6c6572206"
              "973206e6f7420746865206f776e6572600082015250565b61063a8161057d56"
              "5b811461064557600080fd5b50565b610651816105af565b811461065c57600"
              "080fd5b5056fea2646970667358221220d1d385c015549fffb510dbf5df48c9"
              "f7404bfa5d2fc9bb7c0784d513dc5859c464736f6c63430008040033c080a0e"
              "59e41867aff575475a70db3087c24832b24180d062c950834d7a213f8344ed4"
              "a042189bf1bdde1893eda33d837ea7c1a0e36914ccf7255c3b8878171dd3ebe"
              "023")
              .value();
    auto deser = cbdc::buffer_serializer(buf);
    auto rlp_value = cbdc::rlp_value(cbdc::rlp_value_type::array);
    deser >> rlp_value;
    ASSERT_EQ(rlp_value.type(), cbdc::rlp_value_type::array);
    ASSERT_EQ(rlp_value.size(), 12);
}

// Using TX 0xb4b7a6679ab790549dc3324a7239a6bf7a87ffd4c4c092df523a5b0697763db7
TEST_F(evm_test, test_decode_tx_legacy) {
    // https://etherscan.io/getRawTx?tx=
    // 0xb4b7a6679ab790549dc3324a7239a6bf7a87ffd4c4c092df523a5b0697763db7
    auto input = cbdc::buffer::from_hex("f86c06850edac6be0082520894f8d3d485f86"
                                        "228a653d58903a2bf956fab7cd9d3880"
                                        "1033bf26a1bff1b8025a04c7437092b6606ae"
                                        "f7865971bde4cf7f8a441bc084979ba6"
                                        "b008211000f18492a06f308c16e2cec1d768e"
                                        "6c20e3688eb4972a2afaf36be7fba3be"
                                        "44e8639c77a19")
                     .value();

    auto maybe_tx = cbdc::threepc::agent::runner::tx_decode(input, 1);
    ASSERT_TRUE(maybe_tx.has_value());
    auto tx = maybe_tx.value();
    ASSERT_TRUE(tx->m_to.has_value());
    ASSERT_EQ(tx->m_to.value(),
              cbdc::threepc::agent::runner::from_hex<evmc::address>(
                  "0xf8d3d485f86228a653d58903a2bf956fab7cd9d3"));
    ASSERT_EQ(tx->m_value, evmc::uint256be(72967931316403995));
    ASSERT_EQ(tx->m_nonce, evmc::uint256be(6));
    ASSERT_EQ(tx->m_gas_price, evmc::uint256be(63800000000)); // 63.8 GWei
    ASSERT_EQ(tx->m_gas_limit, evmc::uint256be(21000));

    ASSERT_EQ(tx->m_sig.m_v, evmc::uint256be(37));

    auto expected_m_r = evmc::uint256be(0);
    auto expected_m_s = evmc::uint256be(0);

    auto r_bytes = cbdc::buffer::from_hex("4c7437092b6606aef7865971bde4cf7f8a4"
                                          "41bc084979ba6b008211000f18492")
                       .value();
    auto s_bytes = cbdc::buffer::from_hex("6f308c16e2cec1d768e6c20e3688eb4972a"
                                          "2afaf36be7fba3be44e8639c77a19")
                       .value();

    std::memcpy(expected_m_r.bytes, r_bytes.data(), r_bytes.size());
    std::memcpy(expected_m_s.bytes, s_bytes.data(), s_bytes.size());

    ASSERT_EQ(tx->m_sig.m_r, expected_m_r);
    ASSERT_EQ(tx->m_sig.m_s, expected_m_s);

    // TODO: decode from from signature recovery
    /*ASSERT_EQ(tx->m_from(),
       cbdc::threepc::agent::runner::from_hex<evmc::address>(
                     "0x5699bb600962bc92cb874b2d5c73bb5d502a42ce")
                     .value());*/
}

// Using TX 0x7169cc1d3b1bd3b8379d69b2f0490330cfcb98b019a9c607b48d99b9d44dedde
TEST_F(evm_test, test_decode_tx_dynamic_fee) {
    // https://etherscan.io/getRawTx?tx=
    // 0x7169cc1d3b1bd3b8379d69b2f0490330cfcb98b019a9c607b48d99b9d44dedde
    auto input = cbdc::buffer::from_hex("02f8b20182041b8459682f00850bf778b7868"
                                        "2ca1794cfef8857e9c80e3440a823971"
                                        "420f7fa5f62f02080b844a9059cbb00000000"
                                        "0000000000000000c8803d21a704bfeb"
                                        "dbc394bd16501a4b36ad3a2d0000000000000"
                                        "00000000000000000000000000000000"
                                        "003747202a5f45fdaa8c001a039cb2a30ae0b"
                                        "b582c6e2a2f976905d00e9c5a451204c"
                                        "1daffb9c6e332a21c527a043aa1bff7ee82b5"
                                        "e3415fed5225ec081b9fe2ce15db5c09"
                                        "ae9d624cc0790a464")
                     .value();

    auto maybe_tx = cbdc::threepc::agent::runner::tx_decode(input, 1);
    ASSERT_TRUE(maybe_tx.has_value());
    auto tx = maybe_tx.value();
    ASSERT_EQ(tx->m_type,
              cbdc::threepc::agent::runner::evm_tx_type::dynamic_fee);

    ASSERT_TRUE(tx->m_to.has_value());
    ASSERT_EQ(tx->m_to.value(),
              cbdc::threepc::agent::runner::from_hex<evmc::address>(
                  "0xcfef8857e9c80e3440a823971420f7fa5f62f020"));
    ASSERT_EQ(tx->m_value, evmc::uint256be(0));
    ASSERT_EQ(tx->m_nonce, evmc::uint256be(1051));
    ASSERT_EQ(tx->m_gas_fee_cap,
              evmc::uint256be(51396523910)); // 51.39652391 GWei
    ASSERT_EQ(tx->m_gas_tip_cap, evmc::uint256be(1500000000)); // 1.5 GWei
    ASSERT_EQ(tx->m_gas_limit, evmc::uint256be(51735));

    auto expected_input
        = cbdc::buffer::from_hex(
              "a9059cbb000000000000000000000000c8803d21a704bfebdb"
              "c394bd16501a4b36ad3a2d0000000000000000000000000000"
              "00000000000000000003747202a5f45fdaa8")
              .value();

    auto tx_input = cbdc::buffer();
    tx_input.extend(tx->m_input.size());
    std::memcpy(tx_input.data(), tx->m_input.data(), tx->m_input.size());
    ASSERT_EQ(tx_input, expected_input);

    ASSERT_EQ(tx->m_sig.m_v, evmc::uint256be(1));
    auto expected_m_r = evmc::uint256be(0);
    auto expected_m_s = evmc::uint256be(0);

    auto s_bytes = cbdc::buffer::from_hex("43aa1bff7ee82b5e3415fed5225ec081b9f"
                                          "e2ce15db5c09ae9d624cc0790a464")
                       .value();
    auto r_bytes = cbdc::buffer::from_hex("39cb2a30ae0bb582c6e2a2f976905d00e9c"
                                          "5a451204c1daffb9c6e332a21c527")
                       .value();

    std::memcpy(expected_m_r.bytes, r_bytes.data(), r_bytes.size());
    std::memcpy(expected_m_s.bytes, s_bytes.data(), s_bytes.size());

    ASSERT_EQ(expected_m_r, tx->m_sig.m_r);
    ASSERT_EQ(expected_m_s, tx->m_sig.m_s);
}

// Using TX 0x2695ed62cf8cb7759d651c43dc28ffc1dd6a26103841c223721b081b55f4d0b5
TEST_F(evm_test, test_decode_tx_access_list) {
    // https://etherscan.io/getRawTx?tx=
    // 0x2695ed62cf8cb7759d651c43dc28ffc1dd6a26103841c223721b081b55f4d0b5
    auto input
        = cbdc::buffer::from_hex(
              "01f9044701825e1485d448adf9ca83089f9a9411b1f53204d03e5529f09eb30"
              "91939e"
              "4fd8c9cf380b90124022c0d9f00000000000000000000000000000000000000"
              "000000"
              "04902e370046efc47d660000000000000000000000000000000000000000000"
              "000000"
              "000000000000000000000000000000000000000230000377650db9ca400d3fd"
              "ff4900"
              "007685210000000000000000000000000000000000000000000000000000000"
              "000000"
              "000800000000000000000000000000000000000000000000000000000000000"
              "00007c"
              "8661ae7918c0115af9e3691662f605e9c550ddc90f5d2fb29fb7d3cfee444a2"
              "00298f"
              "468908cc942c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000"
              "000000"
              "0000000000000000000000000000004c9b4d6192749ec700000000000000000"
              "000000"
              "0000000000000000000000000029d25cab783fb5900000000f902b6f89b94c0"
              "2aaa39"
              "b223fe8d0a0e5c4f27ead9083c756cc2f884a02ee79dc23d6c13edb1608e2e1"
              "6eee0e"
              "5fe994c46c052a900ce432a6a733faa88a06eeabe5c63f3d0417dd0e83521a7"
              "158c14"
              "03fd1857156a1663d93ddd5ce324ada032f00a85f22bf566874963d108eef7a"
              "5849bd"
              "c0aff29fd9e4fba7a4ca9b25972a04bea0bbbfe1207d935c3c22ccdd4c0e9d7"
              "6cba8d"
              "9249ad821f2d207045b3cba6f89b940f5d2fb29fb7d3cfee444a200298f4689"
              "08cc94"
              "2f884a0149301982a2541c22d14e4a7edde07d33766add09e919225c4418564"
              "70a1f9"
              "b7a00958fe90732c073894bbab469409b16bbadc3b80f6d04a5d3b19436654d"
              "47636a"
              "000000000000000000000000000000000000000000000000000000000000000"
              "03a074"
              "cece5c9a88511447f6977a207255d8267a1b70f8ea462864df11f2e32d3f3ff"
              "901629"
              "48661ae7918c0115af9e3691662f605e9c550ddc9f9014aa0c626a27156226a"
              "4e7a2e"
              "fc9720ec5bfb2e173095132432577475fab25f4ee221a000000000000000000"
              "000000"
              "00000000000000000000000000000000000000000a0c626a27156226a4e7a2e"
              "fc9720"
              "ec5bfb2e173095132432577475fab25f4ee223a0c626a27156226a4e7a2efc9"
              "720ec5"
              "bfb2e173095132432577475fab25f4ee224a09b637a02e6f8cc8aa1e3935c0b"
              "27bde6"
              "63b11428c7707039634076a3fb8a0c48a000000000000000000000000000000"
              "000000"
              "00000000000000000000000000001a000000000000000000000000000000000"
              "000000"
              "00000000000000000000000002a0c626a27156226a4e7a2efc9720ec5bfb2e1"
              "730951"
              "32432577475fab25f4ee222a000000000000000000000000000000000000000"
              "000000"
              "00000000000000000004a000000000000000000000000000000000000000000"
              "000000"
              "00000000000000008d694230000377650db9ca400d3fdff49000076852100c0"
              "80a035"
              "f32a35698e10055162c49e941ea7c11175da87f2910d3474a2e22df92908f0a"
              "00e393"
              "81a67a32a4625b11821180b4129184f9dd9cff410eed7f0360bbddef05f")
              .value();

    auto maybe_tx = cbdc::threepc::agent::runner::tx_decode(input, 1);
    ASSERT_TRUE(maybe_tx.has_value());
    auto tx = maybe_tx.value();
    ASSERT_EQ(tx->m_type,
              cbdc::threepc::agent::runner::evm_tx_type::access_list);

    ASSERT_EQ(tx->m_to,
              cbdc::threepc::agent::runner::from_hex<evmc::address>(
                  "0x11b1f53204d03e5529f09eb3091939e4fd8c9cf3"));
    ASSERT_EQ(tx->m_value, evmc::uint256be(0));
    ASSERT_EQ(tx->m_nonce, evmc::uint256be(24084));
    ASSERT_EQ(tx->m_gas_price,
              evmc::uint256be(911752427978)); // 911.752427978 GWei
    ASSERT_EQ(tx->m_gas_limit, evmc::uint256be(565146));

    auto expected_access_list
        = cbdc::threepc::agent::runner::evm_access_list();
    expected_access_list.push_back(
        cbdc::threepc::agent::runner::evm_access_tuple{
            cbdc::threepc::agent::runner::from_hex<evmc::address>(
                "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
                .value(),
            std::vector<evmc::bytes32>{
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "2ee79dc23d6c13edb1608e2e16eee0e5fe994c46c052a"
                    "900ce432a6a733faa88")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "6eeabe5c63f3d0417dd0e83521a7158c1403fd1857156"
                    "a1663d93ddd5ce324ad")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "32f00a85f22bf566874963d108eef7a5849bdc0aff29f"
                    "d9e4fba7a4ca9b25972")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "4bea0bbbfe1207d935c3c22ccdd4c0e9d76cba8d9249a"
                    "d821f2d207045b3cba6")
                    .value()}});

    expected_access_list.push_back(
        cbdc::threepc::agent::runner::evm_access_tuple{
            cbdc::threepc::agent::runner::from_hex<evmc::address>(
                "0x0f5d2fb29fb7d3cfee444a200298f468908cc942")
                .value(),
            std::vector<evmc::bytes32>{
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "149301982a2541c22d14e4a7edde07d33766add09e919"
                    "225c441856470a1f9b7")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "0958fe90732c073894bbab469409b16bbadc3b80f6d04"
                    "a5d3b19436654d47636")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "000000000000000000000000000000000000000000000"
                    "0000000000000000003")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "74cece5c9a88511447f6977a207255d8267a1b70f8ea4"
                    "62864df11f2e32d3f3f")
                    .value()}});

    expected_access_list.push_back(
        cbdc::threepc::agent::runner::evm_access_tuple{
            cbdc::threepc::agent::runner::from_hex<evmc::address>(
                "0x8661ae7918c0115af9e3691662f605e9c550ddc9")
                .value(),
            std::vector<evmc::bytes32>{
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "c626a27156226a4e7a2efc9720ec5bfb2e17309513243"
                    "2577475fab25f4ee221")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "000000000000000000000000000000000000000000000"
                    "0000000000000000000")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "c626a27156226a4e7a2efc9720ec5bfb2e17309513243"
                    "2577475fab25f4ee223")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "c626a27156226a4e7a2efc9720ec5bfb2e17309513243"
                    "2577475fab25f4ee224")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "9b637a02e6f8cc8aa1e3935c0b27bde663b11428c7707"
                    "039634076a3fb8a0c48")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "000000000000000000000000000000000000000000000"
                    "0000000000000000001")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "000000000000000000000000000000000000000000000"
                    "0000000000000000002")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "c626a27156226a4e7a2efc9720ec5bfb2e17309513243"
                    "2577475fab25f4ee222")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "000000000000000000000000000000000000000000000"
                    "0000000000000000004")
                    .value(),
                cbdc::threepc::agent::runner::from_hex<evmc::bytes32>(
                    "000000000000000000000000000000000000000000000"
                    "0000000000000000008")
                    .value()}});

    expected_access_list.push_back(
        cbdc::threepc::agent::runner::evm_access_tuple{
            cbdc::threepc::agent::runner::from_hex<evmc::address>(
                "0x230000377650db9ca400d3fdff49000076852100")
                .value(),
            std::vector<evmc::bytes32>{}});

    ASSERT_EQ(tx->m_access_list, expected_access_list);

    auto expected_input
        = cbdc::buffer::from_hex(
              "022c0d9f0000000000000000000000000000000000000000000004902e37004"
              "6efc47d66000000000000000000000000000000000000000000000000000000"
              "0000000000000000000000000000000000230000377650db9ca400d3fdff490"
              "000768521000000000000000000000000000000000000000000000000000000"
              "000000000080000000000000000000000000000000000000000000000000000"
              "000000000007c8661ae7918c0115af9e3691662f605e9c550ddc90f5d2fb29f"
              "b7d3cfee444a200298f468908cc942c02aaa39b223fe8d0a0e5c4f27ead9083"
              "c756cc20000000000000000000000000000000000000000000000004c9b4d61"
              "92749ec7000000000000000000000000000000000000000000000000029d25c"
              "ab783fb5900000000")
              .value();
    auto tx_input = cbdc::buffer();
    tx_input.extend(tx->m_input.size());
    std::memcpy(tx_input.data(), tx->m_input.data(), tx->m_input.size());
    ASSERT_EQ(tx_input, expected_input);

    ASSERT_EQ(tx->m_sig.m_v, evmc::uint256be(0));

    auto expected_m_r = evmc::uint256be(0);
    auto expected_m_s = evmc::uint256be(0);

    auto s_bytes = cbdc::buffer::from_hex("0e39381a67a32a4625b11821180b4129184"
                                          "f9dd9cff410eed7f0360bbddef05f")
                       .value();
    auto r_bytes = cbdc::buffer::from_hex("35f32a35698e10055162c49e941ea7c1117"
                                          "5da87f2910d3474a2e22df92908f0")
                       .value();

    std::memcpy(expected_m_r.bytes, r_bytes.data(), r_bytes.size());
    std::memcpy(expected_m_s.bytes, s_bytes.data(), s_bytes.size());

    ASSERT_EQ(tx->m_sig.m_r, expected_m_r);
    ASSERT_EQ(tx->m_sig.m_s, expected_m_s);

    auto buf = cbdc::threepc::agent::runner::tx_encode(tx, 1);

    // https://etherscan.io/getRawTx?tx=
    // 0x2695ed62cf8cb7759d651c43dc28ffc1dd6a26103841c223721b081b55f4d0b5
    auto expected = cbdc::buffer::from_hex(
        "01f9044701825e1485d448adf9ca83089f9a9411b1f53204d03e5529f09eb3091939e"
        "4fd8c9cf380b90124022c0d9f00000000000000000000000000000000000000000000"
        "04902e370046efc47d660000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000230000377650db9ca400d3fdff4900"
        "007685210000000000000000000000000000000000000000000000000000000000000"
        "00080000000000000000000000000000000000000000000000000000000000000007c"
        "8661ae7918c0115af9e3691662f605e9c550ddc90f5d2fb29fb7d3cfee444a200298f"
        "468908cc942c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000"
        "0000000000000000000000000000004c9b4d6192749ec700000000000000000000000"
        "0000000000000000000000000029d25cab783fb5900000000f902b6f89b94c02aaa39"
        "b223fe8d0a0e5c4f27ead9083c756cc2f884a02ee79dc23d6c13edb1608e2e16eee0e"
        "5fe994c46c052a900ce432a6a733faa88a06eeabe5c63f3d0417dd0e83521a7158c14"
        "03fd1857156a1663d93ddd5ce324ada032f00a85f22bf566874963d108eef7a5849bd"
        "c0aff29fd9e4fba7a4ca9b25972a04bea0bbbfe1207d935c3c22ccdd4c0e9d76cba8d"
        "9249ad821f2d207045b3cba6f89b940f5d2fb29fb7d3cfee444a200298f468908cc94"
        "2f884a0149301982a2541c22d14e4a7edde07d33766add09e919225c441856470a1f9"
        "b7a00958fe90732c073894bbab469409b16bbadc3b80f6d04a5d3b19436654d47636a"
        "00000000000000000000000000000000000000000000000000000000000000003a074"
        "cece5c9a88511447f6977a207255d8267a1b70f8ea462864df11f2e32d3f3ff901629"
        "48661ae7918c0115af9e3691662f605e9c550ddc9f9014aa0c626a27156226a4e7a2e"
        "fc9720ec5bfb2e173095132432577475fab25f4ee221a000000000000000000000000"
        "00000000000000000000000000000000000000000a0c626a27156226a4e7a2efc9720"
        "ec5bfb2e173095132432577475fab25f4ee223a0c626a27156226a4e7a2efc9720ec5"
        "bfb2e173095132432577475fab25f4ee224a09b637a02e6f8cc8aa1e3935c0b27bde6"
        "63b11428c7707039634076a3fb8a0c48a000000000000000000000000000000000000"
        "00000000000000000000000000001a000000000000000000000000000000000000000"
        "00000000000000000000000002a0c626a27156226a4e7a2efc9720ec5bfb2e1730951"
        "32432577475fab25f4ee222a000000000000000000000000000000000000000000000"
        "00000000000000000004a000000000000000000000000000000000000000000000000"
        "00000000000000008d694230000377650db9ca400d3fdff49000076852100c080a035"
        "f32a35698e10055162c49e941ea7c11175da87f2910d3474a2e22df92908f0a00e393"
        "81a67a32a4625b11821180b4129184f9dd9cff410eed7f0360bbddef05f");

    ASSERT_EQ(buf, expected);

    auto tx_id = cbdc::threepc::agent::runner::tx_id(tx, 1);
    auto expected_id_buf
        = cbdc::buffer::from_hex("2695ed62cf8cb7759d651c43dc28ffc1dd6a26103841"
                                 "c223721b081b55f4d0b5")
              .value();
    auto expected_id = cbdc::hash_t();

    std::memcpy(expected_id.data(),
                expected_id_buf.data(),
                expected_id_buf.size());

    ASSERT_EQ(tx_id, expected_id);

    /* TODO: From calculation & assertion

        tx->m_from = cbdc::threepc::agent::runner::from_hex<evmc::address>(
                     "0x000000007cb2bd00ae5eb839930bb7847ae5b039")
                     .value();
    */
}
