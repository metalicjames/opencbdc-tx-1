// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../util.hpp"
#include "3pc/agent/impl.hpp"
#include "3pc/agent/runners/evm/format.hpp"
#include "3pc/agent/runners/evm/hash.hpp"
#include "3pc/agent/runners/evm/impl.hpp"
#include "3pc/agent/runners/evm/rlp.hpp"
#include "3pc/agent/runners/evm/util.hpp"
#include "3pc/broker/impl.hpp"
#include "3pc/directory/impl.hpp"
#include "3pc/runtime_locking_shard/impl.hpp"
#include "3pc/ticket_machine/impl.hpp"

#include <future>
#include <gtest/gtest.h>
#include <thread>

class evm_test : public ::testing::Test {
  protected:
    void SetUp() override {
        m_addr0.append("a0", 2);
        m_addr0.extend(18);
        m_addr1.append("a1", 2);
        m_addr1.extend(18);
        m_addr2.append("a2", 2);
        m_addr2.extend(18);
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

    cbdc::buffer m_addr0;
    cbdc::buffer m_addr1;
    cbdc::buffer m_addr2;
};

TEST_F(evm_test, initial_test) {
    auto tx = cbdc::threepc::agent::runner::evm_tx();
    std::memcpy(tx.m_from.bytes, m_addr1.data(), m_addr1.size());
    tx.m_to = evmc::address();
    std::memcpy(tx.m_to->bytes, m_addr0.data(), m_addr0.size());
    tx.m_nonce = evmc::uint256be(1);
    tx.m_value = evmc::uint256be(1000);
    tx.m_gas_price = evmc::uint256be(1);
    tx.m_gas_limit = evmc::uint256be(200000);
    auto params = cbdc::make_buffer(tx);

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
    const auto addr2 = evmc::address{1};
    const auto addr3 = evmc::address{2};
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
    auto tx = cbdc::threepc::agent::runner::evm_tx();
    std::memcpy(tx.m_from.bytes, m_addr1.data(), m_addr1.size());
    tx.m_to = evmc::address();
    std::memcpy(tx.m_to->bytes, m_addr2.data(), m_addr2.size());
    tx.m_nonce = evmc::uint256be(1);
    tx.m_value = evmc::uint256be(1000);
    tx.m_gas_price = evmc::uint256be(1);
    tx.m_gas_limit = evmc::uint256be(21000);
    auto params = cbdc::make_buffer(tx);

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
    tx.m_gas_limit = evmc::uint256be(20999);
    tx.m_nonce = evmc::uint256be(2);
    params = cbdc::make_buffer(tx);
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

    auto tx = cbdc::threepc::agent::runner::evm_tx();
    std::memcpy(tx.m_from.bytes, m_addr1.data(), m_addr1.size());
    tx.m_nonce = evmc::uint256be(1);
    tx.m_value = evmc::uint256be(0);
    tx.m_gas_price = evmc::uint256be(1);
    tx.m_gas_limit = evmc::uint256be(100000);
    tx.m_input.resize(bytecode.size());
    std::memcpy(tx.m_input.data(), bytecode.data(), bytecode.size());
    auto params = cbdc::make_buffer(tx);

    auto deploy_txid = cbdc::threepc::agent::runner::tx_id(tx);

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

    auto contract_addr
        = cbdc::buffer::from_hex("bcfd57a860750107b19eff5a94ad4ce24e69da11")
              .value();

    auto receipt = fut.get();
    ASSERT_TRUE(receipt.m_create_address.has_value());
    auto addr_buf = cbdc::buffer();
    addr_buf.append(receipt.m_create_address->bytes,
                    sizeof(receipt.m_create_address->bytes));
    ASSERT_EQ(addr_buf, contract_addr);

    tx.m_to = evmc::address();
    std::memcpy(tx.m_to->bytes, contract_addr.data(), contract_addr.size());
    tx.m_nonce = evmc::uint256be(2);
    auto store_input
        = cbdc::buffer::from_hex("6057361d000000000000000000000000000000000000"
                                 "000000000000000000000000002a")
              .value();
    tx.m_input.resize(store_input.size());
    std::memcpy(tx.m_input.data(), store_input.data(), store_input.size());
    params = cbdc::make_buffer(tx);

    auto store_txid = cbdc::threepc::agent::runner::tx_id(tx);

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
    addr_buf.clear();
    addr_buf.append(receipt.m_tx.m_to->bytes,
                    sizeof(receipt.m_tx.m_to->bytes));
    ASSERT_EQ(addr_buf, contract_addr);

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
    auto exp_addr = evmc::address();
    std::memcpy(exp_addr.bytes, contract_addr.data(), contract_addr.size());
    ASSERT_EQ(l.m_addr, exp_addr);

    auto retrieve_input
        = cbdc::buffer::from_hex("2e64cec1000000000000000000000000000000000000"
                                 "0000000000000000000000000000")
              .value();
    tx.m_input.resize(retrieve_input.size());
    std::memcpy(tx.m_input.data(),
                retrieve_input.data(),
                retrieve_input.size());
    params = cbdc::make_buffer(tx);

    auto retrieve_txid = cbdc::threepc::agent::runner::tx_id(tx);

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
    addr_buf.clear();
    addr_buf.append(receipt.m_tx.m_to->bytes,
                    sizeof(receipt.m_tx.m_to->bytes));
    ASSERT_EQ(addr_buf, contract_addr);

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
    auto expected_addr
        = cbdc::buffer::from_hex("bcfd57a860750107b19eff5a94ad4ce24e69da11")
              .value();
    auto expected = evmc::address();
    std::memcpy(expected.bytes, expected_addr.data(), expected_addr.size());
    auto sender_addr = evmc::address();
    std::memcpy(sender_addr.bytes, m_addr1.data(), m_addr1.size());
    ASSERT_EQ(
        expected,
        cbdc::threepc::agent::runner::contract_address(sender_addr,
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
