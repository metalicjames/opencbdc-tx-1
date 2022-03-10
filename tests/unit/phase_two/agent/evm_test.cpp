// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "../util.hpp"
#include "3pc/agent/impl.hpp"
#include "3pc/agent/runners/evm/format.hpp"
#include "3pc/agent/runners/evm/impl.hpp"
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
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type);
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
        {});
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
        {});
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
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type);
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
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type);
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
              "50565b61072e8061010d6000396000f3fe60806040523480156100105760008"
              "0fd5b50600436106100575760003560e01c80632e64cec11461005c57806360"
              "57361d1461007a578063715018a6146100965780638da5cb5b146100a057806"
              "3f2fde38b146100be575b600080fd5b6100646100da565b6040516100719190"
              "610565565b60405180910390f35b610094600480360381019061008f9190610"
              "47d565b6100e4565b005b61009e6101b5565b005b6100a861023d565b604051"
              "6100b5919061050a565b60405180910390f35b6100d86004803603810190610"
              "0d39190610454565b610266565b005b6000600154905090565b6100ec61035e"
              "565b73ffffffffffffffffffffffffffffffffffffffff1661010a61023d565"
              "b73ffffffffffffffffffffffffffffffffffffffff1614610160576040517f"
              "08c379a00000000000000000000000000000000000000000000000000000000"
              "0815260040161015790610545565b60405180910390fd5b8060016000828254"
              "6101729190610591565b925050819055507f93fe6d397c74fdf1402a8b72e47"
              "b68512f0510d7b98a4bc4cbdf6ac7108b3c596001546040516101aa91906105"
              "65565b60405180910390a150565b6101bd61035e565b73fffffffffffffffff"
              "fffffffffffffffffffffff166101db61023d565b73ffffffffffffffffffff"
              "ffffffffffffffffffff1614610231576040517f08c379a0000000000000000"
              "000000000000000000000000000000000000000008152600401610228906105"
              "45565b60405180910390fd5b61023b6000610366565b565b600080600090549"
              "06101000a900473ffffffffffffffffffffffffffffffffffffffff16905090"
              "565b61026e61035e565b73ffffffffffffffffffffffffffffffffffffffff1"
              "661028c61023d565b73ffffffffffffffffffffffffffffffffffffffff1614"
              "6102e2576040517f08c379a0000000000000000000000000000000000000000"
              "0000000000000000081526004016102d990610545565b60405180910390fd5b"
              "600073ffffffffffffffffffffffffffffffffffffffff168173fffffffffff"
              "fffffffffffffffffffffffffffff161415610352576040517f08c379a00000"
              "000000000000000000000000000000000000000000000000000081526004016"
              "1034990610525565b60405180910390fd5b61035b81610366565b50565b6000"
              "33905090565b60008060009054906101000a900473fffffffffffffffffffff"
              "fffffffffffffffffff169050816000806101000a81548173ffffffffffffff"
              "ffffffffffffffffffffffffff021916908373fffffffffffffffffffffffff"
              "fffffffffffffff1602179055508173ffffffffffffffffffffffffffffffff"
              "ffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be00"
              "79c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e06040"
              "5160405180910390a35050565b600081359050610439816106ca565b9291505"
              "0565b60008135905061044e816106e1565b92915050565b6000602082840312"
              "1561046657600080fd5b60006104748482850161042a565b915050929150505"
              "65b60006020828403121561048f57600080fd5b600061049d8482850161043f"
              "565b91505092915050565b6104af816105e7565b82525050565b60006104c26"
              "02683610580565b91506104cd82610652565b604082019050919050565b6000"
              "6104e5602083610580565b91506104f0826106a1565b6020820190509190505"
              "65b61050481610619565b82525050565b600060208201905061051f60008301"
              "846104a6565b92915050565b6000602082019050818103600083015261053e8"
              "16104b5565b9050919050565b6000602082019050818103600083015261055e"
              "816104d8565b9050919050565b600060208201905061057a60008301846104f"
              "b565b92915050565b600082825260208201905092915050565b600061059c82"
              "610619565b91506105a783610619565b9250827ffffffffffffffffffffffff"
              "fffffffffffffffffffffffffffffffffffffffff038211156105dc576105db"
              "610623565b5b828201905092915050565b60006105f2826105f9565b9050919"
              "050565b600073ffffffffffffffffffffffffffffffffffffffff8216905091"
              "9050565b6000819050919050565b7f4e487b710000000000000000000000000"
              "0000000000000000000000000000000600052601160045260246000fd5b7f4f"
              "776e61626c653a206e6577206f776e657220697320746865207a65726f20616"
              "0008201527f6464726573730000000000000000000000000000000000000000"
              "000000000000602082015250565b7f4f776e61626c653a2063616c6c6572206"
              "973206e6f7420746865206f776e6572600082015250565b6106d3816105e756"
              "5b81146106de57600080fd5b50565b6106ea81610619565b81146106f557600"
              "080fd5b5056fea2646970667358221220d0c3b60ee6083564db3ad5a89d12f5"
              "c0563368ad3fdf8724972fc58f0927999864736f6c63430008040033")
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

    auto prom = std::promise<void>();
    auto fut = prom.get_future();
    auto agent = std::make_shared<cbdc::threepc::agent::impl>(
        m_log,
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
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type);
    ASSERT_TRUE(agent->exec());
    auto res = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(res, std::future_status::ready);

    auto contract_addr
        = cbdc::buffer::from_hex("72b10bc92b3a94ea79e79d34258aa76b66722ad1")
              .value();
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

    prom = std::promise<void>();
    fut = prom.get_future();
    agent = std::make_shared<cbdc::threepc::agent::impl>(
        m_log,
        &cbdc::threepc::agent::runner::factory<
            cbdc::threepc::agent::runner::evm_runner>::create,
        m_broker,
        m_addr1,
        params,
        [&](const cbdc::threepc::agent::interface::exec_return_type& r) {
            ASSERT_TRUE(
                std::holds_alternative<cbdc::threepc::agent::return_type>(r));
            prom.set_value();
        },
        cbdc::threepc::agent::runner::evm_runner::initial_lock_type);
    ASSERT_TRUE(agent->exec());
    res = fut.wait_for(std::chrono::seconds(2));
    ASSERT_EQ(res, std::future_status::ready);
}
