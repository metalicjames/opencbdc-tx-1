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
        nullptr);
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
        nullptr);
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
