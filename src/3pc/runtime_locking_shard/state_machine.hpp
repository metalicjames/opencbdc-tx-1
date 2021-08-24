// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_RUNTIME_LOCKING_SHARD_STATE_MACHINE_H_
#define CBDC_UNIVERSE0_SRC_3PC_RUNTIME_LOCKING_SHARD_STATE_MACHINE_H_

#include "impl.hpp"
#include "messages.hpp"
#include "util/common/logging.hpp"
#include "util/rpc/blocking_batch_server.hpp"

#include <libnuraft/nuraft.hxx>

namespace cbdc::threepc::runtime_locking_shard {
    /// NuRaft state machine implementation for a runtime locking shard.
    class state_machine : public nuraft::state_machine,
                          public cbdc::rpc::blocking_batch_server<
                              rpc::request,
                              rpc::response,
                              nuraft::buffer&,
                              nuraft::ptr<nuraft::buffer>> {
      public:
        /// Constructor.
        /// \param logger log instance.
        explicit state_machine(std::shared_ptr<logging::log> logger);

        /// Commit the given raft log entry at the given log index, and return
        /// the result.
        /// \param log_idx raft log index of the log entry.
        /// \param data serialized RPC request.
        /// \return serialized RPC response or nullptr if there was an error
        ///         processing the request.
        auto commit(uint64_t log_idx, nuraft::buffer& data)
            -> nuraft::ptr<nuraft::buffer> override;

        /// Not implemented for runtime locking shard.
        /// \return false.
        auto apply_snapshot(nuraft::snapshot& /* s */) -> bool override;

        /// Not implemented for runtime locking shard.
        /// \return nullptr.
        auto last_snapshot() -> nuraft::ptr<nuraft::snapshot> override;

        /// Returns the most recently committed log entry index.
        /// \return log entry index.
        auto last_commit_index() -> uint64_t override;

        /// Not implemented for runtime locking shard.
        void create_snapshot(
            nuraft::snapshot& /* s */,
            nuraft::async_result<bool>::handler_type& /* when_done */)
            override;

      private:
        void process_request(request_type req);

        std::atomic<uint64_t> m_last_committed_idx{0};

        std::unique_ptr<impl> m_shard{};

        std::shared_ptr<logging::log> m_logger;

        std::vector<response_type> m_responses;
    };
}

#endif
