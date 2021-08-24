// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_TRANSACTIONS_UTIL_H_
#define CBDC_UNIVERSE0_SRC_3PC_TRANSACTIONS_UTIL_H_

#include "3pc/broker/interface.hpp"

#include <memory>

namespace cbdc::threepc {
    /// Asynchronously inserts the given row into the cluster.
    /// \param broker broker to use for inserting the row.
    /// \param key key at which to insert value.
    /// \param value value to insert at given key.
    /// \param result_callback function to call on insertion success or
    ///                        failure.
    /// \return true if request was initiated successfully.
    auto put_row(const std::shared_ptr<broker::interface>& broker,
                 broker::key_type key,
                 broker::value_type value,
                 const std::function<void(bool)>& result_callback) -> bool;
}

#endif
