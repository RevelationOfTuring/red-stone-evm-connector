// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.17;

import "../libs/NumericArrayLib.sol";

/**
 * @title Default implementations of virtual redstone consumer base functions
 * @author The Redstone Oracles team
 */

// 该库是Redstone 消费端（Consumer）的最后一道防线。它用来判断：
// 1. 数据是否太旧（或超前）？
// 2. 以及当有多个数据源时，以哪个为准？
library RedstoneDefaultsLib {
    // 为了防止“过期数据攻击”。如果预言机节点签发的价格是 3 分钟之前的，会被认为数据过旧
    uint256 constant DEFAULT_MAX_DATA_TIMESTAMP_DELAY_SECONDS = 3 minutes;
    // 由于后端服务的时间戳是实时的，而链上时间戳会略慢于实时时间戳（大约会延迟一个出块时间），所以当时间戳超越本链上时钟大于1分钟，会被认为有问题
    uint256 constant DEFAULT_MAX_DATA_TIMESTAMP_AHEAD_SECONDS = 1 minutes;

    error TimestampFromTooLongFuture(
        uint256 receivedTimestampSeconds,
        uint256 blockTimestamp
    );
    error TimestampIsTooOld(
        uint256 receivedTimestampSeconds,
        uint256 blockTimestamp
    );

    // 时间戳合规性检查
    function validateTimestamp(
        // 收到的时间戳，单位为毫秒
        uint256 receivedTimestampMilliseconds
    ) internal view {
        // Getting data timestamp from future seems quite unlikely
        // But we've already spent too much time with different cases
        // Where block.timestamp was less than dataPackage.timestamp.
        // Some blockchains may case this problem as well.
        // That's why we add MAX_BLOCK_TIMESTAMP_DELAY
        // and allow data "from future" but with a small delay
        // 将毫秒转为秒
        uint256 receivedTimestampSeconds = receivedTimestampMilliseconds / 1000;

        if (block.timestamp < receivedTimestampSeconds) {
            // 如果收到时间戳快于本链时间戳（未来时间戳）
            // 如果快过1min，revert
            if (
                (receivedTimestampSeconds - block.timestamp) >
                DEFAULT_MAX_DATA_TIMESTAMP_AHEAD_SECONDS
            ) {
                revert TimestampFromTooLongFuture(
                    receivedTimestampSeconds,
                    block.timestamp
                );
            }
        } else if (
            // 如果收到时间戳不快于本链时间戳
            (block.timestamp - receivedTimestampSeconds) >
            DEFAULT_MAX_DATA_TIMESTAMP_DELAY_SECONDS
        ) {
            // 如果落后本链时间戳3min，revert
            revert TimestampIsTooOld(receivedTimestampSeconds, block.timestamp);
        }
    }

    // 多数据源聚合。当 Redstone 配置了多个签名节点（例如 5 个节点分别报出不同的 ETH 价格）时，我们需要一个最终的价格。
    // 即取中位数
    function aggregateValues(
        uint256[] memory values
    ) internal pure returns (uint256) {
        return NumericArrayLib.pickMedian(values);
    }
}
