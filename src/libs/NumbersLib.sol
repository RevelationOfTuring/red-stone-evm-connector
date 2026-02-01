// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

// NumbersLib 是一个非常典型的“位拆分”工具库。它的核心逻辑是将一个 256 位的 uint256 变量，
// 横向切分成两个 128 位的较小整数。
library NumbersLib {
    uint256 constant BITS_COUNT_IN_16_BYTES = 128;

    // 获取高 128 位
    function getNumberFromFirst16Bytes(
        uint256 number
    ) internal pure returns (uint256) {
        return uint256(number >> BITS_COUNT_IN_16_BYTES);
    }

    // 获取低 128 位
    function getNumberFromLast16Bytes(
        uint256 number
    ) internal pure returns (uint256) {
        // 更省gas的方案：注：在 Solidity 0.8.0 之后，uint128(number) 这种向下转型（Downcasting）确实包含溢出检查
        // assembly {
        // // 使用 128 位的掩码直接提取
        //     result := and(number, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        // }
        return
            uint256(
                (number << BITS_COUNT_IN_16_BYTES) >> BITS_COUNT_IN_16_BYTES
            );
    }
}
