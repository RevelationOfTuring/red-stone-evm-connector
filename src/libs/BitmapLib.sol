// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

// 在智能合约开发中，Bitmap 是一种极致的 Gas 优化技术。它的核心思想是：利用一个 uint256 变量的 256 个二进制位，像开关一样存储 256 个布尔值（true/false）
// 相比于使用 bool[] 数组或 mapping(uint256 => bool)，位图可以节省超过 90% 的存储成本
// 使用场景：
// 1. 比如你有 256 个币对，你想一键开启或关闭其中的某些币对，用 Bitmap 只需要一次 SSTORE 就能更新所有状态；
// 2. 节点去重： 当多个节点（Nodes）喂价时，给每个节点分配一个 ID (0-255)。你可以用一个 uint256 记录哪些节点已经提交了。如果 getBitFromBitmap(submittedBitmap, nodeId) 为 true，就拒绝该节点的重复提交。这样只需一个存储插槽就能记录 256 个节点的状态。
library BitmapLib {
    // 将 bitmap 中指定索引 bitIndex 的位置设为 1（即 true）
    function setBitInBitmap(
        uint256 bitmap,
        uint256 bitIndex
    ) internal pure returns (uint256) {
        return bitmap | (1 << bitIndex);
    }

    // 是检查 bitmap 中指定索引 bitIndex 的位置是 0 还是 1
    function getBitFromBitmap(
        uint256 bitmap,
        uint256 bitIndex
    ) internal pure returns (bool) {
        uint256 bitAtIndex = bitmap & (1 << bitIndex);
        return bitAtIndex > 0;
    }
}
