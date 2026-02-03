// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.17;

import "./RedstoneConsumerBase.sol";

/**
 * @title The base contract for Redstone consumers' contracts that allows to
 * securely calculate numeric redstone oracle values
 * @author The Redstone Oracles team
 * @dev This contract can extend other contracts to allow them
 * securely fetch Redstone oracle data from transactions calldata
 */
// 该合约继承了RedstoneConsumerBase，当你的业务合约是使用redstone喂上来的数字时（uint256），适用于代币价格、利率、波动率等。可继承该合约。
// 当多个节点报的价格不一致时，通过中位数来滤掉坏点，取一个统计学上的中间值。
abstract contract RedstoneConsumerNumericBase is RedstoneConsumerBase {
    /**
     * @dev This function can be used in a consumer contract to securely extract an
     * oracle value for a given data feed id. Security is achieved by
     * signatures verification, timestamp validation, and aggregating values
     * from different authorised signers into a single numeric value. If any of the
     * required conditions do not match, the function will revert.
     * Note! This function expects that tx calldata contains redstone payload in the end
     * Learn more about redstone payload here: https://github.com/redstone-finance/redstone-oracles-monorepo/tree/main/packages/evm-connector#readme
     * @param dataFeedId bytes32 value that uniquely identifies the data feed
     * @return Extracted and verified numeric oracle value for the given data feed id
     */
    // 支持单feed id解析单value。
    // 注：内部包含了数据包统一时间戳有效性的验证
    function getOracleNumericValueFromTxMsg(
        bytes32 dataFeedId
    ) internal view virtual returns (uint256) {
        // 实际上就是对基础查询函数getOracleNumericValuesFromTxMsg()的一个封装
        bytes32[] memory dataFeedIds = new bytes32[](1);
        dataFeedIds[0] = dataFeedId;
        return getOracleNumericValuesFromTxMsg(dataFeedIds)[0];
    }

    /**
     * @dev This function can be used in a consumer contract to securely extract several
     * numeric oracle values for a given array of data feed ids. Security is achieved by
     * signatures verification, timestamp validation, and aggregating values
     * from different authorised signers into a single numeric value. If any of the
     * required conditions do not match, the function will revert.
     * Note! This function expects that tx calldata contains redstone payload in the end
     * Learn more about redstone payload here: https://github.com/redstone-finance/redstone-oracles-monorepo/tree/main/packages/evm-connector#readme
     * @param dataFeedIds An array of unique data feed identifiers
     * @return An array of the extracted and verified oracle values in the same order
     * as they are requested in the dataFeedIds array
     */
    // 最基础的查询函数，支持多feed ids解析多values。
    // 注：内部包含了数据包统一时间戳有效性的验证
    function getOracleNumericValuesFromTxMsg(
        bytes32[] memory dataFeedIds
    ) internal view virtual returns (uint256[] memory) {
        // 直接调用RedstoneConsumerBase._securelyExtractOracleValuesAndTimestampFromTxMsg方法
        (
            uint256[] memory values,
            uint256 timestamp
        ) = _securelyExtractOracleValuesAndTimestampFromTxMsg(dataFeedIds);
        // 验证该feed id的时间戳（数据包的统一时间戳）
        validateTimestamp(timestamp);
        // 返回目标feed ids的报价聚合值数组
        return values;
    }

    /**
     * @dev This function can be used in a consumer contract to securely extract several
     * numeric oracle values for a given array of data feed ids. Security is achieved by
     * signatures verification and aggregating values from different authorised signers
     * into a single numeric value. If any of the required conditions do not match,
     * the function will revert.
     * Note! This function returns the timestamp of the packages (it requires it to be
     * the same for all), but does not validate this timestamp.
     * Note! This function expects that tx calldata contains redstone payload in the end
     * Learn more about redstone payload here: https://github.com/redstone-finance/redstone-oracles-monorepo/tree/main/packages/evm-connector#readme
     * @param dataFeedIds An array of unique data feed identifiers
     * @return An array of the extracted and verified oracle values in the same order
     * as they are requested in the dataFeedIds array and data packages timestamp
     */
    // 最基础的查询函数，支持多feed ids解析多values+数据包统一时间戳，
    // 就是对_securelyExtractOracleValuesAndTimestampFromTxMsg的直接封装
    function getOracleNumericValuesAndTimestampFromTxMsg(
        bytes32[] memory dataFeedIds
    ) internal view virtual returns (uint256[] memory, uint256) {
        return _securelyExtractOracleValuesAndTimestampFromTxMsg(dataFeedIds);
    }

    /**
     * @dev This function works similarly to the `getOracleNumericValuesFromTxMsg` with the
     * only difference that it allows to request oracle data for an array of data feeds
     * that may contain duplicates
     *
     * @param dataFeedIdsWithDuplicates An array of data feed identifiers (duplicates are allowed)
     * @return An array of the extracted and verified oracle values in the same order
     * as they are requested in the dataFeedIdsWithDuplicates array
     */
    // 这个函数解决了一个核心痛点：如果用户的业务逻辑需要多次读取同一个feed id的价格（例如：在一个复杂的掉期合约里多次用到 ETH），重复解析 Calldata 和验证签名是非常昂贵的。
    // 参数：dataFeedIdsWithDuplicates：一个可能包含重复 ID 的数组（如 [ETH, BTC, ETH]），返回同样顺序的价格数组
    function getOracleNumericValuesWithDuplicatesFromTxMsg(
        bytes32[] memory dataFeedIdsWithDuplicates
    ) internal view returns (uint256[] memory) {
        // Building an array without duplicates
        // 去重准备，先定义一个跟dataFeedIdsWithDuplicates等长的数组，用于存放去重后的feed id
        bytes32[] memory dataFeedIdsWithoutDuplicates = new bytes32[](
            dataFeedIdsWithDuplicates.length
        );
        bool alreadyIncluded;
        // 用于记录dataFeedIdsWithoutDuplicates中已经存放了多少个不重复的feed id
        uint256 uniqueDataFeedIdsCount = 0;

        // 遍历dataFeedIdsWithDuplicates
        for (
            uint256 indexWithDup = 0;
            indexWithDup < dataFeedIdsWithDuplicates.length;
            indexWithDup++
        ) {
            // Checking if current element is already included in `dataFeedIdsWithoutDuplicates`
            // 先假设该feed id是没有存储在dataFeedIdsWithoutDuplicates中
            alreadyIncluded = false;
            // 对于入参中的每一个feed id（可能是重复的），去内存数组dataFeedIdsWithoutDuplicates（已经挑出来不重复的feed id）。如果没见过，就存进去
            // 注：这部分其实是一个经典的“手动去重”逻辑。因为 Solidity 的内存中没有像 Java 或 Python 那样现成的 Set数据结构，所以必须用最原始的嵌套循环来实现。
            // 为什么嵌套循环最省 Gas？
            // Mapping 只能在 Storage 中：如果我们在合约状态里开一个 mapping 来去重，每次读写都要几万 Gas，贵得离谱；
            // 在内存中，这种 O(N**2) 的操作对于 10 个以内的元素来说，消耗的 Gas 极其微小（几十到几百 Gas）。比起去调用一次昂贵的预言机数据提取（几万 Gas），这点开销简直可以忽略不计
            for (
                uint256 indexWithoutDup = 0;
                indexWithoutDup < uniqueDataFeedIdsCount;
                indexWithoutDup++
            ) {
                // dataFeedIdsWithoutDuplicates中存放的一定是不重复的feed id
                if (
                    // 一旦在dataFeedIdsWithoutDuplicates中找到了该feed id
                    dataFeedIdsWithoutDuplicates[indexWithoutDup] ==
                    dataFeedIdsWithDuplicates[indexWithDup]
                ) {
                    // 标记为该feed id已经在存储在dataFeedIdsWithoutDuplicates中了，跳出对dataFeedIdsWithoutDuplicates的遍历
                    alreadyIncluded = true;
                    break;
                }
            }

            // Adding if not included
            if (!alreadyIncluded) {
                // 如果该feed id没有出现在dataFeedIdsWithoutDuplicates中，直接存入dataFeedIdsWithoutDuplicates队尾
                dataFeedIdsWithoutDuplicates[
                    uniqueDataFeedIdsCount
                ] = dataFeedIdsWithDuplicates[indexWithDup];
                // uniqueDataFeedIdsCount表示dataFeedIdsWithoutDuplicates中feed id个数，自增1
                uniqueDataFeedIdsCount++;
            }
        }

        // Overriding dataFeedIdsWithoutDuplicates.length
        // Equivalent to: dataFeedIdsWithoutDuplicates.length = uniqueDataFeedIdsCount;
        // 此时，dataFeedIdsWithoutDuplicates已经存储着去重后的feed id，但是dataFeedIdsWithoutDuplicates在内存中的长度还是去重前大小
        assembly {
            // 将dataFeedIdsWithoutDuplicates在内存中的长度修改为uniqueDataFeedIdsCount
            mstore(dataFeedIdsWithoutDuplicates, uniqueDataFeedIdsCount)
        }

        // Requesting oracle values (without duplicates)
        // 使用去重后的dataFeedIdsWithoutDuplicates作为目标feed ids，调用RedstoneConsumerBase._securelyExtractOracleValuesAndTimestampFromTxMsg方法
        (
            uint256[] memory valuesWithoutDuplicates,
            uint256 timestamp
        ) = _securelyExtractOracleValuesAndTimestampFromTxMsg(
                dataFeedIdsWithoutDuplicates
            );
        // 验证数据包统一时间戳的有效性
        validateTimestamp(timestamp);

        // Preparing result values array
        // 结果重组：将结果，按照dataFeedIdsWithDuplicates的feed id的顺序，重新组成一个数字数组
        // 先在内存中初始化一个同dataFeedIdsWithDuplicates等长的uint256数组
        uint256[] memory valuesWithDuplicates = new uint256[](
            dataFeedIdsWithDuplicates.length
        );
        // 开始遍历含有重复feed id的dataFeedIdsWithDuplicates
        for (
            uint256 indexWithDup = 0;
            indexWithDup < dataFeedIdsWithDuplicates.length;
            indexWithDup++
        ) {
            // 对于每一个dataFeedIdsWithDuplicates中的feed id，都去不含重复feed id的dataFeedIdsWithoutDuplicates中遍历一遍
            for (
                uint256 indexWithoutDup = 0;
                indexWithoutDup < dataFeedIdsWithoutDuplicates.length;
                indexWithoutDup++
            ) {
                // 如果两者匹配上了
                if (
                    dataFeedIdsWithDuplicates[indexWithDup] ==
                    dataFeedIdsWithoutDuplicates[indexWithoutDup]
                ) {
                    // 将valuesWithoutDuplicates[indexWithoutDup]的值写入valuesWithDuplicates[indexWithDup]
                    valuesWithDuplicates[
                        indexWithDup
                    ] = valuesWithoutDuplicates[indexWithoutDup];
                    // 跳出内部的循环，继续处理下一个feed id（可能重复的）
                    break;
                }
            }
        }

        // 返回重组后的value数组
        return valuesWithDuplicates;
    }
}
