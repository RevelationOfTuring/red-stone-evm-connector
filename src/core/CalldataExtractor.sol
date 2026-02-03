// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.17;

import "./RedstoneConstants.sol";

/**
 * @title The base contract with the main logic of data extraction from calldata
 * @author The Redstone Oracles team
 * @dev This contract was created to reuse the same logic in the RedstoneConsumerBase
 * and the ProxyConnector contracts
 */

// CalldataExtractor展示了如何通过操作底层汇编从 calldata 的末尾提取附加的预言机数据包。
//这种设计非常精妙：它不修改原始函数的参数，而是将数据“贴”在交易数据的最后，从而实现对任何函数的无缝预言机增强。
// Redstone 的数据布局是反向排列的。它的逻辑是：
// 1. 先看最后 9 字节的 Marker。
// 2. 往前读 Metadata（元数据）长度。
// 3. 再往前读 Data Packages Count（数据包数量）。
// 4. 最后循环读取每个 Data Package（数据包）。

// Calldata 中的位置布局：可以把Calldata 的末尾想象成这样（从右往左看）
// | 数据区段                   | 长度说明 |                说明
// | Marker                    | 9 字节  | 协议标识符（检查是否为 Redstone 数据）
// | Unsigned Metadata Size    | 3 字节  | 这里存的就是 unsignedMetadataByteSize 的数值
// | Unsigned Metadata Content | 变量 X  | 实际的元数据内容（长度由上面的字段指定）
// | Data Packages Count       | 2 字节  | 价格包的数量
// | Data Packages...          | 变量 Y  | 核心价格数据 + 时间戳 + 签名
contract CalldataExtractor is RedstoneConstants {
    error DataPackageTimestampMustNotBeZero();
    error DataPackageTimestampsMustBeEqual();
    error RedstonePayloadMustHaveAtLeastOneDataPackage();
    error TooLargeValueByteSize(uint256 valueByteSize);

    // 该函数是Redstone 协议的“安检站”，它遍历所有的预言机数据包，确保它们不仅真实存在，而且所有数据包的时间戳必须完全一致
    // 这是为了防止攻击者将“旧的价格包”和“新的价格包”混合在一起进行套利
    // 如果各个Data Package的时间戳都一致，返回该时间戳；如果有一个不一致，revert
    function extractTimestampsAndAssertAllAreEqual()
        public
        pure
        returns (uint256 extractedTimestamp)
    {
        // 得到Unsigned Metadata Content区域的负偏移量
        uint256 calldataNegativeOffset = _extractByteSizeOfUnsignedMetadata();
        // 向前解析，得到数据包个数dataPackagesCount和Data Packages Count开始的负偏移量
        uint256 dataPackagesCount;
        (
            dataPackagesCount,
            calldataNegativeOffset
        ) = _extractDataPackagesCountFromCalldata(calldataNegativeOffset);

        // 此时calldataNegativeOffset变成了Data Packages结束位置的负偏移量

        // 如果解析出的数据包个数为0，revert
        if (dataPackagesCount == 0) {
            revert RedstonePayloadMustHaveAtLeastOneDataPackage();
        }

        // 进入数据包循环
        for (
            uint256 dataPackageIndex = 0;
            dataPackageIndex < dataPackagesCount;
            dataPackageIndex++
        ) {
            // 计算一个完整数据包（Data Package）占用的总字节数
            uint256 dataPackageByteSize = _getDataPackageByteSize(
                calldataNegativeOffset
            );

            // Extracting timestamp for the current data package
            // 解析出该数据包的时间戳
            uint48 dataPackageTimestamp; // uint48, because timestamp uses 6 bytes

            // timestampNegativeOffset为该数据包内时间戳结束位置+32字节的负偏移量
            uint256 timestampNegativeOffset = (calldataNegativeOffset +
                TIMESTAMP_NEGATIVE_OFFSET_IN_DATA_PACKAGE_WITH_STANDARD_SLOT_BS);
            // timestampOffset为该数据包内时间戳结束位置+32字节的正偏移量
            uint256 timestampOffset = msg.data.length - timestampNegativeOffset;
            // 提取该数据包的时间戳
            assembly {
                dataPackageTimestamp := calldataload(timestampOffset)
            }

            // 时间戳不能为0
            if (dataPackageTimestamp == 0) {
                revert DataPackageTimestampMustNotBeZero();
            }

            // 在处理第一个数据包时，extractedTimestamp会变成本包的dataPackageTimestamp；
            // 在处理第二个及以后的数据包时，会校验extractedTimestamp与各包中的时间戳是否相等，如果不等revert
            if (extractedTimestamp == 0) {
                extractedTimestamp = dataPackageTimestamp;
            } else if (dataPackageTimestamp != extractedTimestamp) {
                revert DataPackageTimestampsMustBeEqual();
            }
            // 每处理完一个数据包后，calldataNegativeOffset都增大该数据包的字节长度
            calldataNegativeOffset += dataPackageByteSize;
        }
    }

    // 计算一个完整数据包（Data Package）占用的总字节数
    // 注：在 Redstone 协议中，数据包的大小不是固定的，因为它取决于包里包含了多少个价格（Data Points）以及每个价格数值的长度。
    // 合约必须先算出当前包的大小，才能知道下一个包从哪里开始
    // 参数：calldataNegativeOffset是从calldata末尾开始到Data Packages Count区域开始负偏移量
    //（也就是到Data Packages区域结束位置的负偏移量）
    function _getDataPackageByteSize(
        uint256 calldataNegativeOffset
    ) internal pure returns (uint256) {
        // 解析出：
        // dataPointsCount：这个包里有多少个报价（Count）
        // eachDataPointValueByteSize：每个报价数值占用了多少字节（Size）
        (
            uint256 dataPointsCount,
            uint256 eachDataPointValueByteSize
        ) = _extractDataPointsDetailsForDataPackage(calldataNegativeOffset);

        // Data Points的总字节数为：报价数量*(feedId字节数 + 报价数值字节数)
        // 那么该Data Package的总字节数为： Data Points的总字节数 + Timestamp（6字节）+ Data Point Value Size（4字节） + Data Points Count（3字节） + Signature（65字节）
        // 注：DATA_PACKAGE_WITHOUT_DATA_POINTS_BS为DATA_POINT_VALUE_BYTE_SIZE_BS + TIMESTAMP_BS + DATA_POINTS_COUNT_BS + SIG_BS
        return
            dataPointsCount *
            (DATA_POINT_SYMBOL_BS + eachDataPointValueByteSize) +
            DATA_PACKAGE_WITHOUT_DATA_POINTS_BS;
    }

    // 验证Marker及获取unsigned metadata content的（从calldata结尾往前查多少字节是unsigned metadata content开始的地方）
    // 这是提取过程的入口，它负责确认这笔交易是否带有 Redstone 数据
    // 什么是Unsigned Metadata？
    // 答：Redstone 的设计允许在价格数据之外，附加一些额外的、不需要签名验证的信息（例如：数据源的 ID、额外的存证信息或协议的分发逻辑）。这些信息就被称为 Unsigned Metadata。
    function _extractByteSizeOfUnsignedMetadata()
        internal
        pure
        returns (uint256)
    {
        // Checking if the calldata ends with the RedStone marker
        bool hasValidRedstoneMarker;
        assembly {
            // 读取calldata中最后32个字节
            // 注：calldatalad(i)：从 calldata 的第 i 个字节位置开始，连续读取 32 个字节，并将其压入 EVM 堆栈
            // 消耗 3 gas
            let calldataLast32Bytes := calldataload(
                sub(calldatasize(), STANDARD_SLOT_BS)
            )

            // 如果经过提取的后值正好等于REDSTONE_MARKER_MASK，那就认为是有效的
            // 逻辑：(最后32字节 & 标记掩码) == 标记掩码
            // 这证明了 calldata 的最末尾确实包含了 Redstone 的特征码
            hasValidRedstoneMarker := eq(
                REDSTONE_MARKER_MASK,
                // 用REDSTONE_MARKER_MASK作为掩码提取calldata 最后32个字节内容
                and(calldataLast32Bytes, REDSTONE_MARKER_MASK)
            )
        }
        // 无效就revert
        if (!hasValidRedstoneMarker) {
            revert CalldataMustHaveValidPayload();
        }

        // Using uint24, because unsigned metadata byte size number has 3 bytes
        // 读取元数据长度
        uint24 unsignedMetadataByteSize;
        // 这里对整个msg.data总长度做了一个最短长度校验，如果calldata的总长度小于9+32=41字节，那就一定是有问题的
        // 目的是防止读取溢出（因为calldataload()一次必须读32字节，所以要不使用内存而读出3字节的内容，必须从3字节内容前29字节的位置开始读，低位的3字节就是要的内容）
        if (REDSTONE_MARKER_BS_PLUS_STANDARD_SLOT_BS > msg.data.length) {
            revert CalldataOverOrUnderFlow();
        }
        assembly {
            // 先从calldata中读出MARKER前32字节的内容。
            // 再赋值给 uint24 变量unsignedMetadataByteSize，Solidity会自动截断，只保留最后 3 字节的值
            unsignedMetadataByteSize := calldataload(
                sub(calldatasize(), REDSTONE_MARKER_BS_PLUS_STANDARD_SLOT_BS)
            )
        }

        // 计算负偏移量，它告诉后续逻辑：“从 Calldata 末端往前数多少字节，才是真实数据包的结束位置
        // 计算公式：元数据内容长度 + 元长度字段本身(3字节) + Marker长度(9字节)
        uint256 calldataNegativeOffset = unsignedMetadataByteSize +
            UNSIGNED_METADATA_BYTE_SIZE_BS +
            REDSTONE_MARKER_BS;
        // 确保计算出来的偏移量不会超过 Calldata 的总长度，防止“越界读取”。
        // 除了已计算的偏移量calldataNegativeOffset，后面至少还得有一个“数据包数量”字段（2字节）
        if (calldataNegativeOffset + DATA_PACKAGES_COUNT_BS > msg.data.length) {
            revert IncorrectUnsignedMetadataSize();
        }
        // 返回负偏移量
        return calldataNegativeOffset;
    }

    // We return uint16, because unsigned metadata byte size number has 2 bytes
    // 剥开元数据层，读取数据包的总数
    // 注：在调用这个函数之前，合约已经通过 _extractByteSizeOfUnsignedMetadata 确定了末尾标记位Marker和元数据Metadata的大小。
    // 现在，它需要知道到底有多少个价格包（Data Packages）需要处理
    // 参数：calldataNegativeOffset——_extractByteSizeOfUnsignedMetadata()返回的偏移量，即从calldata结尾往前查多少字节是unsigned metadata content开始的地方
    // 返回值：
    // - dataPackagesCount：数据包个数
    // - calldataNegativeOffset：从calldata结尾往前查多少字节是data packages count开始的地方
    function _extractDataPackagesCountFromCalldata(
        uint256 calldataNegativeOffset
    )
        internal
        pure
        returns (uint16 dataPackagesCount, uint256 nextCalldataNegativeOffset)
    {
        // 为了读到紧跟在元数据之前的那个 uint16 Data Packages Count，需要把指针再往左（往前）推 32 字节
        // 这确保了要读的 2 字节包含在这 32 字节的最低2字节
        uint256 calldataNegativeOffsetWithStandardSlot = calldataNegativeOffset +
                STANDARD_SLOT_BS;
        // 溢出安全检查
        if (calldataNegativeOffsetWithStandardSlot > msg.data.length) {
            revert CalldataOverOrUnderFlow();
        }

        // 提取数据包数量（Data Packages Count）
        assembly {
            // calldataload()返回的是32字节的内容，但是由于赋值给uint16类型的dataPackagesCount
            // Solidity 会自动自动截断，保留最低位的 2 个字节
            dataPackagesCount := calldataload(
                sub(calldatasize(), calldataNegativeOffsetWithStandardSlot)
            )
        }
        return (
            // 返回数据包数量
            dataPackagesCount,
            // 负偏移指针又往前移动2个字节（跨过Data Packages Count区域）
            calldataNegativeOffset + DATA_PACKAGES_COUNT_BS
        );
    }

    // 该函数负责从 Calldata 的原始字节流中，精准地抠出Feed Id和具体的报价数值
    // 入参：
    // - dataPointNegativeOffset：该Data Point的负偏移量
    // - dataPointValueByteSize：该Data Package中每个报价的值所占的字节长度
    function _extractDataPointValueAndDataFeedId(
        uint256 dataPointNegativeOffset,
        uint256 dataPointValueByteSize
    )
        internal
        pure
        virtual
        returns (bytes32 dataPointDataFeedId, uint256 dataPointValue)
    {
        // 将data point的负偏移量变为正偏移量
        uint256 dataPointCalldataOffset = msg.data.length -
            dataPointNegativeOffset;
        assembly {
            // dataPointCalldataOffset开始的第一个32字节是该data point的feed id
            dataPointDataFeedId := calldataload(dataPointCalldataOffset)
            // dataPointCalldataOffset开始的第二个32字节是该data point的value
            // 注：dataPointValue的高位为data point的value，右侧可能会有垃圾数据。（此时是左对齐）
            // 按照该代码的逻辑来看，dataPointValueByteSize最大也就是32字节了
            dataPointValue := calldataload(
                add(dataPointCalldataOffset, DATA_POINT_SYMBOL_BS)
            )
        }
        // dataPointValueByteSize最多只支持32字节的value
        if (dataPointValueByteSize >= 33) {
            revert TooLargeValueByteSize(dataPointValueByteSize);
        }

        // 将左对齐的data point的value通过向右位移变成右对齐
        unchecked {
            // 向右位移位数为32字节中额外字节的位数，即(32 - dataPointValueByteSize) * 8
            dataPointValue =
                dataPointValue >>
                ((32 - dataPointValueByteSize) * 8);
        }
    }

    // 从一个特定的数据包中提取出两个最核心的控制参数：
    // - dataPointsCount：这个包里有多少个报价（Count）
    // - eachDataPointValueByteSize：每个报价数值占用了多少字节（Size）
    // 注：每个数据包的位置布局为（从左往右）：
    // | 偏移顺序  | 内容                   | 长度 (Size)      | 说明
    // |  1       | Data Points            | 变量 (X)        | 包含多个 (FeedId + Value) 组合
    // |  2       | Timestamp             | 6 字节           | 该数据包的产生时间戳
    // |  3       | Data Point Value Size | 4 字节           | 每个 Data Point Value 占用的字节数
    // |  4       | Data Points Count     | 3 字节           | 该包中包含多少组数据点
    // |  5       | Signature             | 65 字节          | 对上述所有内容的 ECDSA 签名
    // 入参：calldataNegativeOffsetForDataPackage是从calldata末尾开始到Data Packages Count区域开始负偏移量
    //（也就是到Data Packages区域结束的位置的负偏移量）
    function _extractDataPointsDetailsForDataPackage(
        uint256 calldataNegativeOffsetForDataPackage
    )
        internal
        pure
        returns (uint256 dataPointsCount, uint256 eachDataPointValueByteSize)
    {
        // 为了节省 Gas，在序列化时并不会为每个字段都分配 32 字节。
        // 在数据包结构中，报价数量（dataPointsCount_）只占 3 字节，每个报价数值大小（eachDataPointValueByteSize_）只占 4 字节

        // Using uint24, because data points count byte size number has 3 bytes
        uint24 dataPointsCount_;

        // Using uint32, because data point value byte size has 4 bytes
        uint32 eachDataPointValueByteSize_;

        // Extract data points count
        // 定位并提取报价数量
        uint256 calldataOffset = msg.data.length -
            (calldataNegativeOffsetForDataPackage + SIG_BS + STANDARD_SLOT_BS);
        assembly {
            dataPointsCount_ := calldataload(calldataOffset)
        }

        // Extract each data point value size
        // 定位并提取每个报价数值大小
        calldataOffset = calldataOffset - DATA_POINTS_COUNT_BS;
        assembly {
            eachDataPointValueByteSize_ := calldataload(calldataOffset)
        }

        // 返回
        dataPointsCount = dataPointsCount_;
        eachDataPointValueByteSize = eachDataPointValueByteSize_;
    }
}
