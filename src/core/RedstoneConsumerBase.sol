// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.17;

import "./RedstoneConstants.sol";
import "./RedstoneDefaultsLib.sol";
import "./CalldataExtractor.sol";
import "../libs/BitmapLib.sol";
import "../libs/SignatureLib.sol";

/**
 * @title The base contract with the main Redstone logic
 * @author The Redstone Oracles team
 * @dev Do not use this contract directly in consumer contracts, take a
 * look at `RedstoneConsumerNumericBase` and `RedstoneConsumerBytesBase` instead
 */

// RedstoneConsumerBase 是 Redstone 预言机架构中的灵魂组件，是一个抽象合约（Abstract Contract），定义了如何从交易的 calldata 末尾提取、验证并聚合来自多个签名者的预言机数据。
// 在使用中，你几乎永远不会直接继承 RedstoneConsumerBase，而是继承它的具体实现类：
// 场景一：获取数值（价格、波动率等）：
//  如果你需要获取的是数字（例如 ETH 的价格是 2000.12，返回为 2000120000），你应该继承： RedstoneConsumerNumericBase
//  你的工作只需实现权限校验（Signer Index）和阈值（Threshold）；
// 场景二：获取复杂数据（数组、字符串、元数据）
//  如果你需要获取的是 字节流（例如一段签名的文本、一组参数包），你应该继承： RedstoneConsumerBytesBase
//  原理：它不进行数值转换，直接把验证后的原始 bytes 交给你。
abstract contract RedstoneConsumerBase is CalldataExtractor {
    error GetDataServiceIdNotImplemented();

    /* ========== VIRTUAL FUNCTIONS (MAY BE OVERRIDDEN IN CHILD CONTRACTS) ========== */

    /**
     * @dev This function must be implemented by the child consumer contract.
     * It should return dataServiceId which DataServiceWrapper will use if not provided explicitly .
     * If not overridden, value will always have to be provided explicitly in DataServiceWrapper.
     * @return dataServiceId being consumed by contract
     */
    // 需要在子合约中实现该方法
    // 红石系统有多个数据源服务，该 ID 决定了合约信任哪一组数据源。
    function getDataServiceId() public view virtual returns (string memory) {
        revert GetDataServiceIdNotImplemented();
    }

    /**
     * @dev This function must be implemented by the child consumer contract.
     * It should return a unique index for a given signer address if the signer
     * is authorised, otherwise it should revert
     * @param receivedSigner The address of a signer, recovered from ECDSA signature
     * @return Unique index for a signer in the range [0..255]
     */
    // 需要在子合约中实现该方法
    // 权限防火墙。输入解析出来的签名者地址，返回其编号（0-255）。如果该地址不在白名单内，必须抛出错误。这是防止伪造价格的关键。
    function getAuthorisedSignerIndex(
        address receivedSigner
    ) public view virtual returns (uint8);

    /**
     * @dev This function may be overridden by the child consumer contract.
     * It should validate the timestamp against the current time (block.timestamp)
     * It should revert with a helpful message if the timestamp is not valid
     * @param receivedTimestampMilliseconds Timestamp extracted from calldata
     */
    // 验证数据包里的时间戳，如果有问题，触发revert
    function validateTimestamp(
        uint256 receivedTimestampMilliseconds
    ) public view virtual {
        RedstoneDefaultsLib.validateTimestamp(receivedTimestampMilliseconds);
    }

    /**
     * @dev This function must be implemented by the child consumer contract.
     * @return The minimum required value of unique authorised signers
     */
    // 需要在子合约中实现该方法
    // 信任阈值。返回一个数字（如 3），表示一笔交易必须包含至少 3 个不同授权节点的签名，价格才会被采纳
    function getUniqueSignersThreshold() public view virtual returns (uint8);

    /**
     * @dev This function may be overridden by the child consumer contract.
     * It should aggregate values from different signers to a single uint value.
     * By default, it calculates the median value
     * @param values An array of uint256 values from different signers
     * @return Result of the aggregation in the form of a single number
     */
    // 数据聚合：拿到多个签名者的价格后怎么处理？默认是取中位数（Median）。
    function aggregateValues(
        uint256[] memory values
    ) public view virtual returns (uint256) {
        return RedstoneDefaultsLib.aggregateValues(values);
    }

    /* ========== FUNCTIONS WITH IMPLEMENTATION (CAN NOT BE OVERRIDDEN) ========== */

    /**
     * @dev This is an internal helpful function for secure extraction oracle values
     * from the tx calldata. Security is achieved by signatures verification, timestamp
     * validation, and aggregating values from different authorised signers into a
     * single numeric value. If any of the required conditions (e.g. packages with different
     * timestamps or insufficient number of authorised signers) do not match, the function
     * will revert.
     *
     * Note! You should not call this function in a consumer contract. You can use
     * `getOracleNumericValuesFromTxMsg` or `getOracleNumericValueFromTxMsg` instead.
     *
     * @param dataFeedIds An array of unique data feed identifiers
     * @return An array of the extracted and verified oracle values in the same order
     * as they are requested in dataFeedIds array
     * @return dataPackagesTimestamp timestamp equal for all data packages
     */
    // 该函数是 Redstone 的“中央处理器”，它的逻辑非常严密：先分配内存，再逆向解析 calldata，最后进行聚合验证。
    // 返回值：
    // - uint256数组：dataFeedIds对应的价格结果，顺序与dataFeedIds一致。这些值不是某个单一节点的原始数据，
    // 而是根据子合约定义的逻辑（默认通常是取中位数 Median）从多个授权签名者的数据中计算出来的。
    // - dataPackagesTimestamp：统一时间戳（所有被提取的数据包，其时间戳必须完全相等，否则revert）
    function _securelyExtractOracleValuesAndTimestampFromTxMsg(
        // dataFeedIds为想要获取的资产标识符数组
        bytes32[] memory dataFeedIds
    ) internal view returns (uint256[] memory, uint256 dataPackagesTimestamp) {
        // Initializing helpful variables and allocating memory
        // 初始化内存：为每个请求的 DataFeed 准备计数器、位图和数值存放数组
        // 注：三个初始化的数组长度与dataFeedIds的长度一致，且初始化后的数组内都是零值

        // uniqueSignerCountForDataFeedIds的作用是：精确追踪每一个资产（Feed Id）当前已收集到的有效签名数量（不同的signer数量），并作为内存矩阵的索引
        uint256[] memory uniqueSignerCountForDataFeedIds = new uint256[](
            dataFeedIds.length
        );
        // signersBitmapForDataFeedIds的作用是：确保同一个预言机节点（Signer）针对同一个资产FeedId，其贡献的价格只会被计入一次，防止“刷票”操纵价格
        // 如果一个恶意的预言机节点（或者是一个因为网络故障发了重包的节点）在 calldata 里塞进了 10 个数据包，且这 10 个包里的价格都是他伪造的极端价格。
        uint256[] memory signersBitmapForDataFeedIds = new uint256[](
            dataFeedIds.length
        );

        // valuesForDataFeeds的作用是：在解析 Calldata 的过程中，将来自不同签名者、分散在各个数据包中的原始价格，按照资产种类进行“归类”和“暂存”，为最后的聚合计算（如取中位数）做准备
        // Note: valuesForDataFeeds[dataFeedIdIndex][0]表示为：第1个为feed id：dataFeedIds[dataFeedIdIndex]提供价格的signer所提供的价格；
        //       valuesForDataFeeds[dataFeedIdIndex][1]表示为：第2个为feed id：dataFeedIds[dataFeedIdIndex]提供价格的signer所提供的价格。
        // 该语句在内存中只分配了指针槽位，即
        //  内存地址 (偏移量) | 存储内容 (32 字节/槽)   | 说明
        //  p               | dataFeedIds.length   | 外层数组的长度：记录有多少个 DataFeed 槽位。
        //  p + 0x20        | 0x00...00            | 第 1 个元素的指针：此时仅分配了槽位，初始化为 0。
        //  p + 0x40        | 0x00...00            | 第 2 个元素的指针：初始化为 0。
        //  ...             | ...                  | ...
        //  p + (n * 0x20)  | 0x00...00            | 第 n 个元素的指针：初始化为 0。
        uint256[][] memory valuesForDataFeeds = new uint256[][](
            dataFeedIds.length
        );
        // 获取当前子合约定义的签名者阈值（即至少需要多少人的签名）
        uint256 uniqueSignersThreshold = getUniqueSignersThreshold();
        // 循环初始化二维数组，准备存放不同签名者的价格
        for (uint256 i = 0; i < dataFeedIds.length; ) {
            // The line below is commented because newly allocated arrays are filled with zeros
            // But we left it for better readability
            // signersBitmapForDataFeedIds[i] = 0; // <- setting to an empty bitmap
            // 二维数组valuesForDataFeeds中，为每个元素（元素是一个长度为uniqueSignersThreshold的不定长数组）初始做初始化
            valuesForDataFeeds[i] = new uint256[](uniqueSignersThreshold);
            // 使用 unchecked 节省循环变量自增的 Gas
            unchecked {
                i++;
            }
        }

        // Extracting the number of data packages from calldata
        // 验证Marker及获取unsigned metadata content的（从calldata结尾往前查多少字节是unsigned metadata content开始的地方）
        // 注：calldataNegativeOffset此时是指向Data Packages Count结束位移的负偏移量
        uint256 calldataNegativeOffset = _extractByteSizeOfUnsignedMetadata();
        // 剥开元数据层，读取数据包的总数
        // 注：calldataNegativeOffset此时是指向Data Packages结束为止的负偏移量
        uint256 dataPackagesCount;
        (
            dataPackagesCount,
            calldataNegativeOffset
        ) = _extractDataPackagesCountFromCalldata(calldataNegativeOffset);

        // Saving current free memory pointer
        uint256 freeMemPtr;
        assembly {
            // 获取当前的自由内存指针
            // 注：记录当前的内存位置是因为因为接下来的循环会不断申请临时内存来解析签名，如果不手动重置指针，内存消耗会爆炸
            // EVM 的内存费用在超过一定阈值（通常是 32KB）后，其增长曲线从线性变为二次方
            freeMemPtr := mload(FREE_MEMORY_PTR)
        }

        // Data packages extraction in a loop
        for (
            uint256 dataPackageIndex = 0;
            dataPackageIndex < dataPackagesCount;

        ) {
            // Extract data package details and update calldata offset
            // 依次解析单个数据包，其中包括验证签名、检查权限、填充valuesForDataFeeds
            uint256 dataPackageTimestamp;
            (
                calldataNegativeOffset,
                dataPackageTimestamp
            ) = _extractDataPackage(
                dataFeedIds,
                uniqueSignerCountForDataFeedIds,
                signersBitmapForDataFeedIds,
                valuesForDataFeeds,
                calldataNegativeOffset
            );

            // 安全检查：时间戳不能为空
            if (dataPackageTimestamp == 0) {
                revert DataTimestampCannotBeZero();
            }

            // 核心逻辑：强制所有参与聚合的数据包必须具有完全相同的时间戳
            if (dataPackageTimestamp != dataPackagesTimestamp) {
                if (dataPackagesTimestamp == 0) {
                    // Setting dataPackagesTimestamp first time
                    // 解析第一个数据包时，会将该数据包的时间戳赋值给dataPackagesTimestamp
                    dataPackagesTimestamp = dataPackageTimestamp;
                } else {
                    // 从解析第二个数据包开始，会比对各个数据包中的时间戳和dataPackagesTimestamp，如果不一致，revert
                    revert TimestampsMustBeEqual();
                }
            }

            // Resetting the memory pointer to the initial "safe" value
            // We add STANDARD_SLOT_BS (32 bytes) to account for potential allocation
            // of the dataPackageIndex variable, which may or may not be stored in memory
            assembly {
                // 手动重置内存指针，回收循环中产生的内存空间（如签名 bytes）
                // 为什么要加多出一个32字节？因为这个内存空间是留给存储dataPackageIndex变量的
                // 注：在 Solidity 中，普通的局部变量（如 dataPackageIndex）通常存储在 栈（Stack） 上。
                // 但在复杂的循环逻辑中，编译器有时为了避免“栈太深（Stack too deep）”的错误，或者在特定的优化模式下，可能会将某些中间变量或循环状态临时存放在 内存 中
                // 这里预留一个标准的字长（32 字节）可以作为一个“缓冲区”，确保即使编译器在处理循环增量或临时跳转地址时需要一点内存空间，也不会破坏我们标记为“自由”的内存区域。
                mstore(FREE_MEMORY_PTR, add(freeMemPtr, STANDARD_SLOT_BS))
            }
            // dataPackageIndex自增
            unchecked {
                dataPackageIndex++;
            }
        }

        // Validating numbers of unique signers and calculating aggregated values for each dataFeedId
        // 验证每个 feed id 是否收集够了足够的签名，并调用聚合算法（如取中位数）
        return (
            // 确认每个feed id是否收够了票数（signer是否满足信任阈值），并将那一堆原始数值聚合成一个最终的价格并返回一个相同顺序的价格数组
            _getAggregatedValues(
                valuesForDataFeeds,
                uniqueSignerCountForDataFeedIds
            ),
            dataPackagesTimestamp
        );
    }

    /**
     * @dev This is a private helpful function, which extracts data for a data package based
     * on the given negative calldata offset, verifies them, and in the case of successful
     * verification updates the corresponding data package values in memory
     *
     * @param dataFeedIds an array of unique data feed identifiers
     * @param uniqueSignerCountForDataFeedIds an array with the numbers of unique signers
     * for each data feed
     * @param signersBitmapForDataFeedIds an array of signer bitmaps for data feeds
     * @param valuesForDataFeeds 2-dimensional array, valuesForDataFeeds[i][j] contains
     * j-th value for the i-th data feed
     * @param calldataNegativeOffset negative calldata offset for the given data package
     *
     * @return nextCalldataNegativeOffset negative calldata offset for the next data package
     * @return dataPackageTimestamp data package timestamp
     */
    // 从calldata的负偏移量calldataNegativeOffset位置（即该数据包的结束位置）开始提取（向前）出一个完整的数据包，验证其数字签名，并把有效数据填充到在内存中预设好的矩阵中（入参的内存中的数组）
    // 注：每个数据包的位置布局为（从左往右）：
    // | 偏移顺序  | 内容                   | 长度 (Size)      | 说明
    // |  1       | Data Points           | 变量 (X)         | 包含多个 (FeedId + Value) 组合
    // |  2       | Timestamp             | 6 字节           | 该数据包的产生时间戳
    // |  3       | Data Point Value Size | 4 字节           | 每个 Data Point Value 占用的字节数
    // |  4       | Data Points Count     | 3 字节           | 该包中包含多少组数据点
    // |  5       | Signature             | 65 字节          | 对上述所有内容的 ECDSA 签名
    // 返回值：
    // - nextCalldataNegativeOffset：下一个数据包在calldata中的负偏移量（物理位置是该数据包的前一个数据包）
    // - dataPackageTimestamp：该数据包内的统一一致的时间戳
    function _extractDataPackage(
        // 目标 Data Feed Ids列表
        bytes32[] memory dataFeedIds,
        // 每个 Feed 已收集的签名数
        uint256[] memory uniqueSignerCountForDataFeedIds,
        // 签名者去重位图
        uint256[] memory signersBitmapForDataFeedIds,
        // 存储数值的二维内存矩阵
        uint256[][] memory valuesForDataFeeds,
        // 该数据包在当前 Calldata 的负偏移量
        uint256 calldataNegativeOffset
    )
        private
        view
        returns (
            uint256 nextCalldataNegativeOffset,
            uint256 dataPackageTimestamp
        )
    {
        uint256 signerIndex;

        // 从该数据包中提取出两个最核心的控制参数：
        // - dataPointsCount：这个包里有多少个报价（Count）
        // - eachDataPointValueByteSize：每个报价数值占用了多少字节（Size）
        (
            uint256 dataPointsCount,
            uint256 eachDataPointValueByteSize
        ) = _extractDataPointsDetailsForDataPackage(calldataNegativeOffset);

        // We use scopes to resolve problem with too deep stack
        // 这里使用了 {} 代码块来开启一个新的作用域，目的是释放局部变量占用的栈空间，防止 Stack too deep
        {
            address signerAddress;
            bytes32 signedHash;
            bytes memory signedMessage;
            uint256 signedMessageBytesCount;
            uint48 extractedTimestamp;

            // 计算被签名message的总字节长度：数据包中的报价个数 * (每个报价数值占用的字节长度 + 每个feedId的字节长度) + Timestamp的字节长度 + Data Point Value Size的字节长度 + Data Points Count的字节长度
            // 注：eachDataPointValueByteSize + DATA_POINT_SYMBOL_BS就是一个Data Point的字节长度
            // 其实：signedMessageBytesCount就是一个数据包中减去一个签名的字节长度
            // 被签名message的内容就是从一个数据包中扣掉签名后的全部calldata
            signedMessageBytesCount =
                dataPointsCount *
                (eachDataPointValueByteSize + DATA_POINT_SYMBOL_BS) +
                DATA_PACKAGE_WITHOUT_DATA_POINTS_AND_SIG_BS; //DATA_POINT_VALUE_BYTE_SIZE_BS + TIMESTAMP_BS + DATA_POINTS_COUNT_BS

            // 定位时间戳在 calldata 中的正偏移量
            // 即calldataNegativeOffset跳过签名(65字节) -> Data Points Count(3字节) -> Data Point Value Size(4字节) -> 32字节
            // 注：为什么要减32字节？这样可以保证calldataload(timestampCalldataOffset)的低位就是时间戳，不再需要位移提取
            uint256 timestampCalldataOffset = msg.data.length -
                (calldataNegativeOffset +
                    TIMESTAMP_NEGATIVE_OFFSET_IN_DATA_PACKAGE_WITH_STANDARD_SLOT_BS);
            // 定位被签名的message在 calldata 中的正偏移量
            // 即该数据包的起始位置
            uint256 signedMessageCalldataOffset = msg.data.length -
                (calldataNegativeOffset + SIG_BS + signedMessageBytesCount);

            assembly {
                // Extracting the signed message
                // 从calldata中将数据包的签名的message复制到内存中，内存中的bytes memory的起始地址为signedMessage
                signedMessage := extractBytesFromCalldata(
                    signedMessageCalldataOffset,
                    signedMessageBytesCount
                )

                // Hashing the signed message
                // 对内存中的签名的message取hash，即构建digest
                signedHash := keccak256(
                    // 跳过长度字段
                    add(signedMessage, BYTES_ARR_LEN_VAR_BS),
                    signedMessageBytesCount
                )

                // Extracting timestamp
                // 从calldata中读取时间戳
                extractedTimestamp := calldataload(timestampCalldataOffset)

                // 该函数是一个非常精简的memory bytes内存分配器（不做内存清0），用于在内存中初始化一个空间给长度为bytesCount的memory bytes
                // 返回值ptr为该bytes的数据的起始内存地址
                // 注：如果用new bytes() 在分配后会强制把所有分配的内存空间填入0，而本方法
                // 不会填充。因为紧接着就会用 calldatacopy 覆盖这些内存空间
                function initByteArray(bytesCount) -> ptr {
                    // 获取当前空闲内存位置
                    ptr := mload(FREE_MEMORY_PTR)
                    // ptr 指向的第一个字存入了bytes长度
                    mstore(ptr, bytesCount)
                    // 跳过长度槽位，定位数据区
                    ptr := add(ptr, BYTES_ARR_LEN_VAR_BS)
                    // 更新空闲内存指针
                    // 即将原来的空闲指针增加32+bytesCount个字节，然后更新到0x40的内存中
                    mstore(FREE_MEMORY_PTR, add(ptr, bytesCount))
                }

                // 用于从 calldata 中的offset位置开始复制bytesCount个字节到内存中，返回值为内存中该bytes到起始地址
                function extractBytesFromCalldata(offset, bytesCount)
                    -> extractedBytes
                {
                    // 在内存中初始化出一段bytes memory（其字节长度为bytesCount）。extractedBytesStartPtr为该bytes的数据的起始地址
                    let extractedBytesStartPtr := initByteArray(bytesCount)
                    //
                    // 注：calldatacopy 是一条高性能指令，用于将交易的输入数据（calldata）直接复制到内存中
                    // calldatacopy(target, from, size)
                    // - target：目标内存地址。数据要拷贝到内存的哪个位置。
                    // - from：源字节偏移量。从 calldata 的第几个字节开始拷贝。
                    // - size：拷贝的长度。总共拷贝多少个字节。
                    // 注：calldatacopy 不会自动检查越界。如果请求拷贝的size超出了 msg.data 的实际范围，EVM 不会报错，而是会在超出部分填充零（0）
                    calldatacopy(extractedBytesStartPtr, offset, bytesCount)
                    // extractedBytes为该bytes memory的起始地址（数据起始地址-32字节）
                    extractedBytes := sub(
                        extractedBytesStartPtr,
                        BYTES_ARR_LEN_VAR_BS
                    )
                }
            }

            // 将局部代码块中的extractedTimestamp(uint48)赋值给返回值dataPackageTimestamp(uint256)
            dataPackageTimestamp = extractedTimestamp;

            // Verifying the off-chain signature against on-chain hashed data
            // 利用 ECDSA 算法从哈希和签名中恢复出签名者地址
            signerAddress = SignatureLib.recoverSignerAddress(
                signedHash,
                // 当前数据包的负偏移量+65字节，到了本数据包内签名开始的负偏移量
                calldataNegativeOffset + SIG_BS
            );
            // 权限校验：通过解析出的地址换取索引 (0-255)，如果非授权地址会在此处 revert
            signerIndex = getAuthorisedSignerIndex(signerAddress);
        }

        // Updating helpful arrays
        {
            // 调整偏移量，calldataNegativeOffset此时为该数据包的Data Points结束位置
            calldataNegativeOffset =
                calldataNegativeOffset +
                DATA_PACKAGE_WITHOUT_DATA_POINTS_BS;
            bytes32 dataPointDataFeedId;
            uint256 dataPointValue;
            // 开始遍历一个数据包中的Data Points
            for (
                uint256 dataPointIndex = 0;
                dataPointIndex < dataPointsCount;

            ) {
                // calldataNegativeOffset往前移 point value + feed id个字节，到达当前Data Point的起始位置
                calldataNegativeOffset =
                    calldataNegativeOffset +
                    eachDataPointValueByteSize +
                    DATA_POINT_SYMBOL_BS;
                // Extracting data feed id and value for the current data point
                // 从calldata中解析出当前Data Point的feed id和point value
                (
                    dataPointDataFeedId,
                    dataPointValue
                ) = _extractDataPointValueAndDataFeedId(
                    calldataNegativeOffset,
                    eachDataPointValueByteSize
                );

                // 遍历用户传入的目标feed ids，看看该解析出feed id是否在其中
                for (
                    uint256 dataFeedIdIndex = 0;
                    dataFeedIdIndex < dataFeedIds.length;

                ) {
                    // 如果解析出的feed id确实在目标feed ids中
                    if (dataPointDataFeedId == dataFeedIds[dataFeedIdIndex]) {
                        // 获得当前feed id的位图
                        uint256 bitmapSignersForDataFeedId = signersBitmapForDataFeedIds[
                                dataFeedIdIndex
                            ];

                        // 位图去重检查和信任阈值检查：确保该签名者还没为该 feed id 贡献过数据 && 该 feed id收集的有效签名数是否还没达到 getUniqueSignersThreshold()
                        if (
                            !BitmapLib.getBitFromBitmap(
                                bitmapSignersForDataFeedId,
                                signerIndex
                            ) /* current signer was not counted for current dataFeedId */ &&
                            uniqueSignerCountForDataFeedIds[dataFeedIdIndex] <
                            getUniqueSignersThreshold()
                        ) {
                            // Add new value
                            // 将Data Point value写入二维矩阵valuesForDataFeeds
                            // Note: valuesForDataFeeds[dataFeedIdIndex][0]表示为：第1个为feed id：dataFeedIds[dataFeedIdIndex]提供价格的signer所提供的价格；
                            //       valuesForDataFeeds[dataFeedIdIndex][1]表示为：第2个为feed id：dataFeedIds[dataFeedIdIndex]提供价格的signer所提供的价格。
                            valuesForDataFeeds[dataFeedIdIndex][
                                uniqueSignerCountForDataFeedIds[dataFeedIdIndex]
                            ] = dataPointValue;

                            // Increase unique signer counter
                            // 增加该 feed id 的有效签名计数
                            uniqueSignerCountForDataFeedIds[dataFeedIdIndex]++;

                            // Update signers bitmap
                            // 在位图中把该签名者所在的位置设为 1，防止他在同一个calldata 里塞多个包
                            signersBitmapForDataFeedIds[
                                dataFeedIdIndex
                            ] = BitmapLib.setBitInBitmap(
                                bitmapSignersForDataFeedId,
                                signerIndex
                            );
                        }

                        // Breaking, as there couldn't be several indexes for the same feed ID
                        // 一旦feed id匹配成功后，不需要再在 dataFeedIds 里找了，跳出内层循环
                        break;
                    }
                    unchecked {
                        // 如果feed id还没有匹配成功，继续去匹配dataFeedIds的下一个元素
                        dataFeedIdIndex++;
                    }
                }
                unchecked {
                    // 接着处理下一个Data Point
                    dataPointIndex++;
                }
            }
        }

        // 返回：
        // - calldataNegativeOffset（此时calldataNegativeOffset应该指向下一个数据包的结束位置）；
        // - dataPackageTimestamp：本数据包中统一一致的时间戳
        return (calldataNegativeOffset, dataPackageTimestamp);
    }

    /**
     * @dev This is a private helpful function, which aggregates values from different
     * authorised signers for the given arrays of values for each data feed
     *
     * @param valuesForDataFeeds 2-dimensional array, valuesForDataFeeds[i][j] contains
     * j-th value for the i-th data feed
     * @param uniqueSignerCountForDataFeedIds an array with the numbers of unique signers
     * for each data feed
     *
     * @return An array of the aggregated values
     */
    // 该函数负责确认每个feed id是否收够了票数（signer是否满足信任阈值），并将那一堆原始数值聚合成一个最终的价格
    function _getAggregatedValues(
        uint256[][] memory valuesForDataFeeds,
        uint256[] memory uniqueSignerCountForDataFeedIds
    ) private view returns (uint256[] memory) {
        // 创建一个新的一维数组，长度与目标feed id数量一致，用于存放最终结果
        uint256[] memory aggregatedValues = new uint256[](
            valuesForDataFeeds.length
        );
        // 获取预设的信任阈值
        uint256 uniqueSignersThreshold = getUniqueSignersThreshold();
        
        // 开始遍历全部目标feed id并做校验
        for (
            uint256 dataFeedIndex = 0;
            dataFeedIndex < valuesForDataFeeds.length;

        ) {
            // 判断该目标feed id获得的不同signer数量是否满足信任阈值
            if (
                uniqueSignerCountForDataFeedIds[dataFeedIndex] <
                uniqueSignersThreshold
            ) {
                revert InsufficientNumberOfUniqueSigners(
                    uniqueSignerCountForDataFeedIds[dataFeedIndex],
                    uniqueSignersThreshold
                );
            }
            // valuesForDataFeeds[dataFeedIndex]表示该目标feed id得到的不同signer报价的数组（数组元素个数<=信任阈值）
            // 将以上结果做聚合（默认是取中位数）
            uint256 aggregatedValueForDataFeedId = aggregateValues(
                valuesForDataFeeds[dataFeedIndex]
            );
            // 将聚合结果写入aggregatedValues数组的对应位置
            aggregatedValues[dataFeedIndex] = aggregatedValueForDataFeedId;
            unchecked {
                // 继续处理下一个目标feed id
                dataFeedIndex++;
            }
        }

        // 返回聚合后的目标feed ids对应的价格数组
        return aggregatedValues;
    }
}
