// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.17;

/**
 * @title The base contract with helpful constants
 * @author The Redstone Oracles team
 * @dev It mainly contains redstone-related values, which improve readability
 * of other contracts (e.g. CalldataExtractor and RedstoneConsumerBase)
 */
contract RedstoneConstants {
    // === Abbreviations ===
    // BS - Bytes size
    // PTR - Pointer (memory location)
    // SIG - Signature

    // Solidity and YUL constants
    uint256 internal constant STANDARD_SLOT_BS = 32;
    uint256 internal constant FREE_MEMORY_PTR = 0x40;
    uint256 internal constant BYTES_ARR_LEN_VAR_BS = 32;
    uint256 internal constant REVERT_MSG_OFFSET = 68; // Revert message structure described here: https://ethereum.stackexchange.com/a/66173/106364
    uint256 internal constant STRING_ERR_MESSAGE_MASK =
        0x08c379a000000000000000000000000000000000000000000000000000000000;

    // RedStone protocol consts
    uint256 internal constant SIG_BS = 65;
    uint256 internal constant TIMESTAMP_BS = 6;
    // 记录数据包个数的区域长度：2字节
    uint256 internal constant DATA_PACKAGES_COUNT_BS = 2;
    uint256 internal constant DATA_POINTS_COUNT_BS = 3;
    uint256 internal constant DATA_POINT_VALUE_BYTE_SIZE_BS = 4;
    // 即每个币对的feedId
    uint256 internal constant DATA_POINT_SYMBOL_BS = 32;
    // metadata字节长度：3字节
    uint256 internal constant UNSIGNED_METADATA_BYTE_SIZE_BS = 3;
    // MARKER字节长度：9字节
    uint256 internal constant REDSTONE_MARKER_BS = 9; // byte size of 0x000002ed57011e0000
    // red stone的MARKER判断：
    // 这个常量既是掩码，也是特征值
    // 机制：会通过REDSTONE_MARKER_MASK作为掩码，提取calldata最后的32字节内容
    // 如果提取后的结果依然等于REDSTONE_MARKER_MASK，就证明该calldata包含了 Redstone 的特征码
    // 这种设计的精妙之处： 如果使用 0xFFF... 作为掩码，你需要两个变量：一个掩码（Mask），一个期望值（Value）。
    //  而 Redstone 把两者合二为一了。 只有当原始数据的那些位恰好等于这个特征值时，A & B == B 才会成立
    uint256 internal constant REDSTONE_MARKER_MASK =
        0x0000000000000000000000000000000000000000000000000002ed57011e0000;

    // Derived values (based on consts)
    uint256
        internal constant TIMESTAMP_NEGATIVE_OFFSET_IN_DATA_PACKAGE_WITH_STANDARD_SLOT_BS =
        104; // SIG_BS + DATA_POINTS_COUNT_BS + DATA_POINT_VALUE_BYTE_SIZE_BS + STANDARD_SLOT_BS
    uint256 internal constant DATA_PACKAGE_WITHOUT_DATA_POINTS_BS = 78; // DATA_POINT_VALUE_BYTE_SIZE_BS + TIMESTAMP_BS + DATA_POINTS_COUNT_BS + SIG_BS
    uint256 internal constant DATA_PACKAGE_WITHOUT_DATA_POINTS_AND_SIG_BS = 13; // DATA_POINT_VALUE_BYTE_SIZE_BS + TIMESTAMP_BS + DATA_POINTS_COUNT_BS
    // marker 9 bytes + 32 bytes
    uint256 internal constant REDSTONE_MARKER_BS_PLUS_STANDARD_SLOT_BS = 41; // REDSTONE_MARKER_BS + STANDARD_SLOT_BS

    // Error messages
    error CalldataOverOrUnderFlow();
    error IncorrectUnsignedMetadataSize();
    error InsufficientNumberOfUniqueSigners(
        uint256 receivedSignersCount,
        uint256 requiredSignersCount
    );
    error EachSignerMustProvideTheSameValue();
    error EmptyCalldataPointersArr();
    error InvalidCalldataPointer();
    error CalldataMustHaveValidPayload();
    error SignerNotAuthorised(address receivedSigner);
    error DataTimestampCannotBeZero();
    error TimestampsMustBeEqual();
}
