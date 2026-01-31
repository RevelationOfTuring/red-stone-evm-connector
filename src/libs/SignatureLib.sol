// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

// 该库是一个非常底层的、高性能的 ECDSA 签名恢复库。通过直接从 calldata 的末尾提取签名数据来节省 Gas
library SignatureLib {
    // 一个标准的以太坊签名由三部分组成：r (32字节), s (32字节), 和 v (1字节)，共65字节
    // ECDSA 签名中 r 分量的标准长度
    uint256 constant ECDSA_SIG_R_BS = 32;
    // ECDSA 签名中 s 分量的标准长度
    uint256 constant ECDSA_SIG_S_BS = 32;

    // Constants for ECDSA recovery ids
    // 这是以太坊定义的 恢复标识符（Recovery ID） v 的合法取值
    // 在椭圆曲线数学中，通过 r 和 s 计算出的签名点在曲线上可能有多个。
    // 为了能从签名中直接recover出公钥（即地址），需要一个额外的标记 v。
    // 根据以太坊早期标准（继承自比特币），v 的取值被设定为 27 或 28。
    // 如果遇到 v 为 0 或 1，那通常是原始的 ECDSA 结果；如果是 27 或 28，则是以太坊格式。
    // 代码通过这两个常量来剔除不符合规范的非法签名。
    uint8 constant RECOVERY_ID_27 = 27;
    uint8 constant RECOVERY_ID_28 = 28;

    // Constant representing half of the curve order (secp256k1n / 2)
    // 这是 secp256k1 曲线阶（Curve Order, 记作 n）的一半
    // 在椭圆曲线算法中，如果 (r, s) 是有效的签名，那么 (r, n - s) 也是有效的，且指向同一个地址
    // 对策：以太坊通过 EIP-2 强制要求所有的 s 必须小于或等于 n/2。如果提取出的 s 超过了这个常量，代码会直接判定签名非法。
    uint256 constant HALF_CURVE_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    error InvalidSignature(bytes32 signedHash);

    // signedHash，即签名对应的digest
    // signatureCalldataNegativeOffset，签名在整个 calldata 中的“倒数位置”，即从calldata的末尾往前数多少个字节是签名的开始。
    // 例如，如果签名在calldata的最末尾，signatureCalldataNegativeOffset就是65
    // 1. 为什么要使用NegativeOffset？答：允许你的函数参数是变长的（比如不确定有多少个币对）。无论前面有多少数据，只要知道签名在最后 65 字节，就能准确抓取
    // 2. 为什么用汇编更省gas？答：传统的 abi.decode(sig, (bytes32, bytes32, uint8)) 会把整个签名从 calldata 复制到 memory，这至少消耗 2000+ Gas。这段代码通过指针直接定位，开销几乎为零。
    function recoverSignerAddress(
        bytes32 signedHash,
        uint256 signatureCalldataNegativeOffset
    ) internal pure returns (address signerAddress) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            // 计算签名在 calldata 中的起始地址
            // signatureCalldataStartPos = calldata总字节长度 - 签名的倒数偏移量
            let signatureCalldataStartPos := sub(
                calldatasize(),
                signatureCalldataNegativeOffset
            )
            // 加载 r 值：从起始位置读取 32 字节
            r := calldataload(signatureCalldataStartPos)
            // 更新指针：向后移动 32 字节 (ECDSA_SIG_R_BS)
            signatureCalldataStartPos := add(
                signatureCalldataStartPos,
                ECDSA_SIG_R_BS
            )
            // 载 s 值：再读取 32 字节
            s := calldataload(signatureCalldataStartPos)
            // 更新指针：再向后移动 32 字节 (ECDSA_SIG_S_BS)
            signatureCalldataStartPos := add(
                signatureCalldataStartPos,
                ECDSA_SIG_S_BS
            )
            // 加载 v 值：读取紧随其后的 32 字节块，并取其第 0 个字节
            // 注：byte(i, x)是一个单字节提取器，即从一个 32 字节的字x中，提取出指定索引位置为i的单个字节
            v := byte(0, calldataload(signatureCalldataStartPos)) // last byte of the signature memory array
        }
        // 27 and 28 are the only two valid recovery ids used for ECDSA signatures in Ethereum
        // 校验 v 值：以太坊标准签名中 v 只能是 27 或 28
        if (v != RECOVERY_ID_27 && v != RECOVERY_ID_28) {
            revert InvalidSignature(signedHash);
        }
        // Ensure that the s value is in the lower half of the secp256k1 curve order (s < secp256k1n/2+1)
        // to avoid signature malleability issues.
        // 校验 s 值：防止“签名延展性攻击” (Signature Malleability)
        // 强制要求 s 必须在曲线的下半部分。如果 uint256(s) > HALF_CURVE_ORDER，
        // 说明这个签名可能被第三方篡改过（虽然数学上有效，但不符合以太坊规范）
        if (uint256(s) > HALF_CURVE_ORDER) {
            revert InvalidSignature(signedHash);
        }
        // 调用预编译合约 ecrecover (地址为 0x01)
        signerAddress = ecrecover(signedHash, v, r, s);
        // 如果 ecrecover 返回 0x0，说明签名在数学上是错误的（无法对应任何私钥）。
        // 必须拦截，否则在权限控制逻辑中可能会通过“未初始化地址”的漏洞
        if (signerAddress == address(0)) {
            revert InvalidSignature(signedHash);
        }
    }
}
