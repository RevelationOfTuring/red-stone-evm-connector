// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.17;

import "./RedstoneConstants.sol";
import "./CalldataExtractor.sol";

/**
 * @title The base contract for forwarding redstone payload to other contracts
 * @author The Redstone Oracles team
 */

// ProxyConnector是Redstone架构中的“中继转换器”。它的核心逻辑非常暴力且高效：
// 手动重组内存，将 Redstone 数据包“嫁接”到普通的函数调用数据之后，然后通过底层的 call 发送出去。
// 它解决了这样一个问题：如果目标合约（如一个 DEX）需要预言机数据，但原始交易的 msg.data 里没带这些数据，
// ProxyConnector 负责把本交易末尾携带的 Redstone Payload 抠出来，拼接到发往 DEX 的指令后面。
// 使用场景：
// 它是一个“数据中转站”，允许你在面对那些“固定的、不可更改的第三方接口（如 Uniswap 回调uniswapV2Call(address sender, uint amount0, uint amount1, bytes data)）”时，
// 依然能把红石价格数据像“穿山甲”一样传导到最终需要它的地方。
// 例如：你在写一个“聚合器”或“策略路由” (Router/Aggregator)，你的合约本身不存钱，它的工作是调用别人的合约（比如调 Uniswap，再调 Curve）。
// 别人发给你的 msg.data 带有红石数据，但当你用 call 去调下游合约时，数据会丢失。
// 此时我的合约继承ProxyConnector，是为了用它的 proxyCall 自动把那份数据“缝补”到发往下游的指令中。
// 总结：
// 1. 做业务（DEX/Lending）： 继承 RedstoneConsumerBase。
// 2. 做工具（Router/Proxy/Wallet）： 继承 ProxyConnector。
contract ProxyConnector is RedstoneConstants, CalldataExtractor {
    error ProxyCalldataFailedWithoutErrMsg();
    error ProxyCalldataFailedWithStringMessage(string message);
    error ProxyCalldataFailedWithCustomError(bytes result);

    // 本合约提供了三种代理模式，覆盖了所有链上交互场景

    // 用于call，支持发送 msg.value（ETH）
    function proxyCalldata(
        // 目标合约地址
        address contractAddress,
        // 原始业务外部call到calldata
        bytes memory encodedFunction,
        // 如果为true，表示要携带eth来call
        bool forwardValue
    ) internal returns (bytes memory) {
        // 拼接原始业务调用的calldata和redstone的数据到内存中
        bytes memory message = _prepareMessage(encodedFunction);

        // 进行call
        (bool success, bytes memory result) = contractAddress.call{
            value: forwardValue ? msg.value : 0
        }(message);

        return _prepareReturnValue(success, result);
    }

    // 用于 delegatecall（通常用于代理合约升级或库调用），在当前上下文执行代码
    function proxyDelegateCalldata(
        address contractAddress,
        bytes memory encodedFunction
    ) internal returns (bytes memory) {
        bytes memory message = _prepareMessage(encodedFunction);
        (bool success, bytes memory result) = contractAddress.delegatecall(
            message
        );
        return _prepareReturnValue(success, result);
    }

    // 用于读操作（staticcall），不允许修改状态
    function proxyCalldataView(
        address contractAddress,
        bytes memory encodedFunction
    ) internal view returns (bytes memory) {
        bytes memory message = _prepareMessage(encodedFunction);
        (bool success, bytes memory result) = contractAddress.staticcall(
            message
        );
        return _prepareReturnValue(success, result);
    }

    // 核心拼装函数（内存重组）
    // 它在内存中手动构建了一个新的字节数组，将内存中原始业务调用的calldata encodedFunction和redstone的calldata数据拼接在一起
    function _prepareMessage(
        bytes memory encodedFunction
    ) private pure returns (bytes memory) {
        // 原始函数调用（如 swapExactTokens）的calldata字节长度
        uint256 encodedFunctionBytesCount = encodedFunction.length;
        // 计算末尾 Redstone 数据的总长度
        uint256 redstonePayloadByteSize = _getRedstonePayloadByteSize();
        // 总拼接长度
        uint256 resultMessageByteSize = encodedFunctionBytesCount +
            redstonePayloadByteSize;

        // 该检查看似无用（因为redstonePayloadByteSize 是从 msg.data 中解析出来的），但是是为了保证后面
        // 汇编中的 sub(calldatasize(), redstonePayloadByteSize)不会发生向下溢出
        if (redstonePayloadByteSize > msg.data.length) {
            revert CalldataOverOrUnderFlow();
        }

        bytes memory message;

        assembly {
            // 从 0x40 处读取“空闲内存指针”，作为新数组 message 的起始地址
            message := mload(FREE_MEMORY_PTR) // sets message pointer to first free place in memory

            // Saving the byte size of the result message (it's a standard in EVM)
            // 按照 Solidity 字节数组的标准格式，在 message 的前 32 字节写入数组的总长度
            mstore(message, resultMessageByteSize)

            // Copying function and its arguments
            //
            for {
                // from起始是指向内存中encodedFunction的数据起始位置
                let from := add(BYTES_ARR_LEN_VAR_BS, encodedFunction)
                // encodedFunction的数据结束位置
                let fromEnd := add(from, encodedFunctionBytesCount)
                // to起始是指向内存中message的数据起始位置
                let to := add(BYTES_ARR_LEN_VAR_BS, message)
                // 循环条件：from<fromEnd
            } lt(from, fromEnd) {
                // from和to指针每次都想后移动32字节
                from := add(from, STANDARD_SLOT_BS)
                to := add(to, STANDARD_SLOT_BS)
            } {
                // Copying data from encodedFunction to message (32 bytes at a time)
                // 从encodedFunction每次读取 32 字节并存入message
                mstore(to, mload(from))
            }

            // Copying redstone payload to the message bytes
            // 直接从 calldata 中提取原始数据，接着拼接到message的末尾
            // 注：calldatacopy(destOffset, offset, size)，calldata的offset位置开始，将数据复制到destOffset开始的内存中，复制的字节个数为size
            calldatacopy(
                // 要复制到的内存的起始地址，即message + 32字节长度位 + 已复制的encodedFunction的数据
                // 其实就是接着刚才复制完encodedFunction的数据，接着复制redstone的数据
                add(
                    message,
                    add(BYTES_ARR_LEN_VAR_BS, encodedFunctionBytesCount)
                ), // address
                // calldata中redstone数据的起始正偏移量
                sub(calldatasize(), redstonePayloadByteSize), // offset
                // 复制的字节个数为redstone的数据总字节数
                redstonePayloadByteSize // bytes length to copy
            )

            // Updating free memory pointer
            // 更新空闲内存指针
            // 这是 assembly 编程的优良习惯，防止后续代码覆盖这块新数据
            mstore(
                FREE_MEMORY_PTR,
                // 将空闲指针改为message + 32字节长度位 + encodedFunctionBytesCount + redstonePayloadByteSize
                add(
                    add(
                        message,
                        add(redstonePayloadByteSize, encodedFunctionBytesCount)
                    ),
                    BYTES_ARR_LEN_VAR_BS
                )
            )
        }

        // 此时的message的数据内容就是encodedFunction + redstone数据
        return message;
    }

    // 这个函数的作用是计算 Calldata 末尾到底挂了多少字节的 Redstone 数据
    // 注：返回值其实就是从calldata的末尾开始一直向前找，直到找到Data Packages中第一个Data Package的负偏移量
    function _getRedstonePayloadByteSize() private pure returns (uint256) {
        // 跳过 Unsigned Metadata，此时calldataNegativeOffset其实就是从calldata末尾到Unsigned Metadata Content开始的字节长度
        uint256 calldataNegativeOffset = _extractByteSizeOfUnsignedMetadata();
        // 读取 Data Packages Count
        uint256 dataPackagesCount;
        (
            dataPackagesCount,
            calldataNegativeOffset
        ) = _extractDataPackagesCountFromCalldata(calldataNegativeOffset);
        // 此时，calldataNegativeOffset已经变为从calldata末尾到Data Packages Count开始的字节长度

        // 遍历每个Data Pacakge，累加其中各个Data Pacakge的字节长度
        for (
            uint256 dataPackageIndex = 0;
            dataPackageIndex < dataPackagesCount;
            dataPackageIndex++
        ) {
            // 获取各个pacakge的字节长度
            uint256 dataPackageByteSize = _getDataPackageByteSize(
                calldataNegativeOffset
            );
            // 累加
            calldataNegativeOffset += dataPackageByteSize;
        }

        // 此时的累积总的负偏移量其实就是redstone的总数据字节长度
        return calldataNegativeOffset;
    }

    // 当通过 call 或 delegatecall 转发的消息执行完毕后，这个函数负责解析返回的结果：
    // 如果成功，原样返回；如果失败，则解码并抛出最精准的错误信息
    function _prepareReturnValue(
        bool success,
        bytes memory result
    ) internal pure returns (bytes memory) {
        // 如果外部调用失败（说明目标合约执行了 revert 或遇到了 Panic）
        if (!success) {
            if (result.length == 0) {
                // 有些外部合约调用报错不带任何描述（例如 revert()）。
                // 如果返回的字节数组长度为 0，则抛出 Redstone 预设的通用错误
                revert ProxyCalldataFailedWithoutErrMsg();
            } else {
                // 如果外部合约调用报错有描述，来识别错误的类型
                bool isStringErrorMessage;
                assembly {
                    // 提取返回数据的前 32 字节
                    let first32BytesOfResult := mload(
                        add(result, BYTES_ARR_LEN_VAR_BS)
                    )
                    // STRING_ERR_MESSAGE_MASK 是 Error(string) 的 Selector: 0x08c379a0...
                    // 如果内存中返回数据的第一个32字节==STRING_ERR_MESSAGE_MASK，说明外部revert的类型是revert(string)
                    // 注：这里其实隐藏了一个 Redstone 的假设（或者说简化）：
                    //  在绝大多数 Solidity 编译器生成的 revert(string) 代码中，由于 Error 函数只有一个参数，偏移量通常是固定的（通常为0x20）。
                    //  Redstone 的开发者可能认为，只要前 4 字节匹配，后面那 28 字节即使不全是 0，但在那种特定的内存分布下，通过这种方式能快速过滤出报错类型。
                    // 如果要做到100%严谨，应该这样写：只保留前 4 字节进行比对
                    //          isStringErrorMessage := eq(
                    //              and(
                    //                  first32BytesOfResult,
                    //                  0xffffffff00000000000000000000000000000000000000000000000000000000
                    //              ),
                    //              STRING_ERR_MESSAGE_MASK
                    //          )
                    isStringErrorMessage := eq(
                        first32BytesOfResult,
                        STRING_ERR_MESSAGE_MASK
                    )
                }

                if (isStringErrorMessage) {
                    // 如果是revert(string)触发的revert
                    string memory receivedErrMsg;
                    assembly {
                        // receivedErrMsg为result+4+32+32，直接是revert string的数据起始位置
                        receivedErrMsg := add(result, REVERT_MSG_OFFSET)
                    }

                    // 将提取到的 receivedErrMsg 包装进 ProxyCalldataFailedWithStringMessage 抛出，方便前端或开发者查看
                    revert ProxyCalldataFailedWithStringMessage(receivedErrMsg);
                } else {
                    // 如果不是标准字符串（比如是 Solidity 0.8+ 的 error MyError(uint256)），则将原始的 bytes 数据包装在 ProxyCalldataFailedWithCustomError 中抛出
                    revert ProxyCalldataFailedWithCustomError(result);
                }
            }
        }
        //如果 success 为 true，不做任何修改，直接将目标合约返回的数据返回给调用者
        return result;
    }
}
