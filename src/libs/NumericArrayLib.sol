// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

// 该库实现了一个专门用于uint256[] memory排序并取中位数的库
library NumericArrayLib {
    // This function sort array in memory using bubble sort algorithm,
    // which performs even better than quick sort for small arrays

    uint256 constant BYTES_ARR_LEN_VAR_BS = 32;
    uint256 constant UINT256_VALUE_BS = 32;

    error CanNotPickMedianOfEmptyArray();

    // This function modifies the array
    // 从数组中找到中位数（会对该数组排序）
    function pickMedian(uint256[] memory arr) internal pure returns (uint256) {
        // 特意处理了 length == 2 的情况，直接取平均值，避免了进入排序循环
        if (arr.length == 2) {
            return (arr[0] + arr[1]) / 2;
        }
        // 空数组，报错
        if (arr.length == 0) {
            revert CanNotPickMedianOfEmptyArray();
        }
        sort(arr);
        // 计算中位数index
        uint256 middleIndex = arr.length / 2;
        // 如果数组中元素个数为偶数，取中间对称的两个元素值的均值
        if (arr.length % 2 == 0) {
            uint256 sum = arr[middleIndex - 1] + arr[middleIndex];
            return sum / 2;
        } else {
            // 如果数组元素个数为奇数，取中间的元素中
            return arr[middleIndex];
        }
    }

    // 冒泡排序
    function sort(uint256[] memory arr) internal pure {
        assembly {
            // 数组长度
            let arrLength := mload(arr)
            // 元素开始的指针
            let valuesPtr := add(arr, BYTES_ARR_LEN_VAR_BS)
            // 元素结束的指针
            let endPtr := add(valuesPtr, mul(arrLength, UINT256_VALUE_BS))
            // for(arrIPtr=valuesPtr;arrIPtr<endPtr;arrIPtr+=32){}
            // 即for(i=0;i<arr.length;i++){}
            for {
                let arrIPtr := valuesPtr
            } lt(arrIPtr, endPtr) {
                arrIPtr := add(arrIPtr, UINT256_VALUE_BS) // arrIPtr += 32
            } {
                // for(arrJPtr := valuesPtr;arrJPtr<arrIPtr;arrJPtr+=32){}
                // 即for(j=0;j<i;j++){}
                for {
                    let arrJPtr := valuesPtr
                } lt(arrJPtr, arrIPtr) {
                    arrJPtr := add(arrJPtr, UINT256_VALUE_BS) // arrJPtr += 32
                } {
                    // arr[i]
                    let arrI := mload(arrIPtr)
                    // arr[j]
                    let arrJ := mload(arrJPtr)
                    // 如果arr[i]<arr[j]，arr[i],arr[j]=arr[j],arr[i]
                    if lt(arrI, arrJ) {
                        mstore(arrIPtr, arrJ)
                        mstore(arrJPtr, arrI)
                    }
                }
            }
        }
    }
}
