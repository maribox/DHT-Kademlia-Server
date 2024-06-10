#pragma once
#include <bitset>
#include <cstddef> //size_t

constexpr size_t KEYSIZE = 256;
template<int N>
struct BitsetComparator {
    bool operator()(const std::bitset<KEYSIZE>& lhs, const std::bitset<KEYSIZE>& rhs) const {
        for (size_t i = KEYSIZE; i > 0; --i) {
            if (lhs[i-1] != rhs[i-1]) {
                return lhs[i-1] < rhs[i-1];
            }
        }
        return false; // identical bitsets
    }
};