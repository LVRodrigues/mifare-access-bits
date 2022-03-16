/**
 * @file mifare-access-bits.cpp
 * @author Luciano Vieira Rodrigues (luciano.vieira@digicon.com.br)
 * @brief Implementação de mifare-acess-bits.h
 * @version 1.0
 * @date 2021-12-13
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "mifare-access-bits.h"
#include <iostream>
#include <bitset>

std::ostream& operator<<(std::ostream& os, const MifareAccessBits::DataCondition& condition) {
    switch (condition) {
        case MifareAccessBits::KEYAB__KEYAB__KEYAB__KEYAB:
            os << "[Read: Key A|B; Write: Key A|B; Increment: Key A|B; Decrement, Transfer, Restore: Key A|B]";
            os << " (read/write block)";
            break;
        case MifareAccessBits::KEYAB__NEVER__NEVER__NEVER:
            os << "[Read: Key A|B; Write: never; Increment: never; Decrement, Transfer, Restore: never]";
            os << " (read/write block)";
            break;
        case MifareAccessBits::KEYAB__KEYB___NEVER__NEVER:
            os << "[Read: Key A|B; Write: Key B; Increment: never; Decrement, Transfer, Restore: never]";
            os << " (value block)";
            break;
        case MifareAccessBits::KEYAB__KEYB___KEYB___KEYAB:
            os << "[Read: Key A|B; Write: Key B; Increment: Key B; Decrement, Transfer, Restore: Key A|B]";
            os << " (value block)";
            break;
        case MifareAccessBits::KEYAB__NEVER__NEVER__KEYAB:
            os << "[Read: Key A|B; Write: never; Increment: never; Decrement, Transfer, Restore: Key A|B]";
            os << " (read/write block)";
            break;
        case MifareAccessBits::KEYB___KEYB___NEVER__NEVER:
            os << "[Read: Key B; Write: Key B; Increment: never; Decrement, Transfer, Restore: never]";
            os << " (read/write block)";
            break;
        case MifareAccessBits::KEYB___NEVER__NEVER__NEVER:
            os << "[Read: Key B; Write: never; Increment: never; Decrement, Transfer, Restore: never]";
            os << " (read/write block)";
            break;
        case MifareAccessBits::NEVER__NEVER__NEVER__NEVER:
            os << "[Read: never; Write: never; Increment: never; Decrement, Transfer, Restore: never]";
            os << " (read/write block)";
            break;
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const MifareAccessBits::TraillerCondition& condition) {
    switch (condition) {
        case MifareAccessBits::NEVER__KEYA___KEYA___NEVER__KEYA___KEYA: 
            os << "[Read Key A: never; Write Key A: Key A; Read Access Bits: Key A; Write Access Bits: never; Read Key B: Key A; Write Key B: Key A]";
            break;
        case MifareAccessBits::NEVER__NEVER__KEYA___NEVER__KEYA___NEVER:
            os << "[Read Key A: never; Write Key A: never; Read Access Bits: Key A; Write Access Bits: never; Read Key B: Key A; Write Key B: never]";
            break;
        case MifareAccessBits::NEVER__KEYB___KEYAB__NEVER__NEVER__KEYB:
            os << "[Read Key A: never; Write Key A: Key B; Read Access Bits: Key A|B; Write Access Bits: never; Read Key B: never; Write Key B: Key B]";
            break;
        case MifareAccessBits::NEVER__NEVER__KEYAB__NEVER__NEVER__NEVER:
            os << "[Read Key A: never; Write Key A: never; Read Access Bits: Key A|B; Write Access Bits: never; Read Key B: never; Write Key B: never]";
            break;
        case MifareAccessBits::NEVER__KEYA___KEYA___KEYA___KEYA___KEYA:
            os << "[Read Key A: never; Write Key A: Key A; Read Access Bits: Key A; Write Access Bits: Key A; Read Key B: Key A; Write Key B: Key A]";
            break;
        case MifareAccessBits::NEVER__KEYB___KEYAB__KEYB___NEVER__KEYB:
            os << "[Read Key A: never; Write Key A: Key B; Read Access Bits: Key A|B; Write Access Bits: Key B; Read Key B: never; Write Key B: Key B]";
            break;
        case MifareAccessBits::NEVER__NEVER__KEYAB__KEYB___NEVER__NEVER:
            os << "[Read Key A: never; Write Key A: never; Read Access Bits: Key A|B; Write Access Bits: Key B; Read Key B: never; Write Key B: never]";
            break;
        case MifareAccessBits::NEVER__NEVER__KEYAB__NEVER__NEVER__NEVEREX:
            os << "[Read Key A: never; Write Key A: never; Read Access Bits: Key A|B; Write Access Bits: never; Read Key B: never; Write Key B: never]";
            break;
    }
    return os;
}

MifareAccessBits::AccessBits MifareAccessBits::getDataCondition(MifareAccessBits::DataCondition condition) {
    AccessBits result;
    switch (condition) {
        case MifareAccessBits::KEYAB__KEYAB__KEYAB__KEYAB:
            result.c1 = false; result.c2 = false; result.c3 = false;
            break;
        case MifareAccessBits::KEYAB__NEVER__NEVER__NEVER:
            result.c1 = false; result.c2 = true; result.c3 = false;
            break;
        case MifareAccessBits::KEYAB__KEYB___NEVER__NEVER:
            result.c1 = true; result.c2 = false; result.c3 = false;
            break;
        case MifareAccessBits::KEYAB__KEYB___KEYB___KEYAB:
            result.c1 = true; result.c2 = true; result.c3 = false;
            break;
        case MifareAccessBits::KEYAB__NEVER__NEVER__KEYAB:
            result.c1 = false; result.c2 = false; result.c3 = true;
            break;
        case MifareAccessBits::KEYB___KEYB___NEVER__NEVER:
            result.c1 = false; result.c2 = true; result.c3 = true;
            break;
        case MifareAccessBits::KEYB___NEVER__NEVER__NEVER:
            result.c1 = true; result.c2 = false; result.c3 = true;
            break;
        case MifareAccessBits::NEVER__NEVER__NEVER__NEVER:
            result.c1 = true; result.c2 = true; result.c3 = true;
            break;
    }
    return result;
}

MifareAccessBits::AccessBits MifareAccessBits::getTraillerCondition(MifareAccessBits::TraillerCondition condition) {
    AccessBits result;
    switch (condition) {
        case MifareAccessBits::NEVER__KEYA___KEYA___NEVER__KEYA___KEYA: 
            result.c1 = false; result.c2 = false; result.c3 = false;
            break;
        case MifareAccessBits::NEVER__NEVER__KEYA___NEVER__KEYA___NEVER:
            result.c1 = false; result.c2 = true; result.c3 = false;
            break;
        case MifareAccessBits::NEVER__KEYB___KEYAB__NEVER__NEVER__KEYB:
            result.c1 = true; result.c2 = false; result.c3 = false;
            break;
        case MifareAccessBits::NEVER__NEVER__KEYAB__NEVER__NEVER__NEVER:
            result.c1 = true; result.c2 = true; result.c3 = false;
            break;
        case MifareAccessBits::NEVER__KEYA___KEYA___KEYA___KEYA___KEYA:
            result.c1 = false; result.c2 = false; result.c3 = true;
            break;
        case MifareAccessBits::NEVER__KEYB___KEYAB__KEYB___NEVER__KEYB:
            result.c1 = false; result.c2 = true; result.c3 = true;
            break;
        case MifareAccessBits::NEVER__NEVER__KEYAB__KEYB___NEVER__NEVER:
            result.c1 = true; result.c2 = false; result.c3 = true;
            break;
        case MifareAccessBits::NEVER__NEVER__KEYAB__NEVER__NEVER__NEVEREX:
            result.c1 = true; result.c2 = true; result.c3 = true;
            break;
    }
    return result;
}

MifareAccessBits::AccessConditions& MifareAccessBits::value() {
    static MifareAccessBits::AccessConditions result;
    std::bitset<8> b6;
    std::bitset<8> b7;
    std::bitset<8> b8;

    // Bloco 0:
    AccessBits b0 = getDataCondition(block0);
    b6.set(0, !b0.c1);
    b7.set(4, b0.c1);
    b6.set(4, !b0.c2);
    b8.set(0, b0.c2);
    b7.set(0, !b0.c3);
    b8.set(4, b0.c3);

    // Bloco 1:
    AccessBits b1 = getDataCondition(block1);
    b6.set(1, !b1.c1);
    b7.set(5, b1.c1);
    b6.set(5, !b1.c2);
    b8.set(1, b1.c2);
    b7.set(1, !b1.c3);
    b8.set(5, b1.c3);

    // Bloco 2:
    AccessBits b2 = getDataCondition(block2);
    b6.set(2, !b2.c1);
    b7.set(6, b2.c1);
    b6.set(6, !b2.c2);
    b8.set(2, b2.c2);
    b7.set(2, !b2.c3);
    b8.set(6, b2.c3);
    
    AccessBits t0 = getTraillerCondition(trailler);
    b6.set(3, !t0.c1);
    b7.set(7, t0.c1);
    b6.set(7, !t0.c2);
    b8.set(3, t0.c2);
    b7.set(3, !t0.c3);
    b8.set(7, t0.c3);

    result[0] = b6.to_ulong();
    result[1] = b7.to_ulong();
    result[2] = b8.to_ulong();
    return result;
}
