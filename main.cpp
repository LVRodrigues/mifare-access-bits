#include <iostream>
#include <cstddef>

#include "mifare-access-bits.h"

int main(int, char**) {
    MifareAccessBits bits;

    std::cout << "Block 0.: " << bits.getBlock0() << std::endl;
    std::cout << "Block 1.: " << bits.getBlock1() << std::endl;
    std::cout << "Block 2.: " << bits.getBlock2() << std::endl;
    std::cout << "Trailler: " << bits.getTrailler() << std::endl;

    MifareAccessBits::AccessConditions &conditions = bits.value();

    std::cout << std::hex << (int) conditions[0] << std::endl;
    std::cout << std::hex << (int) conditions[1] << std::endl;
    std::cout << std::hex << (int) conditions[2] << std::endl;
    
    return EXIT_SUCCESS;
}
