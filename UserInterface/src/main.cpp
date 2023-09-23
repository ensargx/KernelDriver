#include <iostream>
#include "communication.h"

int main()
{
    KernelInterface kernelInterface = KernelInterface("\\\\.\\MyDriver");
    ULONG Address = kernelInterface.GetClientAddress();
    std::cout << "Client address: 0x" << std::hex << Address << std::endl;
    return 0;
}