#include <iostream>
#include "communication.h"

int main()
{
    std::cout << "Hello World!\n";
    HANDLE hDriver = CreateFileA("\\\\.\\MyDriver", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    if (hDriver == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to get a handle to the driver\n";
        return 1;
    }

    ULONG Address = 0;
    DWORD BytesReturned = 0;

    DeviceIoControl(hDriver, IO_GET_CLIENT_ADDRESS, &Address, sizeof(Address), &Address, sizeof(Address), &BytesReturned, NULL);
    std::cout << "Address: " << std::hex << Address << std::endl;

}