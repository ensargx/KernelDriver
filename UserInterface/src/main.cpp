#include <iostream>
#include "communication.h"

class CommonClass
{
public:
    int v1 = 0;
    int v2 = 2;
};

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

    MemoryReadRequest request;
    
    // Get current process ID
    request.PID = GetCurrentProcessId();

    int ChangeMe = 0x51;
    request.pInAddress = &ChangeMe;
    request.Size = sizeof(int);

    int outBuffer = 100;
    request.pOutBuffer = &outBuffer;
    DWORD bytesIO = 0;

    DeviceIoControl(hDriver, IO_READ_MEMORY, &request, sizeof(request), NULL, NULL, &bytesIO, NULL);

    std::cout << "Out: ";
    std::cout << "0x" << std::hex << outBuffer << "\n";

    return 0;
}