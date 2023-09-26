#include <iostream>
#include "communication.h"

class MyStruct
{
public:
    int var1 = 0x12345678;
    int var2 = 0x54545454;
};

class Memory
{
public:
    ~Memory()
    {
        CloseHandle(hDriver);
    }

    bool Init(int pid, HANDLE hDriver)
    {
        this->pid = pid;
        this->hDriver = hDriver;
        return true;
    }

    template <typename T>
    T Read(PVOID address)
    {
        T buffer;
        MemoryReadRequest request;
        request.PID = pid;
        request.pInAddress = address;
        request.Size = sizeof(T);
        request.pOutBuffer = &buffer;
        DWORD bytesIO = 0;
        DeviceIoControl(hDriver, IO_READ_MEMORY, &request, sizeof(request), NULL, NULL, &bytesIO, NULL);
        return buffer;
    }

    template <typename T>
    bool Write(PVOID address, T value)
    {
        MemoryWriteRequest request;
        request.PID = pid;
        request.address = address;
        request.size = sizeof(T);
        request.inBuffer = &value;
        DWORD bytesIO = 0;
        DeviceIoControl(hDriver, IO_WRITE_MEMORY, &request, sizeof(request), NULL, NULL, &bytesIO, NULL);
        return true;
    }
private:
    int pid;
    HANDLE hDriver;
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

    int PID = GetCurrentProcessId();

    Memory memory;
    memory.Init(PID, hDriver);

    MyStruct myStruct;
    myStruct.var1 = 123321;
    myStruct.var2 = 456654;

    MyStruct myStruct2 = memory.Read<MyStruct>(&myStruct);

    std::cout << "myStruct2.var1: " << std::hex << myStruct2.var1 << "\n";
    std::cout << "myStruct2.var2: " << std::hex << myStruct2.var2 << "\n";

    MyStruct myStruct3;
    myStruct3.var1 = 0x11111111;
    myStruct3.var2 = 0x22222222;

    memory.Write<MyStruct>(&myStruct, myStruct3);

    std::cout << "myStruct.var1: " << std::hex << myStruct.var1 << "\n";
    std::cout << "myStruct.var2: " << std::hex << myStruct.var2 << "\n";



    return 0;
}