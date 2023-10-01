#include "driver.h"
#include "messages.h"
#include "memory.h"
#include "manuelmap.h"

#include <ntddk.h>

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    DebugMessage("Driver Loading\n");
    UNREFERENCED_PARAMETER(pRegistryPath);

    NTSTATUS status;

    pDriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload;

    RtlInitUnicodeString(&g_Dev, L"\\Device\\MyDriver");
    RtlInitUnicodeString(&g_Dos, L"\\DosDevices\\MyDriver");

    status = IoCreateDevice(pDriverObject, 0, &g_Dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_pDeviceObject);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("Failed to create device (IoCreateDevice), Error: 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_Dos, &g_Dev);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("Failed to create symbolic link (IoCreateSymbolicLink), Error: 0x%08X\n", status);
        IoDeleteDevice(g_pDeviceObject);
        return status;
    }

    pDriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)CreateCall;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)CloseCall;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)IoControl;

    g_pDeviceObject->Flags |= DO_DIRECT_IO;
    g_pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    DebugMessage("Driver Unloading\n");
    UNREFERENCED_PARAMETER(pDriverObject);

    IoDeleteSymbolicLink(&g_Dos);
    IoDeleteDevice(g_pDeviceObject);

    return STATUS_SUCCESS;
}

NTSTATUS CreateCall(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    DebugMessage("Creating call from user mode\n");
    UNREFERENCED_PARAMETER(pDeviceObject);

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    DebugMessage("Closing call from user mode\n");
    UNREFERENCED_PARAMETER(pDeviceObject);

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS IoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    DebugMessage("IOCTL Called\n");
    UNREFERENCED_PARAMETER(pDeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesIO = 0;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);

    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (controlCode)
    {
        case IO_GET_CLIENT_ADDRESS:
        {
            DebugMessage("IOCTL: IO_GET_CLIENT_ADDRESS\n");
            PULONG OutBuffer = (PULONG)pIrp->AssociatedIrp.SystemBuffer;
            *OutBuffer = 0x12345678;
            bytesIO = sizeof(ULONG);
            break;
        }
        // TEST AMAÇLI EKLENDÝ
        case IO_GET_MY_CLASS:
        {
            DebugMessage("IOCTL: IO_GET_MY_CLASS\n");
            PCommonClass* OutBuffer = (PCommonClass*)pIrp->AssociatedIrp.SystemBuffer;
            OutBuffer->v1 = 1;
            OutBuffer->v2 = 3;
            bytesIO = sizeof(PCommonClass);
            break;
        }
        // END TEST
        case IO_READ_MEMORY:
        {
            DebugMessage("IOCTL: IO_READ_MEMORY\n");
            MemoryReadRequest* pRequest = (MemoryReadRequest*)pIrp->AssociatedIrp.SystemBuffer;

            PVOID pInAddress = pRequest->pInAddress;
            SIZE_T Size = pRequest->Size;
            INT PID = pRequest->PID;

            DebugMessage("IOCTL: IO_READ_MEMORY: PID: %d, Address: 0x%p, Size: %llu\n", PID, pInAddress, Size);

            PEPROCESS Process;
            status = PsLookupProcessByProcessId((HANDLE)PID, &Process);
            if (!NT_SUCCESS(status))
            {
                DebugMessage("IOCTL: IO_READ_MEMORY: PsLookupProcessByProcessId failed, Error: 0x%08X\n", status);
                break;
            }

            status = Memory::Read(Process, pInAddress, pRequest->pOutBuffer, Size);
            if (!NT_SUCCESS(status))
            {
                DebugMessage("IOCTL: IO_READ_MEMORY: Memory::Read failed, Error: 0x%08X\n", status);
                break;
            }

            bytesIO = sizeof(MemoryReadRequest*);
            break;
        }
        case IO_WRITE_MEMORY:
        {
            DebugMessage("IOCTL: IO_WRITE_MEMORY\n");
            MemoryWriteRequest* pRequest = (MemoryWriteRequest*)pIrp->AssociatedIrp.SystemBuffer;

            PVOID pInAddress = pRequest->address;
            SIZE_T Size = pRequest->size;
            INT PID = pRequest->PID;

            DebugMessage("IOCTL: IO_WRITE_MEMORY: PID: %d, Address: 0x%p, Size: %llu\n", PID, pInAddress, Size);

            PEPROCESS Process;
            status = PsLookupProcessByProcessId((HANDLE)PID, &Process);
            if (!NT_SUCCESS(status))
            {
                DebugMessage("IOCTL: IO_WRITE_MEMORY: PsLookupProcessByProcessId failed, Error: 0x%08X\n", status);
                break;
            }

            status = Memory::Write(Process, pInAddress, pRequest->inBuffer, Size);
            if (!NT_SUCCESS(status))
            {
                DebugMessage("IOCTL: IO_WRITE_MEMORY: Memory::Write failed, Error: 0x%08X\n", status);
                break;
            }

            bytesIO = sizeof(MemoryWriteRequest*);
            break;
        }
        case IO_MANUEL_MAP_DLL:
        {
            DebugMessage("IOCTL: IO_MANUEL_MAP_DLL\n");
            ManuelMapRequest* pRequest = (ManuelMapRequest*)pIrp->AssociatedIrp.SystemBuffer;

            DWORD ThreadId = (DWORD)pRequest->PID;
            // UNICODE_STRING DllPath = pRequest->DllPath;

            // DebugMessage("IOCTL: IO_MANUEL_MAP_DLL: ThreadID: %d, DllPath: %wZ\n", ThreadId, DllPath);
            DebugMessage("IOCTL: IO_MANUEL_MAP_DLL: ThreadID: %d\n", ThreadId);
            
            // Get PETHREAD from ThreadId
            DebugMessage("IOCTL: IO_MANUEL_MAP_DLL: PsLookupThreadByThreadId\n");
            PETHREAD PEThread;
            status = PsLookupThreadByThreadId((HANDLE)ThreadId, &PEThread);
            if (!NT_SUCCESS(status))
            {
                DebugMessage("IOCTL: IO_MANUEL_MAP_DLL: PsLookupThreadByThreadId failed, Error: 0x%08X\n", status);
                break;
            }

            DebugMessage("IOCTL: IO_MANUEL_MAP_DLL: PsLookupThreadByThreadId success\n");

            Suspender PsSuspendThread;
            UNICODE_STRING routineName;
            RtlInitUnicodeString(&routineName, L"PsSuspendProcess");
            PsSuspendThread = (Suspender)((ULONG64)MmGetSystemRoutineAddress(&routineName) + (0x160));

            DebugMessage("IOCTL: IO_MANUEL_MAP_DLL: PsSuspendThread: 0x%p\n", PsSuspendThread);

            // Stop the execution of thread in the process
            ULONG junq;
            status = PsSuspendThread(PEThread, &junq);
            if (!NT_SUCCESS(status))
            {
                DebugMessage("IOCTL: IO_MANUEL_MAP_DLL: PsSuspendThread failed, Error: 0x%08X\n", status);
                break;
            }

            DebugMessage("IOCTL: IO_MANUEL_MAP_DLL: PsSuspendThread success\n");

            break;
        }
        default:
        {
            DebugMessage("IOCTL: Invalid Device Request\n");
            bytesIO = 0;
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = bytesIO;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}
