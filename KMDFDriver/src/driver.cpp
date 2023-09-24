#include "driver.h"
#include "messages.h"

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
