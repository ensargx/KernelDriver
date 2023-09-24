#pragma once

#include <ntifs.h>

PDEVICE_OBJECT g_pDeviceObject = NULL;
UNICODE_STRING g_Dev, g_Dos;

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

extern "C" NTSTATUS NTAPI DriverUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS CreateCall(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

NTSTATUS CloseCall(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

NTSTATUS IoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);