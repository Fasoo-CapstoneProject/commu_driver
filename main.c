#include <ntifs.h>
#include <string.h>
#include <stdbool.h>

#define SIOCTL_TYPE 40000
#define IOCTL_HELLO\
 CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)


const WCHAR deviceNameBuffer[] = L"\\Device\\MYDEVICE";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\MyDevice";
PDEVICE_OBJECT g_MyDevice; // Global pointer to our device object

PVOID string = 0;
UNICODE_STRING direc;
UNICODE_STRING sid;

DECLARE_CONST_UNICODE_STRING(DOC, L".doc");
DECLARE_CONST_UNICODE_STRING(DOCX, L".docx");
DECLARE_CONST_UNICODE_STRING(XLS, L".xls");
DECLARE_CONST_UNICODE_STRING(XLSX, L".xlsx");
DECLARE_CONST_UNICODE_STRING(TXT, L".txt");

static const UNICODE_STRING* extensions[] = { &DOC, &DOCX, &XLS, &XLSX, &TXT };


bool
equal_tail_unicode_string(
	_In_ const PUNICODE_STRING full,
	_In_ const PUNICODE_STRING tail,
	_In_ bool case_insensitive
)
{
	ULONG i;
	USHORT full_count;
	USHORT tail_count;

	if (full == NULL || tail == NULL) return false;

	full_count = full->Length / sizeof(WCHAR);
	tail_count = tail->Length / sizeof(WCHAR);

	if (full_count < tail_count) return false;
	if (tail_count == 0) return false;

	if (case_insensitive)
	{
		for (i = 1; i <= tail_count; ++i)
		{
			if (RtlUpcaseUnicodeChar(full->Buffer[full_count - i]) !=
				RtlUpcaseUnicodeChar(tail->Buffer[tail_count - i]))
				return false;
		}
	}
	else
	{
		for (i = 1; i <= tail_count; ++i)
		{
			if (full->Buffer[full_count - i] != tail->Buffer[tail_count - i])
				return false;
		}
	}

	return true;
}



NTSTATUS Function_IRP_MJ_CREATE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("IRP MJ CREATE received.\n");
	return STATUS_SUCCESS;
}


NTSTATUS Function_IRP_MJ_CLOSE(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	DbgPrint("IRP MJ CLOSE received.\n");
	return STATUS_SUCCESS;
}


NTSTATUS Function_IRP_DEVICE_CONTROL(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	PIO_STACK_LOCATION pIoStackLocation;
	PCHAR welcome = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
	PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (pIoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_HELLO:
		DbgPrint("IOCTL HELLO.\n");
		DbgPrint("Message received : %s\n", pBuf);
		string = pBuf;

		ANSI_STRING astr = { 0 };
		UNICODE_STRING ustr = { 0 };
		RtlInitAnsiString(&astr, (PCHAR)string);
		RtlAnsiStringToUnicodeString(&ustr, &astr, TRUE);

		UNICODE_STRING txt_file;
		RtlInitUnicodeString(&txt_file, L".txt");

			if (true == equal_tail_unicode_string(&ustr, &txt_file, true))
			{
				DbgPrint("extension matched.\n");
				direc = ustr;
			}
			else
			{
				DbgPrint("no extension.\n");
				sid = ustr;
			}

		DbgPrint("directory: %wZ\n", direc);
		DbgPrint("SID: %wZ\n", sid);
			 
		RtlZeroMemory(pBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);

		break;
	}

	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = strlen(welcome);
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


VOID OnUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING symLink;

	RtlInitUnicodeString(&symLink, deviceSymLinkBuffer);

	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(pDriverObject->DeviceObject);

	DbgPrint("OnUnload called!");
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject,
	IN PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS ntStatus = 0;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	// Normalize name and symbolic link.
	RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, deviceSymLinkBuffer);

	// Create the device.
	ntStatus = IoCreateDevice(pDriverObject,
		0, // For driver extension
		&deviceNameUnicodeString,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_UNKNOWN,
		FALSE,
		&g_MyDevice);

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);

	pDriverObject->DriverUnload = OnUnload;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Function_IRP_MJ_CREATE;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Function_IRP_MJ_CLOSE;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Function_IRP_DEVICE_CONTROL;

	DbgPrint("Loading driver\n");

	return STATUS_SUCCESS;
}