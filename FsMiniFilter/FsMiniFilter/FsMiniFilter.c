#include <fltKernel.h>
#include <ntifs.h>
#include <fltKernel.h>
#include <ntstrsafe.h>
#include <ntddk.h>

#define MAX_PATH 260

BOOLEAN IsInDirectory(__in const PUNICODE_STRING FileName, __in const char* Directory) {
	// Getting FileName's size.
	ULONG required_bytes_to_unicode_string_translation;
	RtlUnicodeToMultiByteSize(&required_bytes_to_unicode_string_translation, FileName->Buffer, FileName->Length);

	// Initializing a buffer for storing our string. As malloc or calloc isn't available (they're user mode mem allocation functions), using memory allocation routines.
	char* buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, required_bytes_to_unicode_string_translation, 'Tag1');
	ULONG stored_bytes;

	// Translating.
	RtlUnicodeToMultiByteN(buffer, required_bytes_to_unicode_string_translation, &stored_bytes, FileName->Buffer, FileName->Length);
	buffer[stored_bytes] = '\0';

	// Checking if the memory was successfully allocated.
	if (buffer == NULL) {
		return FALSE;
	}

	// Storing an integer to check if the "Directory" string has the "buffer" substring.
	BOOLEAN result = strstr(buffer, Directory) != 0;
	if (result) {
		DbgPrint("Buffer is %s\n", buffer);
	}

	// Freeing the buffer.
	ExFreePoolWithTag(buffer, 'Tag1');

	// Returning.
	return result;
}

// Function prototypes
FLT_PREOP_CALLBACK_STATUS FsMiniFilterPreWriteCallback(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __out PVOID* CompletionContext);

NTSTATUS FsMiniFilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS FsMiniFilterQueryTeardownCallback(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

// Callback (occurs whenever a user-mode application calls FilterConnectCommunicationPort function)
NTSTATUS FsMiniFilterConnectCommunicationPortCallback(__in PFLT_PORT ClientPort, __in PVOID ServerPortCookie, __in PVOID ConnectionContext, __in ULONG SizeOfcontext, __out PVOID* ConnectionPortCookie);

// Pointer to a caller-supplied callback routine to be called whenever the user-mode handle count for the client port reaches zero or when the minifilter driver is about to be unloaded. 
VOID FsMiniFilterDisconnectNotifyCallback(__in PVOID ConnectionCookie);

// Whenever a connected user-mode application sends a message, callback.
NTSTATUS FsMiniFilterReceiveUserModeMessageCallback(IN PVOID PortCookie, IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength);

// Global data
FLT_CONTEXT_REGISTRATION Contexts[] = {
	{ FLT_CONTEXT_END }
};

FLT_OPERATION_REGISTRATION Operations[] = {
	{ IRP_MJ_WRITE, 0, FsMiniFilterPreWriteCallback, NULL, NULL },
	{ IRP_MJ_OPERATION_END }
};

FLT_REGISTRATION g_registration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	Contexts,
	Operations,
	FsMiniFilterUnloadCallback,
	NULL,
	FsMiniFilterQueryTeardownCallback,
};

// Custom structs
typedef struct _FsMiniFilterCStruct {
	PDRIVER_OBJECT DriverObject;
	
	PFLT_FILTER GlobalFilter;

	PFLT_PORT ServerCommunicationPort;
	PFLT_PORT ClientCommunicationPort;

	PUNICODE_STRING RegistryPath;

} FsMiniFilterCStruct, * PFsMiniFilterCStruct;

typedef struct _FsMiniFilterNotificationStruct {
	ULONG PID;
	WCHAR FileName[MAX_PATH];
} FsMiniFilterNotificationStruct, * PFsMiniFilterNotificationStruct;


FsMiniFilterCStruct GlobalData;

// DriverEntry function
NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath);
NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("Initializing FsMiniFilter File System Filter Driver.\n");

	// Assigning data
	GlobalData.DriverObject = DriverObject;
	GlobalData.RegistryPath = RegistryPath;

	// In order to be registered, every minifilter must call FltRegisterFilter.
	FltRegisterFilter(DriverObject, &g_registration, &GlobalData.GlobalFilter);

	// try catch block would be fine for error handling

	// Starting a communication port in order to be able to send and receive messages from a user-mode application.
	PSECURITY_DESCRIPTOR securityDescriptor;
	OBJECT_ATTRIBUTES objAttributes;
	UNICODE_STRING portName;

	status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(GlobalData.GlobalFilter);
	}

	RtlInitUnicodeString(&portName, L"\\FsMiniFilterCommunicationPort");
	InitializeObjectAttributes(&objAttributes, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, securityDescriptor);
	
	status = FltCreateCommunicationPort(GlobalData.GlobalFilter, &GlobalData.ServerCommunicationPort, &objAttributes, NULL, FsMiniFilterConnectCommunicationPortCallback, FsMiniFilterDisconnectNotifyCallback, FsMiniFilterReceiveUserModeMessageCallback, 1000);
	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(GlobalData.GlobalFilter);
	}
	else {
		DbgPrint("Communication port was successfully established.");
	}

	// Security descriptor
	FltFreeSecurityDescriptor(securityDescriptor);

	// Start filtering
	status = FltStartFiltering(GlobalData.GlobalFilter);
	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(GlobalData.GlobalFilter);
	}

	return STATUS_SUCCESS;
}

// Callbacks
FLT_PREOP_CALLBACK_STATUS FsMiniFilterPreWriteCallback(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __out PVOID* CompletionContext) {
	UNREFERENCED_PARAMETER(CompletionContext);

	// File's name: &FltObjects->FileObject->FileName
	// Content to write: Data->Iopb->Parameters.Write.WriteBuffer
	// PID: PsGetThreadProcessId(Data->Thread)

	// Check data to write, verifies if some pattern of "it's being encrypted!" matches and then blocks or allows (maybe should we swap the old content? something like that."
	if (IsInDirectory(&FltObjects->FileObject->FileName, "\\Users")) {
		DbgPrint("%wZ is at DESKTOP\n", &FltObjects->FileObject->FileName);

		ULONG pid = (ULONG)(ULONG_PTR)PsGetThreadProcessId(Data->Thread);
		UNICODE_STRING fileName = FltObjects->FileObject->FileName;



		// Allocating memory for fileName
		WCHAR* fileNameBuffer = ExAllocatePoolWithTag(NonPagedPool, fileName.Length + sizeof(WCHAR), 'Tag2');

		if (fileNameBuffer != NULL) {
			// Parsing UNICODE_STRING into WCHAR array.
			RtlCopyMemory(fileNameBuffer, fileName.Buffer, fileName.Length);
			fileNameBuffer[fileName.Length / sizeof(WCHAR)] = L'\0';

			PFsMiniFilterNotificationStruct message = ExAllocatePoolWithTag(NonPagedPool, sizeof(FsMiniFilterNotificationStruct), 'Tag4');
			if (message != NULL) {
				// Message constrution
				message->PID = pid;
				wcsncpy(message->FileName, fileNameBuffer, MAX_PATH);

				DbgPrint("Just sent a message for our client application. %s\n");

				// Sending notification to user-mode application.
				NTSTATUS status = FltSendMessage(GlobalData.GlobalFilter, &GlobalData.ClientCommunicationPort, message, sizeof(FsMiniFilterNotificationStruct), NULL, NULL, NULL);
				if (NT_SUCCESS(status)) {
					DbgPrint("Just sent a message for our client application.\n");
				}
				else {
					DbgPrint("Failed to send the message.\n");
				}

				// Freeing resources.
				ExFreePoolWithTag(fileNameBuffer, 'Tag2');
				ExFreePoolWithTag(message, 'Tag4');
			}
		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS FsMiniFilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);

	FltCloseCommunicationPort(GlobalData.ServerCommunicationPort);
	FltUnregisterFilter(GlobalData.GlobalFilter);

	return STATUS_SUCCESS;
}

NTSTATUS FsMiniFilterQueryTeardownCallback(__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(FltObjects);

	return STATUS_SUCCESS;
}

NTSTATUS FsMiniFilterConnectCommunicationPortCallback(__in PFLT_PORT ClientPort, __in PVOID ServerPortCookie, __in PVOID ConnectionContext, __in ULONG SizeOfcontext, __out PVOID* ConnectionPortCookie) {
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfcontext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	GlobalData.ClientCommunicationPort = ClientPort;

	DbgPrint("Some user-mode application has called ConnectCommunicationPortCallback!\n");
	return STATUS_SUCCESS;
}

VOID FsMiniFilterDisconnectNotifyCallback(__in PVOID ConnectionCookie) {
	UNREFERENCED_PARAMETER(ConnectionCookie);
	
	FltCloseClientPort(GlobalData.GlobalFilter, &GlobalData.ClientCommunicationPort);
	DbgPrint("Some user-mode application has disconnected!\n");
}

NTSTATUS FsMiniFilterReceiveUserModeMessageCallback(IN PVOID PortCookie, IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength) {
	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(InputBuffer);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

	DbgPrint("RECEIVED A MESSAGE!\n");
	return STATUS_SUCCESS;
}