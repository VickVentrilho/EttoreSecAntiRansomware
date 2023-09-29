#include <fltKernel.h>

// Custom struct
typedef struct _FsMiniFilterCStruct {
	PDRIVER_OBJECT DriverObject;
	PFLT_FILTER GlobalFilter;
	PUNICODE_STRING RegistryPath;

} FsMiniFilterCStruct, * PFsMiniFilterCStruct;

extern FsMiniFilterCStruct GlobalData;