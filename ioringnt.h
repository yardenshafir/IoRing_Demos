#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <ioringapi.h>
#include <ntioring_x.h>
#include <winternl.h>
#include <intrin.h>

//
// Data structures
//

typedef struct _NT_IORING_INFO
{
    ULONG Version;
    IORING_CREATE_FLAGS Flags;
    ULONG SubmissionQueueSize;
    ULONG SubQueueSizeMask;
    ULONG CompletionQueueSize;
    ULONG CompQueueSizeMask;
    union {
        PIORING_SUB_QUEUE_HEAD SubQueueBase;
        ULONG64 SubQueuePaddingForX86;
    };
    union {
        PIORING_COMP_QUEUE_HEAD CompQueueBase;
        ULONG64 CompQueuePaddingForX86;
    };
} NT_IORING_INFO, *PNT_IORING_INFO;

typedef struct _IORING_BUFFER_INFO
{
    PVOID Address;
    ULONG Length;
} IORING_BUFFER_INFO, *PIORING_BUFFER_INFO;

typedef struct _IORING_OBJECT
{
  USHORT Type;
  USHORT Size;
  NT_IORING_INFO Info;
  PSECTION SectionObject;
  PVOID KernelMappedBase;
  PMDL Mdl;
  PVOID MdlMappedBase;
  ULONG_PTR ViewSize;
  ULONG SubmitInProgress;
  PVOID IoRingEntryLock;
  PVOID EntriesCompleted;
  PVOID EntriesSubmitted;
  KEVENT RingEvent;
  PVOID EntriesPending;
  ULONG BuffersRegistered;
  PIORING_BUFFER_INFO BufferArray;
  ULONG FilesRegistered;
  PHANDLE FileHandleArray;
} IORING_OBJECT, *PIORING_OBJECT;

typedef struct _IORING_CQE
{
    ULONG64 UserData;
    HRESULT ResultCode;
    ULONG64 Information;
} IORING_CQE, *PIORING_CQE;

typedef struct _NT_IORING_SQE
{
    ULONG Opcode;
    ULONG Flags;
    union {
        HANDLE FileRef;
        ULONG64 FilePaddingForx86;
    };
    LARGE_INTEGER FileOffset;
    union {
        PVOID Buffer;
        ULONG64 BufferPaddingForX86;
    };
    ULONG BufferSize;
    ULONG BufferOffset;
    ULONG Key;
    ULONG64 UserData;
    ULONG64 Padding[4];
} NT_IORING_SQE, *PNT_IORING_SQE;

typedef struct _IORING_SUB_QUEUE_HEAD
{
    ULONG QueueHead;
    ULONG QueueTail;
    ULONG64 Padding;
} IORING_SUB_QUEUE_HEAD, *PIORING_SUB_QUEUE_HEAD;

typedef struct _IORING_COMP_QUEUE_HEAD
{
    ULONG QueueHead;
    ULONG QueueTail;
} IORING_COMP_QUEUE_HEAD, * PIORING_COMP_QUEUE_HEAD;

typedef struct _NT_IORING_CAPABILITIES
{
  IORING_VERSION Version;
  IORING_OP_CODE MaxOpcode;
  ULONG FlagsSupported;
  ULONG MaxSubQueueSize;
  ULONG MaxCompQueueSize;
} NT_IORING_CAPABILITIES, *PNT_IORING_CAPABILITIES;

typedef struct _HIORING
{
    ULONG SqePending;
    ULONG SqeCount;
    HANDLE handle;
    IORING_INFO Info;
    ULONG IoRingKernelAcceptedVersion;
} HIORING, *PHIORING;

//
// Function definitions
//
EXTERN_C
NTSTATUS
NTAPI
NtSubmitIoRing (
    _In_ HANDLE Handle,
    _In_ IORING_CREATE_REQUIRED_FLAGS Flags,
    _In_ ULONG EntryCount,
    _In_ PLARGE_INTEGER Timeout
	);

EXTERN_C
NTSTATUS
NTAPI
NtCreateIoRing (
    _Out_ PHANDLE pIoRingHandle,
    _In_ ULONG CreateParametersSize,
    _In_ PIO_RING_STRUCTV1 CreateParameters,
    _In_ ULONG OutputParametersSize,
    _In_ PNT_IORING_INFO pRingInfo
	);

EXTERN_C
NTSTATUS
NTAPI
NtQueryIoRingCapabilities (
	_In_ SIZE_T CapabilitiesLength,
	_Out_ PNT_IORING_CAPABILITIES Capabilities
	);

EXTERN_C
NTSTATUS
NTAPI
NtSetInformationIoRing (
	_In_ HANDLE Handle,
	_In_ ULONG InformationClass,
	_In_ ULONG InformationLength,
	_In_ PVOID IoRingInformation
	);