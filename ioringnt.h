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
    PIORING_QUEUE_HEAD SubQueueBase;
    PVOID CompQueueBase;
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
    UINT_PTR UserData;
    HRESULT ResultCode;
    ULONG_PTR Information;
} IORING_CQE, *PIORING_CQE;

typedef struct _NT_IORING_SQE
{
    ULONG Opcode;
    ULONG Flags;
    HANDLE FileRef;
    LARGE_INTEGER FileOffset;
    PVOID Buffer;
    ULONG BufferSize;
    ULONG BufferOffset;
    ULONG Key;
    PVOID UserData;
    PVOID Padding[4];
} NT_IORING_SQE, *PNT_IORING_SQE;

typedef struct _IORING_QUEUE_HEAD
{
    ULONG QueueIndex;
    ULONG QueueCount;
    ULONG64 Aligment;
} IORING_QUEUE_HEAD, *PIORING_QUEUE_HEAD;

typedef struct _IORING_COMP_QUEUE_HEAD
{
    ULONG QueueIndex;
    ULONG QueueCount;
} IORING_COMP_QUEUE_HEAD, * PIORING_COMP_QUEUE_HEAD;

enum IORING_OP_CODE
{
  IORING_OP_NOP = 0x0,
  IORING_OP_READ = 0x1,
  IORING_OP_REGISTER_FILES = 0x2,
  IORING_OP_REGISTER_BUFFERS = 0x3,
  IORING_OP_CANCEL = 0x4,
  IORING_OP_WRITE = 0x5,
};

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
NTSTATUS
NtSubmitIoRing (
    _In_ HANDLE Handle,
    _In_ IORING_CREATE_REQUIRED_FLAGS Flags,
    _In_ ULONG EntryCount,
    _In_ PLARGE_INTEGER Timeout
	);

NTSTATUS
NtCreateIoRing (
    _Out_ PHANDLE pIoRingHandle,
    _In_ ULONG CreateParametersSize,
    _In_ PIO_RING_STRUCTV1 CreateParameters,
    _In_ ULONG OutputParametersSize,
    _In_ NT_IORING_INFO* pRingInfo
	);

NTSTATUS
NtQueryIoRingCapabilities (
	_In_ SIZE_T CapabilitiesLength,
	_Out_ PNT_IORING_CAPABILITIES Capabilities
	);

NTSTATUS
NtSetInformationIoRing(
	_In_ HANDLE Handle,
	_In_ ULONG InformationClass,
	_In_ ULONG InformationLength,
	_In_ PVOID IoRingInformation
	);