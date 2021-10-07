#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <cstdio>
#include <ioringapi.h>
#include <winternl.h>
#include <time.h>
#include <intrin.h>

typedef struct _IO_RING_STRUCTV1
{
    ULONG IoRingVersion;
    ULONG SubmissionQueueSize;
    ULONG CompletionQueueSize;
    ULONG RequiredFlags;
    ULONG AdvisoryFlags;
} IO_RING_STRUCTV1, * PIO_RING_STRUCTV1;

typedef struct _IORING_QUEUE_HEAD
{
    ULONG QueueIndex;
    ULONG QueueCount;
    ULONG64 Aligment;
} IORING_QUEUE_HEAD, * PIORING_QUEUE_HEAD;

typedef struct _IORING_COMP_QUEUE_HEAD
{
    ULONG QueueIndex;
    ULONG QueueCount;
} IORING_COMP_QUEUE_HEAD, * PIORING_COMP_QUEUE_HEAD;

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
} NT_IORING_INFO, * PNT_IORING_INFO;

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
    PVOID stuff1;
    PVOID stuff2;
    PVOID stuff3;
    PVOID stuff4;
} NT_IORING_SQE, * PNT_IORING_SQE;

typedef struct _FILE_DATA {
    HANDLE FileHandle;
    LARGE_INTEGER Size;
    PVOID Buffer;
    ULONG64 SumOfBytes;
} FILE_DATA, *PFILE_DATA;

EXTERN_C_START
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
NtClose (
    _In_ HANDLE Handle
);

NTSTATUS
NtReadFile (
    _In_     HANDLE           FileHandle,
    _In_opt_ HANDLE           Event,
    _In_opt_ PIO_APC_ROUTINE  ApcRoutine,
    _In_opt_ PVOID            ApcContext,
    _Out_    PIO_STATUS_BLOCK IoStatusBlock,
    _Out_    PVOID            Buffer,
    _In_     ULONG            Length,
    _In_opt_ PLARGE_INTEGER   ByteOffset,
    _In_opt_ PULONG           Key
);

EXTERN_C_END

void CompletionRoutine (
    DWORD dwErrorCode,
    DWORD dwNumberOfBytesTransfered,
    LPOVERLAPPED lpOverlapped
);

ULONG g_filesCompleted = 0;

void CreateListOfFiles (
    ULONG SizeToRead,
    PFILE_DATA* FileData,
    PULONG Length,
    BOOLEAN Overlapped
)
{
    HANDLE hFind = NULL;
    WIN32_FIND_DATA data;
    wchar_t* dir = (wchar_t*)L"C:\\Windows\\System32\\";
    wchar_t* path;
    HANDLE hFile = NULL;
    int i = 0;
    PFILE_DATA fileData = *FileData;
    ULONG flagsAndAttributes;

    flagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    if (Overlapped)
    {
        flagsAndAttributes |= FILE_FLAG_OVERLAPPED;
    }

    hFind = FindFirstFile(L"C:\\Windows\\System32\\*", &data);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (hFind != INVALID_HANDLE_VALUE)
            {
                path = (wchar_t*)VirtualAlloc(NULL, lstrlenW(dir) + lstrlenW(data.cFileName), MEM_COMMIT, PAGE_READWRITE);
                if (path == NULL)
                {
                    continue;
                }
                lstrcpyW(path, dir);
                lstrcatW(path, data.cFileName);
                hFile = CreateFile(path,
                    GENERIC_READ,
                    0,
                    NULL,
                    OPEN_EXISTING,
                    flagsAndAttributes,
                    NULL);
                VirtualFree(path, NULL, MEM_RELEASE);
                if (hFile == INVALID_HANDLE_VALUE)
                {
                    continue;
                }

                fileData[i].FileHandle = hFile;
                fileData[i].Size.HighPart = data.nFileSizeHigh;
                fileData[i].Size.HighPart = data.nFileSizeLow;
                fileData[i].Buffer = VirtualAlloc(NULL,
                    SizeToRead,
                    MEM_COMMIT,
                    PAGE_READWRITE);
                

                i++;
            }
        } while (FindNextFile(hFind, &data));
        FindClose(hFind);
    }
    *Length = i;
}

void LegacyNtReadFile ()
{
    ULONG sizeToRead = 0x100000;
    PFILE_DATA fileData;
    ULONG numberOfEntries;
    ULONG bytesRead;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    clock_t start;
    clock_t end;

    fileData = (PFILE_DATA)VirtualAlloc(NULL, 0x10000 * sizeof(FILE_DATA), MEM_COMMIT, PAGE_READWRITE);
    if (fileData == NULL)
    {
        printf("Failed allocating memory\n");
        goto Exit;
    }
    CreateListOfFiles(sizeToRead, &fileData, &numberOfEntries, FALSE);

    start = clock();
    for (int i = 0; i < numberOfEntries; i++)
    {
        status = NtReadFile(fileData[i].FileHandle, NULL, NULL, NULL, &iosb, fileData[i].Buffer, sizeToRead, 0, NULL);
    }
    end = clock();
    printf("NT read file time: %d\n", end - start);

Exit:
    if (fileData)
    {
        for (int i = 0; i < numberOfEntries; i++)
        {
            if (fileData[i].FileHandle)
            {
                NtClose(fileData[i].FileHandle);
            }
            if (fileData[i].Buffer != NULL)
            {
                VirtualFree(fileData[i].Buffer, NULL, MEM_RELEASE);
            }
        }
        VirtualFree(fileData, NULL, MEM_RELEASE);
    }
}

void CompletionRoutine (
    DWORD dwErrorCode,
    DWORD dwNumberOfBytesTransfered,
    LPOVERLAPPED lpOverlapped
)
{
    UNREFERENCED_PARAMETER(dwErrorCode);
    UNREFERENCED_PARAMETER(dwNumberOfBytesTransfered);
    UNREFERENCED_PARAMETER(lpOverlapped);
    g_filesCompleted++;
}

void LegacyReadFile()
{
    ULONG sizeToRead = 0x100000;
    PFILE_DATA fileData;
    ULONG numberOfEntries;
    ULONG bytesRead;
    HRESULT result;
    OVERLAPPED* pOverlapped = new OVERLAPPED;
    __int64 start;
    __int64 end;
    ULONG64 sum;

    fileData = (PFILE_DATA)VirtualAlloc(NULL, 0x10000 * sizeof(FILE_DATA), MEM_COMMIT, PAGE_READWRITE);
    if (fileData == NULL)
    {
        printf("Failed allocating memory\n");
        goto Exit;
    }
    CreateListOfFiles(sizeToRead, &fileData, &numberOfEntries, FALSE);

    start = __rdtsc();
    sum = 0;
    for (int i = 0; i < numberOfEntries; i++)
    {
        result = ReadFile(fileData[i].FileHandle, fileData[i].Buffer, sizeToRead, &bytesRead, NULL);
        if (FAILED(result))
        {
            printf("ReadFile failed\n");
        }
        fileData[i].SumOfBytes = 0;
        for (PBYTE b = (PBYTE)fileData[i].Buffer; (ULONG64)b < (ULONG64)(fileData[i].Buffer) + sizeToRead; b++)
        {
            fileData[i].SumOfBytes += *b;
        }
        sum += fileData[i].SumOfBytes;
    }
    end = __rdtsc();
    printf("ReadFile time: %lld\n", end - start);
    printf("\tSum: %lld\n", sum);

Exit:
    if (fileData)
    {
        for (int i = 0; i < numberOfEntries; i++)
        {
            if (fileData[i].FileHandle)
            {
                NtClose(fileData[i].FileHandle);
            }
            if (fileData[i].Buffer != NULL)
            {
                VirtualFree(fileData[i].Buffer, NULL, MEM_RELEASE);
            }
        }
        VirtualFree(fileData, NULL, MEM_RELEASE);
    }
}

void LegacyReadFileEx()
{
    ULONG sizeToRead = 0x100000;
    PFILE_DATA fileData;
    ULONG numberOfEntries;
    ULONG bytesRead;
    BOOL result;
    OVERLAPPED overlapped;
    __int64 start;
    __int64 end;
    ULONG64 sum;

    fileData = (PFILE_DATA)VirtualAlloc(NULL, 0x10000 * sizeof(FILE_DATA), MEM_COMMIT, PAGE_READWRITE);
    if (fileData == NULL)
    {
        printf("Failed allocating memory\n");
        goto Exit;
    }
    CreateListOfFiles(sizeToRead, &fileData, &numberOfEntries, TRUE);

    start = __rdtsc();
    for (int i = 0; i < numberOfEntries; i++)
    {
        overlapped = { 0 };
        result = ReadFileEx(fileData[i].FileHandle, fileData[i].Buffer, sizeToRead, &overlapped, CompletionRoutine);
        if (result == FALSE)
        {
            printf("ReadFileEx failed\n");
        }
    }
    while (g_filesCompleted < numberOfEntries)
    {
        SleepEx(1, TRUE);
    }
    sum = 0;
    for (int i = 0; i < numberOfEntries; i++)
    {
        fileData[i].SumOfBytes = 0;
        for (PBYTE b = (PBYTE)fileData[i].Buffer; (ULONG64)b < (ULONG64)(fileData[i].Buffer) + sizeToRead; b++)
        {
            fileData[i].SumOfBytes += *b;
        }
        sum += fileData[i].SumOfBytes;
    }

    end = __rdtsc();
    printf("ReadFileEx time: %lld\n", end - start);
    printf("\tSum: %lld\n", sum);

Exit:
    if (fileData)
    {
        for (int i = 0; i < numberOfEntries; i++)
        {
            if (fileData[i].FileHandle)
            {
                NtClose(fileData[i].FileHandle);
            }
            if (fileData[i].Buffer != NULL)
            {
                VirtualFree(fileData[i].Buffer, NULL, MEM_RELEASE);
            }
        }
        VirtualFree(fileData, NULL, MEM_RELEASE);
    }
}


void IoRingNt()
{
    NTSTATUS status;
    IO_RING_STRUCTV1 ioringStruct;
    NT_IORING_INFO ioringInfo;
    HANDLE handle = NULL;
    PNT_IORING_SQE sqe;
    LARGE_INTEGER timeout;
    HANDLE hFile = NULL;
    ULONG sizeToRead = 0x100000;
    PVOID* buffer = NULL;
    ULONG64 endOfBuffer;
    PFILE_DATA fileData;
    ULONG numberOfEntries;
    ULONG64 sum;
    IORING_CQE* cqe;
    __int64 start;
    __int64 end;

    fileData = (PFILE_DATA)VirtualAlloc(NULL, 0x10000 * sizeof(FILE_DATA), MEM_COMMIT, PAGE_READWRITE);
    if (fileData == NULL)
    {
        printf("Failed allocating memory\n");
        goto Exit;
    }
    CreateListOfFiles(sizeToRead, &fileData, &numberOfEntries, TRUE);

    ioringStruct.IoRingVersion = 1;
    ioringStruct.SubmissionQueueSize = 0x10000;
    ioringStruct.CompletionQueueSize = 0x20000;
    ioringStruct.AdvisoryFlags = IORING_CREATE_ADVISORY_FLAGS_NONE;
    ioringStruct.RequiredFlags = IORING_CREATE_REQUIRED_FLAGS_NONE;

    status = NtCreateIoRing(&handle,
                            sizeof(ioringStruct),
                            &ioringStruct,
                            sizeof(ioringInfo),
                            &ioringInfo);
    if (!NT_SUCCESS(status))
    {
        printf("Failed creating IO ring handle: 0x%x\n", status);
        goto Exit;
    }

    ioringInfo.SubQueueBase->QueueCount = numberOfEntries;
    ioringInfo.SubQueueBase->QueueIndex = 0;
    ioringInfo.SubQueueBase->Aligment = 0;

    sqe = (PNT_IORING_SQE)((ULONG64)ioringInfo.SubQueueBase + sizeof(IORING_QUEUE_HEAD));

    for (int i = 0; i < numberOfEntries; i++)
    {
        sqe[i].Opcode = 1;
        sqe[i].Flags = 0;
        sqe[i].FileRef = fileData[i].FileHandle;
        sqe[i].FileOffset.QuadPart = 0;
        sqe[i].Buffer = fileData[i].Buffer;
        sqe[i].BufferOffset = 0;
        sqe[i].BufferSize = sizeToRead;
        sqe[i].Key = 1234;
        sqe[i].UserData = nullptr;
    }

    timeout.QuadPart = 0;

    start = __rdtsc();
    status = NtSubmitIoRing(handle, IORING_CREATE_REQUIRED_FLAGS_NONE, numberOfEntries, &timeout);
    if (!NT_SUCCESS(status))
    {
        printf("Failed submitting IO ring: 0x%x\n", status);
        goto Exit;
    }

    cqe = (IORING_CQE*)((ULONG64)ioringInfo.CompQueueBase + sizeof(IORING_COMP_QUEUE_HEAD));
    sum = 0;
    for (int i = 0; i < numberOfEntries; i++)
    {
        if (cqe[i].ResultCode == STATUS_SUCCESS)
        {
            for (PBYTE b = (PBYTE)fileData[i].Buffer; (ULONG64)b < (ULONG64)(fileData[i].Buffer) + sizeToRead; b++)
            {
                fileData[i].SumOfBytes += *b;
            }
            sum += fileData[i].SumOfBytes;
        }
    }

    end = __rdtsc();
    printf("time IO Ring NT: %lld\n", end - start);
    printf("\tSum: %lld\n", sum);

    /*printf("Data from file:\n");
    endOfBuffer = (ULONG64)buffer + sizeToRead;
    for (; (ULONG64)buffer < endOfBuffer; buffer++)
    {
        printf("%p ", *buffer);
    }
    printf("\n");*/

Exit:
    if (handle != NULL)
    {
        NtClose(handle);
    }
    if (fileData)
    {
        for (int i = 0; i < numberOfEntries; i++)
        {
            if (fileData[i].FileHandle)
            {
                NtClose(fileData[i].FileHandle);
            }
            if (fileData[i].Buffer != NULL)
            {
                VirtualFree(fileData[i].Buffer, NULL, MEM_RELEASE);
            }
        }
        VirtualFree(fileData, NULL, MEM_RELEASE);
    }
}

void IoRingKernelBase()
{
    HRESULT result;
    HIORING handle = NULL;
    IORING_CREATE_FLAGS flags;
    IORING_HANDLE_REF requestDataFile = IoRingHandleRefFromHandle(0);
    IORING_BUFFER_REF requestDataBuffer = IoRingBufferRefFromPointer(0);
    UINT32 submittedEntries;
    HANDLE hFile = NULL;
    ULONG sizeToRead = 0x100000;
    PVOID buffer = NULL;
    ULONG64 endOfBuffer;
    PFILE_DATA fileData;
    ULONG numberOfEntries = 0;
    IORING_CQE cqe;
    ULONG64 sum;
    __int64 start;
    __int64 end;
    
    fileData = (PFILE_DATA)VirtualAlloc(NULL, 0x10000 * sizeof(FILE_DATA), MEM_COMMIT, PAGE_READWRITE);
    if (fileData == NULL)
    {
        printf("Failed allocating memory\n");
        goto Exit;
    }

    flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
    result = CreateIoRing(IORING_VERSION_1, flags, 0x10000, 0x20000, &handle);
    if (!SUCCEEDED(result))
    {
        printf("Failed creating IO ring handle: 0x%x\n", result);
        goto Exit;
    }

    CreateListOfFiles(sizeToRead, &fileData, &numberOfEntries, TRUE);
    for (int i = 0; i < numberOfEntries; i++)
    {
        requestDataFile = IoRingHandleRefFromHandle(fileData[i].FileHandle);
        requestDataBuffer = IoRingBufferRefFromPointer(fileData[i].Buffer);

        result = BuildIoRingReadFile(handle,
                                     requestDataFile,
                                     requestDataBuffer,
                                     sizeToRead,
                                     0,
                                     NULL,
                                     IOSQE_FLAGS_NONE);

        if (!SUCCEEDED(result))
        {
            printf("Failed building IO ring read file structure: 0x%x\n", result);
            continue;
        }
    }

    //result = BuildIoRingRegisterFileHandles(handle, i, fileHandles, NULL);

    start = __rdtsc();
    result = SubmitIoRing(handle, 0, 0, &submittedEntries);
    if (!SUCCEEDED(result))
    {
        printf("Failed submitting IO ring: 0x%x\n", result);
        goto Exit;
    }
    sum = 0;
    for (int i = 0; i < submittedEntries; i++)
    {
        result = PopIoRingCompletion(handle, &cqe);
        if (cqe.ResultCode == STATUS_SUCCESS)
        {
            for (PBYTE b = (PBYTE)fileData[i].Buffer; (ULONG64)b < (ULONG64)(fileData[i].Buffer) + sizeToRead; b++)
            {
                fileData[i].SumOfBytes += *b;
            }
            sum += fileData[i].SumOfBytes;
        }
    }

    end = __rdtsc();
    printf("time IO Ring KernelBase: %lld\n", end - start);
    printf("\tSum: %lld\n", sum);

    /*printf("Data from file:\n");
    endOfBuffer = (ULONG64)buffer + sizeToRead;
    for (; (ULONG64)buffer < endOfBuffer; buffer++)
    {
        printf("%p ", *buffer);
    }
    printf("\n");*/

Exit:
    if (handle != NULL)
    {
        CloseIoRing(handle);
    }
    if (fileData)
    {
        for (int i = 0; i < numberOfEntries; i++)
        {
            if (fileData[i].FileHandle)
            {
                NtClose(fileData[i].FileHandle);
            }
            if (fileData[i].Buffer)
            {
                VirtualFree(fileData[i].Buffer, NULL, MEM_RELEASE);
            }
        }
        VirtualFree(fileData, NULL, MEM_RELEASE);
    }
}

int main()
{
    LegacyReadFile();
    LegacyReadFileEx();
    IoRingKernelBase();
    IoRingNt();
    
    //LegacyNtReadFile();

    ExitProcess(0);
}



/*
NT-KB-LG
KB-LG-NT
LG-NT-KB
NT-LG-KB
KB-NT-LG
LG-KB-NT
*/