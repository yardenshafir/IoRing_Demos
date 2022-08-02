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
    ULONG Head;
    ULONG Tail;
    ULONG64 Flags;
} IORING_QUEUE_HEAD, *PIORING_QUEUE_HEAD;

typedef struct _IORING_COMP_QUEUE_HEAD
{
    ULONG Head;
    ULONG Tail;
} IORING_COMP_QUEUE_HEAD, *PIORING_COMP_QUEUE_HEAD;

typedef struct _NT_IORING_INFO
{
    ULONG Version;
    IORING_CREATE_FLAGS Flags;
    ULONG SubmissionQueueSize;
    ULONG SubQueueSizeMask;
    ULONG CompletionQueueSize;
    ULONG CompQueueSizeMask;
    PIORING_QUEUE_HEAD SubQueueBase;
    PIORING_COMP_QUEUE_HEAD CompQueueBase;
} NT_IORING_INFO, * PNT_IORING_INFO;

//
// Update: 22H2 SQE structure
//
typedef struct _NT_IORING_SQE
{
    ULONG OpCode;
    ULONG Flags;
    union
    {
        ULONG64 UserData;
        ULONG64 PaddingUserDataForWow;
    };
    enum _NT_IORING_OP_FLAGS CommonOpFlags;
    ULONG Padding;
    HANDLE FileRef;
    PVOID Buffer;
    ULONG64 Offset;
    ULONG Length;
    ULONG Key;
    ULONG64 padding;
} NT_IORING_SQE, * PNT_IORING_SQE;

typedef struct _FILE_DATA {
    HANDLE FileHandle;
    LARGE_INTEGER Size;
    PVOID Buffer;
    ULONG64 SumOfBytes;
    LARGE_INTEGER Offset;
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
    _Out_ NT_IORING_INFO* pRingInfo
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

void
CompletionRoutine (
    DWORD dwErrorCode,
    DWORD dwNumberOfBytesTransfered,
    LPOVERLAPPED lpOverlapped
);

ULONG g_filesCompleted = 0;

HRESULT
CreateListForSingleFile (
    _In_ ULONG SizeToRead,
    _In_ ULONG NumberOfEntries,
    _In_ BOOLEAN Overlapped,
    _Out_ PFILE_DATA* FileData
)
{
    PFILE_DATA fileData;
    ULONG flagsAndAttributes;
    HANDLE hFile = NULL;
    DWORD fileSize;

    *FileData = nullptr;

    if (NumberOfEntries == 0)
    {
        return ERROR_INVALID_INDEX;
    }

    fileData = (PFILE_DATA)VirtualAlloc(NULL,
                                        NumberOfEntries * sizeof(FILE_DATA),
                                        MEM_COMMIT,
                                        PAGE_READWRITE);
    if (fileData == NULL)
    {
        printf("Failed allocating memory\n");
        return ERROR_INSUFFICIENT_VIRTUAL_ADDR_RESOURCES;
    }
    flagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    if (Overlapped)
    {
        flagsAndAttributes |= FILE_FLAG_OVERLAPPED;
    }

    //
    // Pick combase.dll as a random file that'll always be there. Why? No actual reason
    //
    hFile = CreateFile(L"C:\\Windows\\System32\\combase.dll",
                       GENERIC_READ,
                       0,
                       NULL,
                       OPEN_EXISTING,
                       flagsAndAttributes,
                       NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return ERROR_INVALID_HANDLE;
    }
    GetFileSize(hFile, &fileSize);

    for (ULONG i = 0; i < NumberOfEntries; i++)
    {
        fileData[i].FileHandle = hFile;
        fileData[i].Size.QuadPart = fileSize;
        fileData[i].Offset.QuadPart = rand() % (fileSize - SizeToRead);
        fileData[i].Buffer = VirtualAlloc(NULL,
                                          SizeToRead,
                                          MEM_COMMIT,
                                          PAGE_READWRITE);
    }
    *FileData = fileData;
    return S_OK;
}

HRESULT
CreateListOfFilesFromDir (
    _In_ ULONG SizeToRead,
    _Out_ PFILE_DATA* FileData,
    _Out_ PULONG NumberOfFileHandles,
    _In_ BOOLEAN Overlapped
)
{
    HANDLE hFind = NULL;
    WIN32_FIND_DATA data;
    wchar_t* dir = (wchar_t*)L"C:\\Windows\\System32\\";
    wchar_t* path;
    HANDLE hFile = NULL;
    int i = 0;
    PFILE_DATA fileData;
    ULONG flagsAndAttributes;

    if ((NumberOfFileHandles == nullptr) || (FileData == nullptr))
    {
        printf("Invalid parameter\n");
        return ERROR_INVALID_PARAMETER;
    }

    *FileData = nullptr;
    *NumberOfFileHandles = 0;

    fileData = (PFILE_DATA)VirtualAlloc(NULL, 0x10000 * sizeof(FILE_DATA), MEM_COMMIT, PAGE_READWRITE);
    if (fileData == NULL)
    {
        printf("Failed allocating memory\n");
        return ERROR_INSUFFICIENT_VIRTUAL_ADDR_RESOURCES;
    }

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
                path = (wchar_t*)VirtualAlloc(NULL,
                                              (ULONG64)lstrlenW(dir) + (ULONG64)lstrlenW(data.cFileName),
                                              MEM_COMMIT,
                                              PAGE_READWRITE);
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
                fileData[i].Size.LowPart = data.nFileSizeLow;
                fileData[i].Offset.QuadPart = rand() % (fileData[i].Size.HighPart - SizeToRead);
                fileData[i].Buffer = VirtualAlloc(NULL,
                                                  SizeToRead,
                                                  MEM_COMMIT,
                                                  PAGE_READWRITE);
                i++;
            }
        } while (FindNextFile(hFind, &data));
        FindClose(hFind);
    }
    *FileData = fileData;
    *NumberOfFileHandles = i;
    return S_OK;
}

HRESULT
CreateListOfFiles (
    _In_ ULONG SizeToRead,
    _In_opt_ ULONG NumberOfEntries,
    _Out_ PULONG NumberOfFileHandles,
    _Out_ PFILE_DATA* FileData,
    _In_ BOOLEAN Overlapped,
    _In_ BOOLEAN OpenFilesFromDirectory
)
{
    HRESULT result;
    if ((NumberOfFileHandles == nullptr) || (FileData == nullptr))
    {
        printf("Invalid parameter\n");
        return ERROR_INVALID_PARAMETER;
    }
    *NumberOfFileHandles = 0;
    *FileData = nullptr;

    if (OpenFilesFromDirectory != FALSE)
    {
        if (NumberOfFileHandles == 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        return CreateListOfFilesFromDir(SizeToRead, FileData, NumberOfFileHandles, Overlapped);
    }
    else
    {
        result = CreateListForSingleFile(SizeToRead, NumberOfEntries, Overlapped, FileData);
        if (SUCCEEDED(result))
        {
            *NumberOfFileHandles = NumberOfEntries;
        }
        return result;
    }
}

void
LegacyNtReadFile (
    _In_ BOOLEAN ReadMultipleFiles
    )
{
    HRESULT result;
    ULONG sizeToRead = 0x100000;
    PFILE_DATA fileData;
    ULONG numberOfEntries;
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;
    ULONG64 start;
    ULONG64 end;
    ULONG64 sum;

    sum = 0;
    numberOfEntries = 5000;
    result = CreateListOfFiles(sizeToRead,
                               numberOfEntries,
                               &numberOfEntries,
                               &fileData,
                               TRUE,
                               ReadMultipleFiles);
    if (!SUCCEEDED(result))
    {
        printf("failed to create list of file handles");
        goto Exit;
    }

    start = __rdtsc();
    for (ULONG i = 0; i < numberOfEntries; i++)
    {
        status = NtReadFile(fileData[i].FileHandle,
                            NULL,
                            NULL,
                            NULL,
                            &iosb,
                            fileData[i].Buffer,
                            sizeToRead,
                            (PLARGE_INTEGER)&fileData[i].Offset,
                            NULL);
        if (!NT_SUCCESS(status))
        {
            printf("NtReadFile failed: %x\n", status);
        }
        fileData[i].SumOfBytes = 0;
        for (PBYTE b = (PBYTE)fileData[i].Buffer; (ULONG64)b < (ULONG64)(fileData[i].Buffer) + sizeToRead; b++)
        {
            fileData[i].SumOfBytes += *b;
        }
        sum += fileData[i].SumOfBytes;
    }
    end = __rdtsc();
    printf("NT read file time: %lld\n", end - start);
    printf("\tSum: %lld\n", sum);

Exit:
    if (fileData)
    {
        if ((ReadMultipleFiles == FALSE) && (fileData[0].FileHandle))
        {
            //
            // Only close the handle once
            //
            NtClose(fileData[0].FileHandle);
        }
        for (ULONG64 i = 0; i < numberOfEntries; i++)
        {
            if ((ReadMultipleFiles != FALSE) & (fileData[i].FileHandle != 0))
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

void
CompletionRoutine (
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

void
LegacyReadFile (
    _In_ BOOLEAN ReadMultipleFiles
    )
{
    ULONG sizeToRead = 0x100000;
    PFILE_DATA fileData;
    ULONG numberOfEntries;
    ULONG bytesRead;
    HRESULT result;
    OVERLAPPED overlapped = { 0 };
    ULONG64 start;
    ULONG64 end;
    ULONG64 sum;

    numberOfEntries = 5000;
    result = CreateListOfFiles(sizeToRead,
                               numberOfEntries,
                               &numberOfEntries,
                               &fileData,
                               TRUE,
                               ReadMultipleFiles);
    if (!SUCCEEDED(result))
    {
        printf("failed to create list of file handles");
        goto Exit;
    }

    overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    start = __rdtsc();
    sum = 0;
    for (ULONG i = 0; i < numberOfEntries; i++)
    {
        overlapped.OffsetHigh = fileData[i].Offset.HighPart;
        overlapped.Offset = fileData[i].Offset.LowPart;
        if (ReadFile(fileData[i].FileHandle, fileData[i].Buffer, sizeToRead, &bytesRead, &overlapped) == FALSE)
        {
            result = GetLastError();
            if (result != ERROR_IO_PENDING)
            {
                printf("ReadFile failed: %d\n", result);
                continue;
            }
            else
            {
                result = WaitForSingleObject(overlapped.hEvent, INFINITE);
                if (GetOverlappedResult(fileData[i].FileHandle,
                                        &overlapped,
                                        &bytesRead,
                                        FALSE) == FALSE)
                {
                    result = GetLastError();
                    printf("Failed reading file: %d\n", result);
                    continue;
                }
            }
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
        if ((ReadMultipleFiles == FALSE) && (fileData[0].FileHandle))
        {
            //
            // Only close the handle once
            //
            NtClose(fileData[0].FileHandle);
        }
        for (ULONG i = 0; i < numberOfEntries; i++)
        {
            if ((ReadMultipleFiles != FALSE) & (fileData[i].FileHandle != 0))
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

void
LegacyReadFileEx (
    _In_ BOOLEAN ReadMultipleFiles
    )
{
    ULONG sizeToRead = 0x100000;
    PFILE_DATA fileData;
    ULONG numberOfEntries;
    HRESULT result;
    OVERLAPPED overlapped{ 0 };
    __int64 start;
    __int64 end;
    ULONG64 sum;

    numberOfEntries = 5000;
    result = CreateListOfFiles(sizeToRead,
                               numberOfEntries,
                               &numberOfEntries,
                               &fileData,
                               TRUE,
                               ReadMultipleFiles);
    if (!SUCCEEDED(result))
    {
        printf("failed to create list of file handles");
        goto Exit;
    }

    start = __rdtsc();
    for (ULONG i = 0; i < numberOfEntries; i++)
    {
        overlapped.InternalHigh = fileData[i].Offset.HighPart;
        overlapped.Internal = fileData[i].Offset.LowPart;
        if (ReadFileEx(fileData[i].FileHandle, fileData[i].Buffer, sizeToRead, &overlapped, CompletionRoutine) == FALSE)
        {
            printf("ReadFileEx failed\n");
        }
    }
    if (ReadMultipleFiles != FALSE)
    {
        while (g_filesCompleted < numberOfEntries)
        {
            SleepEx(1, TRUE);
        }
    }
    else
    {
        while (g_filesCompleted < 1)
        {
            SleepEx(1, TRUE);
        }
    }
    sum = 0;
    for (ULONG i = 0; i < numberOfEntries; i++)
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
        if ((ReadMultipleFiles == FALSE) && (fileData[0].FileHandle))
        {
            //
            // Only close the handle once
            //
            NtClose(fileData[0].FileHandle);
        }
        for (ULONG i = 0; i < numberOfEntries; i++)
        {
            if ((ReadMultipleFiles != FALSE) & (fileData[i].FileHandle != 0))
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

void
IoRingNt (
    _In_ BOOLEAN ReadMultipleFiles
    )
{
    NTSTATUS status;
    HRESULT result;
    IO_RING_STRUCTV1 ioringStruct;
    NT_IORING_INFO ioringInfo;
    HANDLE handle = NULL;
    PNT_IORING_SQE sqe;
    LARGE_INTEGER timeout;
    HANDLE hFile = NULL;
    ULONG sizeToRead = 0x100000;
    PVOID* buffer = NULL;
    PFILE_DATA fileData;
    ULONG numberOfEntries;
    ULONG64 sum;
    IORING_CQE* cqe;
    __int64 start;
    __int64 end;

    numberOfEntries = 5000;
    result = CreateListOfFiles(sizeToRead,
                               numberOfEntries,
                               &numberOfEntries,
                               &fileData,
                               TRUE,
                               ReadMultipleFiles);
    if (!SUCCEEDED(result))
    {
        printf("failed to create list of file handles");
        goto Exit;
    }

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
    ioringInfo.SubQueueBase->Tail = numberOfEntries;
    ioringInfo.SubQueueBase->Head = 0;
    ioringInfo.SubQueueBase->Flags = 0;

    sqe = (PNT_IORING_SQE)((ULONG64)ioringInfo.SubQueueBase + sizeof(IORING_QUEUE_HEAD));

    for (ULONG i = 0; i < numberOfEntries; i++)
    {
        sqe[i].OpCode = 1;
        sqe[i].Flags = 0;
        sqe[i].FileRef = fileData[i].FileHandle;
        sqe[i].Offset = fileData[i].Offset.QuadPart;
        sqe[i].Buffer = fileData[i].Buffer;
        sqe[i].Length = sizeToRead;
        sqe[i].Key = 1234;
        sqe[i].UserData = 0;
    }

    timeout.QuadPart = 0;

    start = __rdtsc();
    status = NtSubmitIoRing(handle, IORING_CREATE_REQUIRED_FLAGS_NONE, 0, &timeout);
    if (!NT_SUCCESS(status))
    {
        printf("Failed submitting IO ring: 0x%x\n", status);
        goto Exit;
    }

    cqe = (IORING_CQE*)(ioringInfo.CompQueueBase + 1);
    sum = 0;
    while (ioringInfo.CompQueueBase->Head != ioringInfo.CompQueueBase->Tail)
    {
        if (cqe[ioringInfo.CompQueueBase->Head].ResultCode == STATUS_SUCCESS)
        {
            for (PBYTE b = (PBYTE)fileData[ioringInfo.CompQueueBase->Head].Buffer;
                (ULONG64)b < (ULONG64)(fileData[ioringInfo.CompQueueBase->Head].Buffer) + sizeToRead;
                b++)
            {
                fileData[ioringInfo.CompQueueBase->Head].SumOfBytes += *b;
            }
            sum += fileData[ioringInfo.CompQueueBase->Head].SumOfBytes;
            ioringInfo.CompQueueBase->Head++;
        }
    }

    end = __rdtsc();
    printf("time IO Ring NT: %lld\n", end - start);
    printf("\tSum: %lld\n", sum);

Exit:
    if (handle != NULL)
    {
        NtClose(handle);
    }
    if (fileData)
    {
        if ((ReadMultipleFiles == FALSE) && (fileData[0].FileHandle))
        {
            //
            // Only close the handle once
            //
            NtClose(fileData[0].FileHandle);
        }
        for (ULONG i = 0; i < numberOfEntries; i++)
        {
            if ((ReadMultipleFiles != FALSE) & (fileData[i].FileHandle != 0))
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

void
IoRingKernelBase (
    _In_ BOOLEAN ReadMultipleFiles
    )
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
    PFILE_DATA fileData;
    ULONG numberOfEntries = 0;
    IORING_CQE cqe;
    ULONG64 sum;
    __int64 start;
    __int64 end;

    fileData = nullptr;

    flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
    result = CreateIoRing(IORING_VERSION_1, flags, 0x10000, 0x20000, &handle);
    if (!SUCCEEDED(result))
    {
        printf("Failed creating IO ring handle: 0x%x\n", result);
        goto Exit;
    }

    numberOfEntries = 5000;
    result = CreateListOfFiles(sizeToRead,
                               numberOfEntries,
                               &numberOfEntries,
                               &fileData,
                               TRUE,
                               ReadMultipleFiles);
    if (!SUCCEEDED(result))
    {
        printf("failed to create list of file handles");
        goto Exit;
    }
    for (ULONG i = 0; i < numberOfEntries; i++)
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

    start = __rdtsc();
    result = SubmitIoRing(handle, 0, 0, &submittedEntries);
    if (!SUCCEEDED(result))
    {
        printf("Failed submitting IO ring: 0x%x\n", result);
        goto Exit;
    }
    sum = 0;
    for (ULONG i = 0; i < submittedEntries; i++)
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

Exit:
    if (handle != NULL)
    {
        CloseIoRing(handle);
    }
    if (fileData)
    {
        if ((ReadMultipleFiles == FALSE) && (fileData[0].FileHandle))
        {
            //
            // Only close the handle once
            //
            NtClose(fileData[0].FileHandle);
        }
        for (ULONG i = 0; i < numberOfEntries; i++)
        {
            if ((ReadMultipleFiles != FALSE) & (fileData[i].FileHandle != 0))
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

int main()
{
    BOOLEAN ReadMultipleFiles = FALSE;

    LegacyReadFile(ReadMultipleFiles);
    LegacyReadFileEx(ReadMultipleFiles);
    IoRingKernelBase(ReadMultipleFiles);
    IoRingNt(ReadMultipleFiles);
    LegacyNtReadFile(ReadMultipleFiles);

    ExitProcess(0);
}
