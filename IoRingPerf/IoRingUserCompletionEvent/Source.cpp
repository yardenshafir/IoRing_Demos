#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <cstdio>
#include <ioringapi.h>
#include <winternl.h>
#include <time.h>
#include <intrin.h>

typedef struct _FILE_DATA {
    HANDLE FileHandle;
    LARGE_INTEGER Size;
    PVOID Buffer;
    ULONG64 SumOfBytes;
} FILE_DATA, * PFILE_DATA;

HANDLE g_event;
PFILE_DATA g_fileData;

/*
    lpThreadParameter here is the handle to the ioring object
*/
DWORD
WaitOnEvent (
    LPVOID lpThreadParameter
)
{
    HRESULT result;
    ULONG64 sum;
    IORING_CQE cqe;
    int i = 0;
    sum = 0;

    WaitForSingleObject(g_event, INFINITE);
    while (TRUE)
    {
        result = PopIoRingCompletion((HIORING)lpThreadParameter, &cqe);
        if (result == S_OK)
        {
            if (cqe.ResultCode == STATUS_SUCCESS)
            {
                for (PBYTE b = (PBYTE)(g_fileData[i].Buffer); (ULONG64)b < (ULONG64)(g_fileData[i].Buffer) + cqe.Information; b++)
                {
                    sum += *b;
                }
            }
        }
        else
        {
            WaitForSingleObject(g_event, INFINITE);
            ResetEvent(g_event);
        }
        printf("popped result at index %d, sum: 0x%llx\n", i, sum);
        i += 1;
    }
    return i;
}

void
CreateListOfFiles (
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

void
IoRingUserEventDemo ()
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

    HANDLE event;
    ULONG threadId;
    HANDLE thread;

    fileData = (PFILE_DATA)VirtualAlloc(NULL, 0x10000 * sizeof(FILE_DATA), MEM_COMMIT, PAGE_READWRITE);
    if (fileData == NULL)
    {
        printf("Failed allocating memory\n");
        goto Exit;
    }
    g_fileData = fileData;

    flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
    result = CreateIoRing(IORING_VERSION_3, flags, 0x10000, 0x20000, &handle);
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

    g_event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (g_event == 0)
    {
        printf("Failed creating event! Error 0x%x\n", GetLastError());
        goto Exit;
    }
    result = SetIoRingCompletionEvent(handle, g_event);
    thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitOnEvent, handle, 0, &threadId);

    result = SubmitIoRing(handle, 0, 0, &submittedEntries);
    if (!SUCCEEDED(result))
    {
        printf("Failed submitting IO ring: 0x%x\n", result);
        goto Exit;
    }
    getchar();

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
                CloseHandle(fileData[i].FileHandle);
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
    IoRingUserEventDemo();

    ExitProcess(0);
}