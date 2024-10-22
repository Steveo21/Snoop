//gcc hashapi.c -o hashapi.exe -lshlwapi -lntdll
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <string.h>

#pragma comment(lib, "Shlwapi.lib")

int cmpUnicodeStr(WCHAR substr[], WCHAR mystr[]) {
    _wcslwr_s(substr, MAX_PATH);
    _wcslwr_s(mystr, MAX_PATH);

    int result = 0;
    if (StrStrW(mystr, substr) != NULL) {
        result = 1;
    }
    return result;
}

typedef UINT(CALLBACK* fnMessageBoxA)(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
);

// Hash function for API names
DWORD hash_api(const char* api_name) {
    DWORD hash_value = 0x69;
    
    for (int i = 0; api_name[i] != '\0'; i++) {
        hash_value += (hash_value * 0xac88d37f0 + (unsigned char)api_name[i]) & 0xffffff;
    }
    
    return hash_value;
}

// custom implementation
HMODULE myGetModuleHandle(LPCWSTR lModuleName) {
    PEB* pPeb = (PEB*)__readgsqword(0x60);
    PEB_LDR_DATA* Ldr = pPeb->Ldr;
    LIST_ENTRY* ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* pStartListEntry = ModuleList->Flink;

    WCHAR mystr[MAX_PATH] = { 0 };
    WCHAR substr[MAX_PATH] = { 0 };
    for (LIST_ENTRY* pListEntry = pStartListEntry; pListEntry != ModuleList; pListEntry = pListEntry->Flink) {
        LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));
        
        memset(mystr, 0, MAX_PATH * sizeof(WCHAR));
        memset(substr, 0, MAX_PATH * sizeof(WCHAR));
        wcscpy_s(mystr, MAX_PATH, pEntry->FullDllName.Buffer);
        wcscpy_s(substr, MAX_PATH, lModuleName);
        if (cmpUnicodeStr(substr, mystr)) {
            return (HMODULE)pEntry->DllBase;
        }
    }
    
    printf("failed to get a handle to %ws\n", lModuleName);
    return NULL;
}

const char* findApiByHash(HMODULE hModule, DWORD targetHash) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    // Try hashing each exported function name until we find a match
    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        const char* functionName = (const char*)hModule + addressOfNames[i];
        DWORD currentHash = hash_api(functionName) & 0xFFFFFF;  // Get last 24 bits
        
        // For debugging
        // printf("Testing %s: 0x%08x vs target 0x%08x\n", functionName, currentHash, targetHash & 0xFFFFFF);
        
        if (currentHash == (targetHash & 0xFFFFFF)) {
            return functionName;
        }
    }

    return NULL;
}

FARPROC myGetProcAddress(HMODULE hModule, DWORD targetHash) {
    const char* functionName = findApiByHash(hModule, targetHash);
    if (functionName == NULL) {
        return NULL;
    }
    
    // Once we have the name, get the actual function address
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        if (strcmp(functionName, (const char*)hModule + addressOfNames[i]) == 0) {
            return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
        }
    }

    return NULL;
}

int main(int argc, char* argv[]) {
    DWORD targetHash = 0x005b71f18;  // Hash for MessageBoxA
    wchar_t user32_dll[] = L"user32.dll";

    HMODULE mod = myGetModuleHandle(user32_dll);
    if (NULL == mod) {
        return -2;
    }

    fnMessageBoxA myMessageBoxA = (fnMessageBoxA)myGetProcAddress(mod, targetHash);
    if (myMessageBoxA != NULL) {
        myMessageBoxA(NULL, "Meow-meow!", "=^..^=", MB_OK);
    }

    return 0;
}
