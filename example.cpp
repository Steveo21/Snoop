#include <iostream>
#include <windows.h>

DWORD getHashFromString(char *string) 
{
        size_t stringLength = strnlen_s(string, 50);
        DWORD hash = 0x69;

        for (size_t i = 0; i < stringLength; i++)
        {
                hash += (hash * 0xac88d37f0 + string[i]) & 0xffffff;
        }
        return hash;
}

PDWORD getFunctionAddressByHash(char *library, DWORD hash)
{
        PDWORD functionAddress = (PDWORD)0;

        HMODULE libraryBase = LoadLibraryA(library);
        if (!libraryBase) {
            return NULL;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
        PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

        DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

        PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
        PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
        PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

        for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
        {
                DWORD functionNameRVA = addressOfNamesRVA[i];
                DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
                char* functionName = (char*)functionNameVA;
                DWORD_PTR functionAddressRVA = 0;

                DWORD functionNameHash = getHashFromString(functionName);

                if (functionNameHash == hash)
                {
                        functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
                        functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
                        printf("%s : 0x%x : %p\n", functionName, functionNameHash, functionAddress);
                        return functionAddress;
                }
        }
        return NULL;  // Added return for when function is not found
}

using customMessageBoxA = int(WINAPI*)(  // Changed return type to int
        HWND    hWnd,
        LPCTSTR lpText,
        LPCTSTR lpCaption,
        UINT    uType
);

int main()
{
        PDWORD functionAddress = getFunctionAddressByHash((char *)"user32.dll", 0x005b71f18);
        if (!functionAddress) {
            printf("Failed to find function\n");
            return 1;
        }

        customMessageBoxA MessageBoxA = (customMessageBoxA)functionAddress;

        customMessageBoxA(NULL, "Meow-meow!", "=^..^=", MB_OK);  // Changed to store int result

        return 0;  // Return 0 for success
}
