#include <iostream>
#include <windows.h>

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

int main()
{
    // List of API names to test
    const char* apiNames[] = { "VirtualAlloc", "RtlCopyMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "SemperFidelis" };
    
    // Iterate through the API names and calculate their hashes
    for (const char* apiName : apiNames)
    {
        DWORD hash = getHashFromString(const_cast<char*>(apiName));
        std::cout << "API Name: " << apiName << "\tHash: 0x" << std::hex << hash << std::endl;
    }

    return 0;
}
