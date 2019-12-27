#include <iostream>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

using namespace std;

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile)) {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo)) {
        if (!processName.compare(processInfo.szExeFile)) {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

DWORD_PTR GetProcessBaseAddress(DWORD processID) {
    DWORD_PTR baseAddress = 0;
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    HMODULE *moduleArray;
    LPBYTE moduleArrayBytes;
    DWORD bytesRequired;

    if (processHandle) {
        if (EnumProcessModules(processHandle, nullptr, 0, &bytesRequired)) {
            if (bytesRequired) {
                moduleArrayBytes = reinterpret_cast<LPBYTE>(LocalAlloc(LPTR, bytesRequired));

                if (moduleArrayBytes) {
                    moduleArray = reinterpret_cast<HMODULE*>(moduleArrayBytes);

                    if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
                        baseAddress = reinterpret_cast<DWORD_PTR>(moduleArray[0]);

                    LocalFree(moduleArrayBytes);
                }
            }
        }

        CloseHandle(processHandle);
    }

    return baseAddress;
}

DWORD_PTR GetCalculedOffsets(HANDLE hProc, DWORD_PTR ptr, std::vector<DWORD_PTR> offsets) {
    DWORD_PTR addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i) {
        ReadProcessMemory(hProc, reinterpret_cast<BYTE*>(addr), &addr, sizeof(addr), nullptr);
        addr += offsets[i];
    }
    return addr;
}

int main() {
    DWORD hp = 1000;
    DWORD mp = 1000;
    DWORD pID = FindProcessId(L"BloodstainedRotN-Win64-Shipping.exe");

    if (pID == 0) {
        cout << "Bloodstained process not found!" << endl;
        cout << endl << "Press ENTER to close." << endl;
        cin.get();
    } else {
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);

        DWORD_PTR hpBaseAddress = GetProcessBaseAddress(pID) + 0x066F33A0;
        DWORD_PTR mpBaseAddress = GetProcessBaseAddress(pID) + 0x066F33A0;

        std::vector<DWORD_PTR> hpOffsets = {0x48, 0x1B0, 0x550, 0xE48, 0x70, 0xD30, 0x38};
        std::vector<DWORD_PTR> mpOffsets = {0x48, 0x1B0, 0x550, 0xE48, 0x38, 0x6D0, 0x2FC};

        DWORD_PTR hpCalculedAddress = GetCalculedOffsets(hProc, hpBaseAddress, hpOffsets);
        DWORD_PTR mpCalculedAddress = GetCalculedOffsets(hProc, mpBaseAddress, mpOffsets);

        cout << "Close this window to disable GOD Mode." << endl;
        while (true) {
            WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(hpCalculedAddress), &(hp), sizeof(hp), nullptr);
            WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(mpCalculedAddress), &(mp), sizeof(mp), nullptr);
            Sleep(100);
        }
    }

    return 0;
}
