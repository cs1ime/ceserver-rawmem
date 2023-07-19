#pragma once

#include "ceserver.h"
#include <string>
#include <list>
#include <memory>

struct process_list_entry
{
    int pid;
    std::string name;
};
struct module_list_entry
{
    std::string moduleName;
    uint64_t baseAddress;
    uint64_t moduleSize;
    int part;
    int is64bit;
};
struct process_list
{
    std::list<process_list_entry> list;
    std::list<process_list_entry>::iterator itor;
};
struct module_list
{
    std::list<module_list_entry> list;
    std::list<module_list_entry>::iterator itor;
};
struct region_info
{
    uint64_t baseaddress;
    uint64_t size;
    uint32_t protection;
    uint32_t type;
};

namespace ceserver
{

    HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
    BOOL Process32First(HANDLE hSnapshot, process_list_entry *processentry);
    BOOL Process32Next(HANDLE hSnapshot, process_list_entry *processentry);
    BOOL Module32First(HANDLE hSnapshot, module_list_entry *moduleentry);
    BOOL Module32Next(HANDLE hSnapshot, module_list_entry *moduleentry);

    void CloseHandle(HANDLE handle);
    HANDLE OpenProcess(DWORD pid);
    int GetArchitecture(HANDLE hProcess);
    unsigned char GetPlatformABI();

    int ReadProcessMemory(HANDLE hProcess, uint64_t lpAddress, void *buffer, int size);
    int WriteProcessMemory(HANDLE hProcess, uint64_t lpAddress, void *buffer, int size);
    int VirtualQueryEx(HANDLE hProcess, uint64_t lpAddress, region_info *rinfo, char *mapsline);
    std::shared_ptr<std::list<region_info>>
    VirtualQueryExFull(HANDLE hProcess, uint32_t flags);

}
