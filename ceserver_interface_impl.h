#pragma once

#include "ceserver_interface.h"
#include <memory>
#include <list>
#include <functional>
#include <dma_type.h>

namespace ceserver_impl
{
    bool initialize(
                    std::function<bool(physaddr pa, u8 *pb, u32 cb)> _read_physical_memory,
                    std::function<bool(physaddr pa, u8 *pb, u32 cb)> _write_physical_memory);
    unsigned char GetPlatformABI();
    std::list<process_list_entry> TraverseProcess();
    std::list<module_list_entry> TraverseModule(uint64_t pid);
    std::list<region_info> TraverseMemoryRegion(uint64_t pid);
    uint64_t OpenProcess(uint64_t pid);
    void CloseProcess(uint64_t obj);
    bool Is64BitProcess(uint64_t pid);

    int ReadProcessMemory(uint64_t pobj, uint64_t lpAddress, void *buffer, int size);
    int WriteProcessMemory(uint64_t pobj, uint64_t lpAddress, void *buffer, int size);

} // namespace ceserver_impl
