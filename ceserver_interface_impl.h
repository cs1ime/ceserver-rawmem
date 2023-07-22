#pragma once

#include "ceserver_interface.h"
#include <dma.h>
#include <functional>
#include <list>
#include <memory>

namespace ceserver_impl {
bool initialize(std::shared_ptr<physmem_accessor> accessor);
unsigned char GetPlatformABI();
std::list<process_list_entry> TraverseProcess();
std::list<module_list_entry> TraverseModule(uint64_t pid);
std::list<region_info> TraverseMemoryRegion(uint64_t pid);
uint64_t OpenProcess(uint64_t pid);
void CloseProcess(uint64_t obj);
bool Is64BitProcess(uint64_t pid);

int ReadProcessMemory(uint64_t pobj, uint64_t lpAddress, void *buffer,
                      int size);
int WriteProcessMemory(uint64_t pobj, uint64_t lpAddress, void *buffer,
                       int size);

} // namespace ceserver_impl
