#include "ceserver_interface_impl.h"
#include <algorithm>
#include <dma.h>
#include <dma_symbol_remote_pdb.h>
#include <functional>
#include <string.h>
#include <string>

#define p1x(v1) printf(("" #v1 "=%08llX\r\n"), v1)
#define p1d(v1) printf(("" #v1 "=%08lld\r\n"), v1)

extern bool dma_read_physical_memory_impl(physaddr pa, u8 *pb, u32 cb);
extern bool dma_write_physical_memory_impl(physaddr pa, u8 *pb, u32 cb);

namespace ceserver_impl {
std::shared_ptr<ntfuncs> sys = nullptr;
bool initialize(std::shared_ptr<physmem_accessor> accessor) {

  auto ms_downloader = std::make_unique<downloader>(
      "save", "https://msdl.microsoft.com/download/symbols/");
  if (!ms_downloader->valid())
    return false;
  auto factory =
      std::make_shared<dma_symbol_factory_remote_pdb>(std::move(ms_downloader));
  auto creator = std::make_shared<ntfunc_creator>(factory, accessor);
  sys = creator->try_create();
  if (sys == nullptr) {
    fprintf(stderr, "dma_try_initialize failed!\r\n");
    return false;
  }
  return true;
}
unsigned char GetPlatformABI() {
  // windows=0 linux=1
  return 1;
}
std::list<process_list_entry> TraverseProcess() {
  std::list<int> &&pids = sys->traversepid();
  std::list<process_list_entry> result;
  for (auto &&pid : pids) {
    auto name = sys->pidname(pid);
    result.push_back({pid, name});
  }
  return result;
}
std::list<module_list_entry> TraverseModule(uint64_t pid) {
  std::list<module_list_entry> result{};
  if (sys->pidexist(pid)) {
    auto p = sys->p(pid);
    if (p != nullptr) {
      auto mods64 = p->traversemod();
      auto mods32 = p->traversemod32();

      for (auto &&mod64 : mods64) {
        auto [base, size, name] = mod64;
        result.push_back(

            {name, base, size, 0, 1});
      }
      for (auto &&mod32 : mods32) {
        auto [base, size, name] = mod32;
        result.push_back({name, base, size, 0, 0});
      }
    }
  }
  return result;
}

std::map<int, std::list<region_info>> m_cached_memoryregion;
std::list<region_info> TraverseMemoryRegion(uint64_t pid) {
  std::list<region_info> result{};
  if (m_cached_memoryregion.find(pid) != m_cached_memoryregion.end()) {
    return m_cached_memoryregion[pid];
  }

  if (sys->pidexist(pid)) {
    auto p = sys->p(pid);
    if (p != nullptr) {
      auto mems = p->traversemem(0, (uptr)0x7FFFFFFF0000);
      // printf("mems:%d\r\n",mems.size());
      for (auto &[addr, size, rwx] : mems) {
        // p1x(addr);
        u64 protval = 0;
        if (rwx == 1)
          protval = PAGE_READONLY;
        else if (rwx == 3)
          protval = PAGE_READWRITE;
        else if (rwx == 5)
          protval = PAGE_EXECUTE_READ;
        else if (rwx == 7)
          protval = PAGE_EXECUTE_READWRITE;
        else
          protval = PAGE_EXECUTE_READWRITE;

        result.push_back({addr, size, protval, MEM_PRIVATE});
      }
      result.sort(
          [](auto a, auto b) -> bool { return a.baseaddress < b.baseaddress; });
      m_cached_memoryregion.insert({pid, result});
    }
  }
  return result;
}
uint64_t OpenProcess(uint64_t pid) {

  if (sys->pidexist(pid)) {
    auto p = sys->p(pid);
    auto ptr = new decltype(p)(p);
    return (uint64_t)ptr;
  }
  return pid;
}
void CloseProcess(uint64_t obj) {
  auto typeobj = (std::shared_ptr<process> *)obj;
  delete typeobj;
}
bool Is64BitProcess(uint64_t pid) { return true; }
int ReadProcessMemory(uint64_t pobj, uint64_t lpAddress, void *buffer,
                      int size) {
  auto typeobj = (std::shared_ptr<process> *)pobj;
  auto p = *typeobj;
  return p->read_virt(lpAddress, buffer, size) ? size : 0;
}
int WriteProcessMemory(uint64_t pobj, uint64_t lpAddress, void *buffer,
                       int size) {
  auto typeobj = (std::shared_ptr<process> *)pobj;
  auto p = *typeobj;
  return p->write_virt(lpAddress, buffer, size) ? size : 0;
}

} // namespace ceserver_impl
