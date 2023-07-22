#include "ceserver_interface.h"
#include "ceserver.h"
#include "ceserver_interface_impl.h"
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <stack>
#include <sys/time.h>
#include <unordered_map>

// abstract layer for handles management

namespace ceserver {

uint64_t GetTickCount() {
  long long tmp;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  tmp = tv.tv_sec;
  tmp = tmp * 1000;
  tmp = tmp + (tv.tv_usec / 1000);
  return tmp;
}

class Process {
private:
  uint64_t pid = 0;
  uint64_t ProcessObject = 0;
  bool is64bit = false;

public:
  explicit Process(uint64_t _pid, uint64_t obj) {
    pid = _pid;
    ProcessObject = obj;
    is64bit = ceserver_impl::Is64BitProcess(obj);
  }
  uint64_t GetPid() const { return pid; }
  uint64_t GetProcessObject() const { return ProcessObject; }
  bool Is64Bit() { return is64bit; }
};

class HandleListEntry {
private:
  int count;

public:
  void *pointer;
  handleType type;

  explicit HandleListEntry(void *p, handleType t) {
    this->pointer = p;
    this->type = t;
    this->count = 1;
  };
  void AddRef() { this->count++; }
  void DecRef() { this->count--; }
  int refCount() { return this->count; }
};

using typeTHSProcessHandle = process_list *;
using typeTHSModuleHandle = module_list *;
using typeProcessHandle = Process *;

std::map<HANDLE, HandleListEntry *> m_handletable;
std::shared_mutex m_handletable_lock;
HANDLE m_latesthandle = 0;
std::stack<HANDLE> m_handletable_freed;

handleType GetHandleType(HANDLE handle) {
  m_handletable_lock.lock_shared();
  auto it = m_handletable.find(handle);
  if (it != m_handletable.end()) {
    void *ptr = m_handletable[handle];
    if (ptr) {
      handleType ty = m_handletable[handle]->type;
      m_handletable_lock.unlock_shared();
      return ty;
    }
  }
  m_handletable_lock.unlock_shared();
  return htEmpty;
}
void *GetPointerFromHandle(HANDLE handle) {
  m_handletable_lock.lock_shared();
  auto it = m_handletable.find(handle);
  if (it != m_handletable.end()) {
    void *ptr = m_handletable[handle];
    if (ptr) {
      auto result = m_handletable[handle]->pointer;
      m_handletable_lock.unlock_shared();
      return result;
    }
  }
  m_handletable_lock.unlock_shared();
  return nullptr;
}
HANDLE CreateHandle(void *pointer, handleType ht) {
  m_handletable_lock.lock();
  HANDLE hNewHandle;
  if (!m_handletable_freed.empty()) {
    hNewHandle = m_handletable_freed.top();
    m_handletable_freed.pop();
    m_handletable.insert({hNewHandle, new HandleListEntry(pointer, ht)});
    // m_handletable[hNewHandle]=pointer;
    m_handletable_lock.unlock();
    return hNewHandle;
  }
  hNewHandle = ++m_latesthandle;
  m_handletable.insert({hNewHandle, new HandleListEntry(pointer, ht)});
  m_handletable_lock.unlock();
  ;
  return hNewHandle;
}

void DestoryHandle(HANDLE handle) {

  auto it = m_handletable.find(handle);
  if (it != m_handletable.end()) {
    void *ptr = m_handletable[handle];
    handleType ty = m_handletable[handle]->type;
    if (ptr) {
      auto he = (HandleListEntry *)ptr;
      if (ty == htTHSProcess) {
        auto obj = (typeTHSProcessHandle)he->pointer;
        delete obj;
      } else if (ty == htTHSModule) {
        auto obj = (typeTHSModuleHandle)he->pointer;
        delete obj;
      } else if (ty == htProcesHandle) {
        auto obj = (typeProcessHandle)he->pointer;
        ceserver_impl::CloseProcess(obj->GetProcessObject());
        delete obj;
      }

      delete he;
    }
    m_handletable_freed.push(it->first);
    m_handletable.erase(it);
  }
}
void CloseHandle(HANDLE handle) {
  m_handletable_lock.lock();
  auto it = m_handletable.find(handle);
  if (it != m_handletable.end()) {
    auto he = m_handletable[handle];
    he->DecRef();
    if (he->refCount() == 0) {
      DestoryHandle(handle);
    }
  }
  m_handletable_lock.unlock();
}
HandleListEntry *QueryHandle(HANDLE handle) {
  m_handletable_lock.lock_shared();
  auto it = m_handletable.find(handle);

  HandleListEntry *result = it != m_handletable.end() ? it->second : nullptr;

  m_handletable_lock.unlock_shared();
  return result;
}

HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
  if (dwFlags & TH32CS_SNAPPROCESS) {
    auto &&pl = ceserver_impl::TraverseProcess();
    process_list *plist = new process_list({pl, pl.begin()});
    if (plist != nullptr) {
      return CreateHandle(plist, htTHSProcess);
    } else {
      return 0;
    }
  } else if (dwFlags & TH32CS_SNAPMODULE) {
    auto &&ml = ceserver_impl::TraverseModule(th32ProcessID);
    module_list *mlist = new module_list({ml, ml.begin()});
    if (mlist != nullptr) {
      return CreateHandle(mlist, htTHSModule);
    } else {
      return 0;
    }
  }
  return 0;
}

BOOL Process32Next(HANDLE hSnapshot, process_list_entry *processentry) {
  HandleListEntry *he = QueryHandle(hSnapshot);
  if (he && he->type == htTHSProcess) {
    process_list *plist = (decltype(plist))he->pointer;
    if (plist && !plist->list.empty() && plist->itor != plist->list.end()) {
      *processentry = *plist->itor;
      plist->itor++;
      return TRUE;
    }
  }
  return FALSE;
}
BOOL Process32First(HANDLE hSnapshot, process_list_entry *processentry) {
  HandleListEntry *he = QueryHandle(hSnapshot);
  if (he && he->type == htTHSProcess) {
    process_list *plist = (decltype(plist))he->pointer;
    if (plist && !plist->list.empty()) {
      plist->itor = plist->list.begin();
      //*processentry=*plist->itor;
      return Process32Next(hSnapshot, processentry);
    }
  }
  return FALSE;
}

BOOL Module32Next(HANDLE hSnapshot, module_list_entry *moduleentry) {
  HandleListEntry *he = QueryHandle(hSnapshot);
  if (he && he->type == htTHSModule) {
    module_list *plist = (decltype(plist))he->pointer;
    if (plist && !plist->list.empty() && plist->itor != plist->list.end()) {
      *moduleentry = *plist->itor;
      plist->itor++;
      return TRUE;
    }
  }
  return FALSE;
}
BOOL Module32First(HANDLE hSnapshot, module_list_entry *moduleentry) {
  HandleListEntry *he = QueryHandle(hSnapshot);
  if (he && he->type == htTHSModule) {
    module_list *plist = (decltype(plist))he->pointer;
    if (plist && !plist->list.empty()) {
      plist->itor = plist->list.begin();
      //*processentry=*plist->itor;
      return Module32Next(hSnapshot, moduleentry);
    }
  }
  return FALSE;
}

HANDLE OpenProcess(DWORD pid) {
  uint64_t obj = ceserver_impl::OpenProcess(pid);
  if (obj == 0)
    return 0;

  auto p = new Process(pid, obj);

  return CreateHandle(p, htProcesHandle);
}
int GetArchitecture(HANDLE hProcess) {
  if (GetHandleType(hProcess) == htProcesHandle) {
    Process *p = (Process *)GetPointerFromHandle(hProcess);
    if (p->Is64Bit())
      return 1;
    else
      return 0;
  }
  return -1;
}
unsigned char GetPlatformABI() {
  // windows=0 linux=1
  return ceserver_impl::GetPlatformABI();
}

int ReadProcessMemory(HANDLE hProcess, uint64_t lpAddress, void *buffer,
                      int size) {
  if (GetHandleType(hProcess) == htProcesHandle) {
    Process *p = (Process *)GetPointerFromHandle(hProcess);
    if (p) {
      return ceserver_impl::ReadProcessMemory(p->GetProcessObject(), lpAddress,
                                              buffer, size);
    }
  }
  return 0;
}
int WriteProcessMemory(HANDLE hProcess, uint64_t lpAddress, void *buffer,
                       int size) {
  if (GetHandleType(hProcess) == htProcesHandle) {
    Process *p = (Process *)GetPointerFromHandle(hProcess);
    if (p) {
      return ceserver_impl::WriteProcessMemory(p->GetProcessObject(), lpAddress,
                                               buffer, size);
    }
  }
  return 0;
}

std::list<region_info> TraverseMemoryRegion(uint64_t pid) {
  auto result = ceserver_impl::TraverseMemoryRegion(pid);
  result.sort(
      [](auto a, auto b) -> bool { return a.baseaddress < b.baseaddress; });
  std::list<region_info> noaccess{};

  region_info prev_region = {0, 0, PAGE_NOACCESS, MEM_PRIVATE};
  for (auto &&m : result) {
    uint64_t prev_endaddr = prev_region.baseaddress + prev_region.size;
    if (m.baseaddress - prev_endaddr > 0) {
      noaccess.push_back({.baseaddress = prev_endaddr,
                          .size = m.baseaddress - prev_endaddr,
                          .protection = PAGE_NOACCESS,
                          .type = MEM_PRIVATE});
    }
    prev_region = m;
  }
  result.splice(result.begin(), noaccess);
  result.sort(
      [](auto a, auto b) -> bool { return a.baseaddress < b.baseaddress; });
  return std::move(result);
}
std::map<int, std::pair<uint64_t, std::list<region_info>>>
    m_VirtualQueryEx_Cache;
std::mutex m_VirtualQueryEx_Cache_lock;
int VirtualQueryExImpl(Process *p, uint64_t lpAddress, region_info *rinfo,
                       char *mapsline) {
  auto pid = p->GetPid();

  // processing cache
  if (m_VirtualQueryEx_Cache.find(pid) != m_VirtualQueryEx_Cache.end()) {
    auto &&[time, region] = m_VirtualQueryEx_Cache[pid];
    if (GetTickCount() - time > 1000) {
      auto &&new_region = TraverseMemoryRegion(pid);
      m_VirtualQueryEx_Cache.erase(pid);
      m_VirtualQueryEx_Cache.insert({pid, {GetTickCount(), new_region}});
    }
  } else {
    auto &&new_region = TraverseMemoryRegion(pid);
    m_VirtualQueryEx_Cache.insert({pid, {GetTickCount(), new_region}});
  }

  auto regions = m_VirtualQueryEx_Cache[pid].second;

  for (auto &&m : regions) {
    if (lpAddress >= m.baseaddress && lpAddress < m.baseaddress + m.size) {
      *rinfo = m;
      return 1;
    }
  }
  return 0;
}
int VirtualQueryEx(HANDLE hProcess, uint64_t lpAddress, region_info *rinfo,
                   char *mapsline) {
  *rinfo = {0};
  if (GetHandleType(hProcess) == htProcesHandle) {
    Process *p = (Process *)GetPointerFromHandle(hProcess);
    if (p) {
      m_VirtualQueryEx_Cache_lock.lock();
      int result = VirtualQueryExImpl(p, lpAddress, rinfo, mapsline);
      m_VirtualQueryEx_Cache_lock.unlock();
      return result;
    }
  }
  return 0;
}

std::shared_ptr<std::list<region_info>> VirtualQueryExFull(HANDLE hProcess,
                                                           uint32_t flags) {
  if (GetHandleType(hProcess) == htProcesHandle) {
    Process *p = (Process *)GetPointerFromHandle(hProcess);
    if (p) {
      return std::make_shared<std::list<region_info>>(
          TraverseMemoryRegion(p->GetPid()));
    }
  }
  return std::make_shared<std::list<region_info>>();
}

} // namespace ceserver
