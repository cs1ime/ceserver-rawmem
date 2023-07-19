
#ifndef _DMA_INTERFACE_H_
#define _DMA_INTERFACE_H_

#include <memory>
#include "dma_type.h"
#include "dma_mmu.h"
#include "dma_ntutil.h"
#include "dma_symbol.h"

class ntfunc_creator
{
public:
    ntfunc_creator(std::shared_ptr<dma_symbol_factory> symbol_factory,
                   std::function<bool(physaddr pa, u8 *pb, u32 cb)> _read_physical_memory,
                   std::function<bool(physaddr pa, u8 *pb, u32 cb)> _write_physical_memory) : read_physical_memory(_read_physical_memory),
                                                                                              write_physical_memory(_write_physical_memory),
                                                                                              m_symbol_factory(symbol_factory)
    {
    }
    std::shared_ptr<ntfuncs>
    try_create();

private:
    physaddr mmu_get_pa_from_dtb(physaddr dtb, uptr va);
    uptr dma_find_MmPfnDataBase_from_dtb(u8 *pb);
    uptr dma_find_selfmapping_ptebase(u8 *pb, physaddr pa);
    bool dma_check_root_tb(u8 *pb, physaddr pa);
    physaddr dma_find_root_tb();
    u64 dma_find_ntoskrnl(physaddr dtb);

    std::shared_ptr<mmu> g_sysmmu = 0;
    physaddr g_root_tb = 0;
    u64 g_ptebase = 0;
    u64 g_pfnbase = 0;
    std::shared_ptr<dma_symbol_factory> m_symbol_factory;
    std::function<bool(physaddr pa, u8 *pb, u32 cb)> read_physical_memory;
    std::function<bool(physaddr pa, u8 *pb, u32 cb)> write_physical_memory;
};
#endif // !_DMA_INTERFACE_H_
