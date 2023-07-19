#pragma once
#ifndef _LEECH_TO_DMA_H_
#define _LEECH_TO_DMA_H_

#include <dma_type.h>

namespace rawmem2dma
{
    bool rawmem2dma_init(const char *filename);
    void rawmem2dma_uninit();
}

bool dma_read_physical_memory_impl(physaddr pa, u8 *pb, u32 cb);
bool dma_write_physical_memory_impl(physaddr pa, u8 *pb, u32 cb);

#endif // !_LEECH_TO_DMA_H_
