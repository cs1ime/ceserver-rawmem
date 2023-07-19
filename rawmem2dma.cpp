#include <dma_type.h>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>
#include <fstream>
#include <list>
#include <tuple>
#include <functional>
#include <utility>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define printf

namespace rawmem2dma
{
    int m_rawmemfd = 0;
    void *m_mapped_addr = nullptr;
    long m_mapped_size = 0;
    bool rawmem2dma_init(const char *filename)
    {
        int fd = open(filename, O_RDONLY);
        if (fd != -1)
        {
            struct stat st = {};
            if (stat(filename, &st) == 0)
            {
                void *addr = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
                if (addr != nullptr)
                {
                    m_mapped_addr = addr;
                    m_mapped_size = st.st_size;
                    return true;
                }
                else
                {
                    perror("mmap");
                }
            }
            else
            {
                perror("stat");
            }
            close(fd);
        }
        else
        {
            perror("open");
        }
        return false;
    }
    void rawmem2dma_uninit()
    {
        if (m_mapped_addr != nullptr)
        {
            munmap(m_mapped_addr, m_mapped_size);
            m_mapped_addr = nullptr;
            m_mapped_size = 0;
        }
        if (m_rawmemfd != 0)
        {
            close(m_rawmemfd);
            m_rawmemfd = 0;
        }
    }
    bool dma_read_physical_memory_impl(physaddr pa, u8* pb, u32 cb)
    {
        if (!rawmem2dma::m_mapped_addr || rawmem2dma::m_mapped_size == 0)
        {
            return false;
        }
        uint64_t realsize = pa + cb;
        if (realsize > rawmem2dma::m_mapped_size)
        {
            return false;
        }
        if (realsize == 0)
        {
            return false;
        }
        if (pa == D_BADPHYSADDR)
            return false;
        memcpy(pb, pa + (unsigned char *)rawmem2dma::m_mapped_addr, cb);
        return true;
    }
    bool dma_write_physical_memory_impl(physaddr pa, u8* pb, u32 cb)
    {
        if (!rawmem2dma::m_mapped_addr || rawmem2dma::m_mapped_size == 0)
        {
            return false;
        }
        uint64_t realsize = pa + cb;
        if (realsize > rawmem2dma::m_mapped_size)
        {
            realsize = rawmem2dma::m_mapped_size;
        }
        if (realsize == 0)
        {
            return false;
        }
        if (pa == D_BADPHYSADDR)
            return false;
        return true;
    }

} // namespace rawmem2dma

