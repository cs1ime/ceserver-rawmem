#include <iostream>
#include <algorithm>
#include "pdb_parser.h"
#include <string.h>
#include <iomanip>

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("%s symbol/struct pdbfile\r\n", argv[0]);
        exit(1);
    }

    pdb_parser parser(argv[2]);

    std::cout << std::hex << std::uppercase;

    if (!strcmp(argv[1], "symbol"))
    {
        auto syms = parser.get_all_symbols();
        for (auto &&[name, address] : syms)
        {
            std::cout << name << " = 0x" << address << std::endl;
        }
    }

    if (!strcmp(argv[1], "struct"))
    {
        auto structures = parser.get_all_structures();

        for (auto &&[name, fields] : structures)
        {
            std::vector<std::pair<std::string, field_info>> sortedVec(fields.begin(), fields.end());
            std::sort(sortedVec.begin(), sortedVec.end(), [](auto &&a, auto &&b) -> bool
                      {
                if(a.second.offset==b.second.offset)
                {
                    return a.second.bitfield_offset<b.second.bitfield_offset;
                }
                return a.second.offset<b.second.offset; });

            std::cout << "struct " << name << std::endl;
            std::cout << "{" << std::endl;

            for (auto &&[field_name, field_info] : sortedVec)
            {
                std::cout << "\t"
                          << "/* +0x" << std::setw(4) << std::setfill('0') << field_info.offset << " */\t" << field_info.type_name << " " << field_name;
                if (field_info.is_bitfield)
                {
                    std::cout << std::dec;
                    std::cout << " : " << field_info.bitfield_length;
                    std::cout << "  /* " << field_info.bitfield_offset << ":" << field_info.bitfield_offset + field_info.bitfield_length - 1 << " */";
                    std::cout << std::hex;
                }
                std::cout << "; " << std::endl;
            }

            std::cout << "}" << std::endl;
        }
    }

    return 0;
}
