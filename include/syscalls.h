#pragma once
#include "common.h"


#include <unordered_map>   // Utilizado para o mapa de chamadas de sistema
#include <string> // Utilizado para as strings de nomes e tipos de argumentos das chamadas de sistema
#include <vector> // Utilizado para os vetores dos argumentos das chamadas de sistema

namespace Syscall
{
    struct SyscallInfo
    {
        std::string name;
        int arg_count;
        std::vector<std::string> args;
    };

    extern const std::unordered_map<int, SyscallInfo> syscall_map;

    std::string get_syscall_name(long syscall_num);

} 