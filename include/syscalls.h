#pragma once
#include "common.h"

namespace Syscall
{
    /**
     * @struct SyscallInfo
     * @brief Estrutura que representa as informações de uma chamada de sistema.
     * 
     * Contém o nome da syscall, a quantidade de argumentos que ela espera e 
     * uma lista contendo os tipos desses argumentos.
     */
    struct SyscallInfo
    {
        std::string name; /// Nome da chamada de sistema (ex: "open", "read")
        int arg_count; /// Quantidade de argumentos que a syscall recebe
        std::vector<std::string> args; /// Vetor contendo os tipos dos argumentos
    };


    /**
     * @brief Map que associa o número da syscall à sua respectiva informação.
     * 
     * Cada entrada do mapa usa como chave o número inteiro da syscall e como valor uma estrutura SyscallInfo
     * que contém nome e detalhes dos argumentos da syscall.
     */
    extern const std::unordered_map<int, SyscallInfo> syscall_map;

    /**
     * @brief Retorna o nome da syscall dado o número da chamada.
     * 
     * @param syscall_num Número inteiro da chamada de sistema.
     * @return std::string Nome da syscall correspondente. Se o número não existir no mapa, retorna uma string padrão (ex: "unknown").
     */
    std::string get_syscall_name(long syscall_num);

} 