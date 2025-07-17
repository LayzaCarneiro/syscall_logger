#ifndef COMMON_H
#define COMMON_H


/**
 * @file common.h
 * @brief Cabeçalho comum com includes essenciais para manipulação de syscalls, processos, ptrace, entre outros.
 * 
 * Este arquivo centraliza as bibliotecas necessárias para operações de tracing de processos e chamadas de sistema,
 * incluindo manipulação de processos, leitura de registradores, e manipulação de arquivos.
 */

/* --- Includes do sistema para controle de processos e ptrace --- */
#include <sys/ptrace.h>   /// Para usar ptrace, ferramenta de controle e inspeção de processos.
#include <sys/types.h>    /// Tipos básicos do sistema (pid_t, etc).
#include <sys/wait.h>     /// Funções para espera de processos (wait, waitpid).
#include <sys/user.h>     /// Estruturas para acesso aos registradores do usuário (user_regs_struct).
#include <sys/syscall.h>  /// Definições das chamadas de sistema do Linux.
#include <unistd.h>       /// Funções básicas POSIX (fork, exec, read, write, etc).

/* --- Includes para entrada e saída, manipulação de strings e erros --- */
#include <iostream>       /// Entrada e saída padrão (cout, cerr, etc).
#include <cstdlib>        /// Funções utilitárias padrão (exit, etc).
#include <cstring>        /// Funções para manipulação de strings C (memcpy, strcmp).
#include <string>         /// Classe std::string para manipulação de strings C++.
#include <errno.h>        /// Variável errno e macros para tratamento de erros.

/* --- Includes adicionais --- */
#include <map>            /// Estrutura std::map para associações chave-valor.
#include <sys/reg.h>      /// Definições dos offsets dos registradores em ptrace (ex: ORIG_RAX, RDI, etc).
#include <time.h>         /// Manipulação de data e hora.
#include <fstream>        /// Manipulação de arquivos via streams.
#include <unordered_map>  /// Utilizado para o mapa de chamadas de sistema
#include <vector>         /// Utilizado para os vetores dos argumentos das chamadas de sistema

#endif // COMMON_H
