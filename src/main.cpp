#include "../include/syscalls.h"

/* Códigos ANSI para cores no terminal para melhorar visualização de logs */
#define COLOR_RESET     "\033[0m"
#define COLOR_GRAY      "\033[90m"
#define COLOR_BOLD      "\033[1m"
#define COLOR_YELLOW    "\033[33m"

#include <sstream>

/**
 * @brief Retorna a data e hora atual no formato "YYYY-MM-DD HH:MM:SS.mmm".
 * 
 * Utiliza o relógio do sistema (`CLOCK_REALTIME`) para obter o timestamp atual com precisão em milissegundos.
 * 
 * O formato da string retornada é: "2025-07-17 22:45:30.123", onde os últimos três dígitos representam os milissegundos.
 * 
 * @return std::string String formatada com o timestamp atual.
 */
std::string current_timestamp() {
    char buffer[64];   // Buffer para armazenar a parte principal da data e hora
    timespec ts;       // Estrutura para armazenar tempo com segundos e nanossegundos

    clock_gettime(CLOCK_REALTIME, &ts);   // Obtém o tempo atual
    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);   // Converte tempo para hora local de forma thread-safe
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);   // Formata a data e hora
 
    char final_buf[80];   // Buffer final que inclui os milissegundos
    snprintf(final_buf, sizeof(final_buf), "%s.%03ld", buffer, ts.tv_nsec / 1000000);

    return final_buf;
}

/**
 * @brief Lê uma string da memória de um processo externo identificado pelo PID.
 * 
 * A função lê a string a partir do endereço virtual `addr` no processo `pid`, 
 * utilizando a chamada ptrace com o comando PTRACE_PEEKDATA, que lê um "long" de dados.
 * A leitura é feita em blocos do tamanho de `long` bytes e os caracteres são concatenados 
 * até encontrar o terminador nulo '\0' ou ocorrer um erro.
 * 
 * @param pid Identificador do processo alvo (process ID).
 * @param addr Endereço virtual dentro do processo alvo de onde a leitura deve começar.
 * @return std::string A string lida da memória do processo. Se ocorrer erro, retorna a string parcialmente lida.
 */
std::string read_string_from_pid(pid_t pid, unsigned long addr) {
    std::string result;
    union {
        long word;    /// Armazena o dado lido (um "long" de tamanho da arquitetura)
        char chars[sizeof(long)];   /// Permite acessar o dado byte a byte
    } data;

    while (true) {
        errno = 0;   // Resetar errno antes da chamad
        data.word = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);    // Lê um word da memória do processo

        if (errno != 0) break;  // Se ocorreu erro na leitura (ex: endereço inválido), interrompe a leitura

        // Percorre byte a byte o dado lido procurando o caractere nulo terminador
        for (int i = 0; i < sizeof(long); i++) {
            if (data.chars[i] == '\0') return result;   // Se achar o terminador, retorna a string acumulada
            result += data.chars[i];                    // Caso contrário, adiciona o caractere à string resultante
        }

        addr += sizeof(long);   // Avança para o próximo bloco da memória
    }

    return result;
}

/**
 * @brief Verifica se um argumento de uma syscall é uma string legível (endereçada na memória do processo).
 * 
 * Essa função é usada para identificar quais argumentos de chamadas de sistema são ponteiros
 * para strings que podem ser lidas diretamente na memória do processo monitorado, para que possam ser
 * interpretados, exibidos ou logados corretamente.
 * 
 * @param syscall_num Número da chamada de sistema (constantes do sistema, ex: SYS_execve).
 * @param arg_index Índice do argumento (0-based) dentro da chamada.
 * @return true Se o argumento indicado é um ponteiro para uma string legível na memória.
 * @return false Caso contrário.
 * 
 * @note Atualmente cobre apenas alguns casos comuns, como:
 *  - syscall execve: o argumento 0 é o caminho do programa (string)
 *  - syscall openat: o argumento 1 é o caminho do arquivo (string)
 *  - syscall open: o argumento 0 é o caminho do arquivo (string)
 *  - syscall write: o argumento 1 é o buffer de dados (string ou bytes)
 */
bool is_readable_string_syscall_arg(long syscall_num, int arg_index) {
    // Ex: execve(0)
    if (syscall_num == SYS_execve && arg_index == 0) return true;
    if (syscall_num == SYS_openat && arg_index == 1) return true;
    if (syscall_num == SYS_open && arg_index == 0) return true;
    if (syscall_num == SYS_write && arg_index == 1) return true;
    return false;
}


/**
 * Função principal que rastreia syscalls de um processo filho.
 * Utiliza ptrace para capturar entrada e saída de chamadas do sistema.
 */
int main(int argc, char* argv[]) {

    // Verifica se o usuário passou um comando para rastrear
    if (argc < 2) {
        std::cerr << "Uso: " << argv[0] << " <comando>\n";
        return 1;
    }

    // Abre arquivo de log e imprime cabeçalho
    std::ofstream logfile("syscall_log.csv");
    logfile << "[Timestamp] PID - Syscall (Arg1, Arg2, Arg3) = Return\n";
    std::cout << "[Timestamp] PID - Syscall (Arg1, Arg2, Arg3) = Return\n";

    // Cria um processo filho
    pid_t child = fork();

    if (child == 0) {
        // Processo filho: solicita rastreamento via ptrace
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        kill(getpid(), SIGSTOP);    // pausa até que o pai esteja pronto

        // Executa o comando fornecido
        execvp(argv[1], &argv[1]);

        perror("execvp");
        return 1;
    } else {
        // Processo pai: inicia o rastreamento
        int status, retval;
        struct user_regs_struct regs;
        bool entering = true;   // alterna entre entrada e saída da syscall

        waitpid(child, &status, 0);     // espera o filho parar
        ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);    // inicia rastreamento

        // Loop principal de rastreamento
        while (true) {
            waitpid(child, &status, 0);     
            if (WIFEXITED(status)) break;   // filho terminou

            ptrace(PTRACE_GETREGS, child, nullptr, &regs);  // coleta registradores

            if (entering) {
                // --- ENTRADA DA SYSCALL ---
                long syscall_num = regs.orig_rax;
                std::string syscall_name = Syscall::get_syscall_name(syscall_num);

                std::ostringstream line;
                line << COLOR_GRAY << "[" << current_timestamp() << "]" << COLOR_RESET;
                line << " PID:" << child << " - ";
                line << COLOR_BOLD << COLOR_YELLOW << syscall_name << COLOR_RESET << "(";

                // Verifica se temos metadados da syscall
                if ( Syscall::syscall_map.find(syscall_num) !=  Syscall::syscall_map.end()) {
                    const auto& info = Syscall::syscall_map.at(syscall_num);
                    int real_arg_count = std::min(info.arg_count, static_cast<int>(info.args.size()));

                    for (int i = 0; i < real_arg_count; ++i) {
                        std::string type = info.args[i];

                        unsigned long arg = 0;

                        // Coleta argumentos correspondente
                        switch (i) {
                            case 0: arg = regs.rdi; break;
                            case 1: arg = regs.rsi; break;
                            case 2: arg = regs.rdx; break;
                        }

                        // Se o argumento é uma string legível
                        if (type.find("char") != std::string::npos && is_readable_string_syscall_arg(syscall_num, i)) {
                            if (arg == 0) {
                                line << "NULL";
                            } else {
                                try {
                                    std::string str = read_string_from_pid(child, arg);
                                    line << "\"" << str << "\"";
                                } catch (...) {
                                    line << "\"<erro ao ler>\"";
                                }
                            }
                        } else {
                            // Caso contrário, exibe em hexadecimal
                            line << "0x" << std::hex << arg;
                        }

                        if (i < info.arg_count - 1) line << ", ";
                    }
                }

                line << ") = ";

                // Pega valor de retorno antecipadamente
                retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX, 0);

                // Imprime linha sem o valor de retorno ainda
                logfile << line.str();
                std::cout << line.str();

            } else {
                // --- SAÍDA DA SYSCALL ---
                std::ostringstream ret_line;

                ret_line << retval;

                // Se valor de retorno for negativo, é erro
                if (retval < 0) {
                    ret_line << " [" << strerror(-retval) << "]";
                }
                ret_line << std::endl;

                logfile << ret_line.str();
                std::cout  << ret_line.str();            
            }

            // Alterna entre entrada e saída
            entering = !entering;

            // Continua para próxima syscall
            ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);
        }

        logfile.close();    // fecha arquivo de lo
    }

    return 0;
}