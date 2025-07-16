// #include <sys/ptrace.h>
// #include <sys/wait.h>
// #include <sys/user.h>
// #include <sys/types.h>
// #include <unistd.h>
// #include <time.h>
// #include <errno.h>
// #include <cstring>
// #include <iostream>
// #include <fstream>

// #include "syscalls.h"

// std::string current_timestamp() {
//     char buffer[64];
//     timespec ts;
//     clock_gettime(CLOCK_REALTIME, &ts);
//     struct tm tm_info;
//     localtime_r(&ts.tv_sec, &tm_info);
//     strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
//     char final_buf[80];
//     snprintf(final_buf, sizeof(final_buf), "%s.%03ld", buffer, ts.tv_nsec / 1000000);
//     return final_buf;
// }

// int main(int argc, char* argv[]) {
//     if (argc < 2) {
//         std::cerr << "Uso: " << argv[0] << " <comando>\n";
//         return 1;
//     }

//     std::ofstream logfile("syscall_log.csv");
//     logfile << "[Timestamp] PID - Syscall (Arg1, Arg2, Arg3) = Return\n";

//     pid_t child = fork();
//     if (child == 0) {
//         ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
//         kill(getpid(), SIGSTOP);
//         execvp(argv[1], &argv[1]);
//         perror("execvp");
//         return 1;
//     } else {
//         int status;
//         struct user_regs_struct regs;
//         bool entering = true;
//         waitpid(child, &status, 0);
//         ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);

//         while (true) {
//             waitpid(child, &status, 0);
//             if (WIFEXITED(status)) break;

//             ptrace(PTRACE_GETREGS, child, nullptr, &regs);

//             if (entering) {
//                 long syscall_num = regs.orig_rax;
//                 std::string syscall_name = get_syscall_name(syscall_num);

//                 std::string timestamp = current_timestamp();
//                 logfile << "[" << timestamp << "] ";
//                 logfile << child << " - ";
//                 logfile << syscall_name << " (";
//                 logfile << "0x" << std::hex << regs.rdi << ", ";
//                 logfile << "0x" << std::hex << regs.rsi << ", ";
//                 logfile << "0x" << std::hex << regs.rdx << ") = ";
//             } else {
//                 logfile << "0x" << std::hex << regs.rax << "\n";
//             }

//             entering = !entering;
//             ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);
//         }

//         logfile.close();
//     }

//     return 0;
// }

// // g++ -Wall -o syscall_logger main.cpp
// // sudo ./syscall_logger ls -la

#include "common.h"
#include "syscalls.h"

std::string read_string_from_pid(pid_t pid, unsigned long addr) {
    std::string result;
    union {
        long word;
        char chars[sizeof(long)];
    } data;

    while (true) {
        errno = 0;
        data.word = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
        if (errno != 0) {
            perror("ptrace(PTRACE_PEEKDATA) failed");
            break;
        }

        for (int i = 0; i < sizeof(long); ++i) {
            if (data.chars[i] == '\0') {
                return result;
            }
            result += data.chars[i];
        }

        addr += sizeof(long);
    }

    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Uso: " << argv[0] << " <comando>\n";
        return 1;
    }

    pid_t child = fork();

    if (child == 0) {
        // Processo filho
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        kill(getpid(), SIGSTOP);  // Sinaliza para o pai se preparar
        execvp(argv[1], &argv[1]); // Executa o comando
        perror("execvp falhou");
        return 1;
    } else {
        // Processo pai
        int status;
        waitpid(child, &status, 0);  // Espera o filho parar

        ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);

        while (true) {
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, nullptr, &regs);

            long syscall = regs.orig_rax;

            // std::cout << "[PID " << child << "] syscall: " << get_syscall_name(syscall) << "\n";

            if (syscall == SYS_open || syscall == SYS_openat || syscall == SYS_execve) {
                std::string path = read_string_from_pid(child, regs.rdi);
                std::cout << "[PID " << child << "] syscall: " << get_syscall_name(syscall)
                        << " (\"" << path << "\")\n";
            } else {
                std::cout << "[PID " << child << "] syscall: " << get_syscall_name(syscall)
                        << " (" << std::hex << "0x" << regs.rdi << ")\n";
            }

            ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);
        }
    }

    return 0;
}
