#include "../include/common.h"
#include "../include/syscalls.h"

#include <sstream>

std::string current_timestamp() {
    char buffer[64];
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);
    char final_buf[80];
    snprintf(final_buf, sizeof(final_buf), "%s.%03ld", buffer, ts.tv_nsec / 1000000);
    return final_buf;
}

std::string read_string_from_pid(pid_t pid, unsigned long addr) {
    std::string result;
    union {
        long word;
        char chars[sizeof(long)];
    } data;

    while (true) {
        errno = 0;
        data.word = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
        if (errno != 0) break;

        for (int i = 0; i < sizeof(long); i++) {
            if (data.chars[i] == '\0') return result;
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

    std::ofstream logfile("syscall_log.csv");
    logfile << "[Timestamp] PID - Syscall (Arg1, Arg2, Arg3) = Return\n";
    std::cout << "[Timestamp] PID - Syscall (Arg1, Arg2, Arg3) = Return\n";

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        kill(getpid(), SIGSTOP);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        return 1;
    } else {
        int status;
        struct user_regs_struct regs;
        bool entering = true;
        waitpid(child, &status, 0);
        ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);

        while (true) {
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            ptrace(PTRACE_GETREGS, child, nullptr, &regs);

            if (entering) {
                long syscall_num = regs.orig_rax;
                std::string syscall_name = Syscall::get_syscall_name(syscall_num);

                // if (syscall_name == "open" || syscall_name == "execve") {
                //     std::string arg1 = read_string_from_pid(child, regs.rdi);
                //     line << "\"" << arg1 << "\", ";
                // } else {
                //     line << "0x" << std::hex << regs.rdi << ", ";
                // }

                // line << "0x" << std::hex << regs.rsi << ", ";
                // line << "0x" << std::hex << regs.rdx << ") = ";

                std::ostringstream line;
                line << "[" << current_timestamp() << "] ";
                line << child << " - " << syscall_name << "(";

                if ( Syscall::syscall_map.find(syscall_num) !=  Syscall::syscall_map.end()) {
                    const auto& info = Syscall::syscall_map.at(syscall_num);
                    int real_arg_count = std::min(info.arg_count, static_cast<int>(info.args.size()));

                    for (int i = 0; i < real_arg_count; ++i) {
                        std::string type = info.args[i];

                        unsigned long arg = 0;
                        switch (i) {
                            case 0: arg = regs.rdi; break;
                            case 1: arg = regs.rsi; break;
                            case 2: arg = regs.rdx; break;
                        }

                        if (type.find("char") != std::string::npos) {
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
                            line << "0x" << std::hex << arg;
                        }

                        if (i < info.arg_count - 1) line << ", ";
                    }
                }

                line << ") = ";

                logfile << line.str();
                std::cout << line.str();

            } else {
                std::ostringstream ret_line;
                long retorno = (long)regs.rax;

                ret_line << retorno << " (0x" << std::hex << regs.rax << ")";
                if (retorno < 0) {
                    ret_line << " [" << strerror(-retorno) << "]";
                }
                ret_line << std::endl;

                logfile << ret_line.str();
                std::cout  << ret_line.str();            
            }

            entering = !entering;
            ptrace(PTRACE_SYSCALL, child, nullptr, nullptr);
        }

        logfile.close();
    }

    return 0;
}