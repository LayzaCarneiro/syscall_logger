#include "../include/common.h"
#include "../include/syscalls.h"

#define COLOR_RESET     "\033[0m"
#define COLOR_GRAY      "\033[90m"
#define COLOR_BOLD      "\033[1m"
#define COLOR_YELLOW    "\033[33m"

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

bool is_readable_string_syscall_arg(long syscall_num, int arg_index) {
    // Ex: execve(0)
    if (syscall_num == SYS_execve && arg_index == 0) return true;
    if (syscall_num == SYS_openat && arg_index == 1) return true;
    if (syscall_num == SYS_open && arg_index == 0) return true;
    if (syscall_num == SYS_write && arg_index == 1) return true;
    return false;
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
        int status, retval;
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

                std::ostringstream line;
                line << COLOR_GRAY << "[" << current_timestamp() << "]" << COLOR_RESET;
                line << " PID:" << child << " - ";
                line << COLOR_BOLD << COLOR_YELLOW << syscall_name << COLOR_RESET << "(";

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
                            line << "0x" << std::hex << arg;
                        }

                        if (i < info.arg_count - 1) line << ", ";
                    }
                }

                line << ") = ";

                retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX, 0);
                logfile << line.str();
                std::cout << line.str();

            } else {
                std::ostringstream ret_line;

                ret_line << retval;
                if (retval < 0) {
                    ret_line << " [" << strerror(-retval) << "]";
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