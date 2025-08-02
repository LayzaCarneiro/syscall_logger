# LTracer - Syscall Logger

**LTracer** is a system call logger written in **C++ for Linux**.
It traces syscalls made by a process and displays:

* Timestamp of each call
* Process PID
* System call name
* Call parameters
* Return value

This tool is useful for debugging, analyzing process behavior, learning about Linux internals, or building observability tools.

<img width="900" height="315" alt="Captura de Tela 2025-08-02 às 16 00 11" src="https://github.com/user-attachments/assets/99daa5dc-9719-4e80-a79b-b21ebc4f772f" />


---

## 📁 Project Structure

```
LTracer/
├── CMakeLists.txt
├── include/
│   ├── common.h
│   └── syscalls.h
├── src/
│   └── main.cpp
├── utils/
│   └── syscallmap.cpp
```

---

## ⚙️ Build Instructions

This project uses **CMake**.

```bash
git clone https://github.com/LayzaCarneiro/LTracer.git
cd LTracer
mkdir build
cd build
cmake ..
make
```

The executable will be generated as:

```bash
./LTracer
```

---

## ▶️ Usage

Run `LTracer` followed by the command you want to trace:

```bash
./LTracer <command>
```

### Example:

```bash
./LTracer ls
```

This will execute `ls` and print all syscalls made during its execution, showing the timestamp, PID, syscall name, parameters, and return value.

---

## ✅ Requirements

* Linux (any distribution that supports `ptrace`)
* CMake 3.10 or higher
* C++17-compatible compiler
