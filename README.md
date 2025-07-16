## 📦 Compilação

Este projeto usa CMake.

```bash
git clone https://github.com/LayzaCarneiro/LTracer.git
cd LTracer
mkdir build
cd build
cmake ..
make
````

O executável será gerado como `./LTracer`.

## ▶️ Uso

```bash
./LTracer <comando>
```

Exemplo:

```bash
./LTracer ls -l /home
```

Isso executará `ls -l /home` e imprimirá as syscalls chamadas durante a execução.
