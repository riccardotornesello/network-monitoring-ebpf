# Network monitoring with eBPF

This project is a POC of a traffic monitoring system using eBPF.

It was created in a lab in the Software Networking 2024-25 course at the Politecnico di Torino taught by Professor Fulvio Risso.

Special thanks to [Federico Parola](https://github.com/FedeParola "FedeParola on GitHub") who created the initial structure of the project.

## Building

Install pre-requirements:
```sh
sudo apt update
sudo apt install -y clang libelf-dev zlib1g-dev gcc-multilib
```

Init libbpf and bpftool submodules:
```sh
git submodule update --init --recursive
```

Build and install libbpf:
```sh
cd ./libbpf/src
make
sudo make install
# Make sure the loader knows where to find libbpf
sudo ldconfig /usr/lib64
```

Build and install bpftool:
```sh
cd ./bpftool/src
make
sudo make install
```

Build and run the network monitor:
```sh
make
sudo ./network_monitor <ifname>
```