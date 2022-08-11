all:
	rm -f redirectHTTPS.o redirectHTTPS.bpf
	clang -D DEBUG -target bpf -Wall -Werror -O2 -c -g -emit-llvm -c redirectHTTPS.c -o - | llc -march=bpf -filetype=obj -o redirectHTTPS.o
	sudo ip -force link set dev eth0 xdpdrv off
	sudo ip link set dev eth0 xdpdrv obj redirectHTTPS.o sec xdp

note:
	# clang -c Compile source code without linking
	# clang -g debug info
	# clang -O2 O1 O0 O0=debug 
	# clang -S -target bpf -D __BPF_TRACING__ -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Werror -O2 -emit-llvm -c -g -o redirectHTTPS.bpf redirectHTTPS.c
	# prlimit --memlock=unlimited --pid $$; ulimit -s unlimited
	# sudo ip link set dev eth0 xdp off

install:
	dnf install clang llvm bpftool
	dnf install elfutils-libelf-devel libpcap-devel perf
	dnf install kernel-headers kernel-devel
	apt install linux-tools-common linux-tools-generic
	prlimit --memlock=unlimited --pid $$; ulimit -s unlimited
	ethtool -K eth0 lro off	
	ethtool -K eth0 tx off
	
wsl:
	## kernel bpftool
	# error #BTF: .tmp_vmlinux.btf: pahole (pahole) is not available,Failed to generate BTF for vmlinux
	# sudo apt install dwarves  # DWARF utilities, DWARF debugging information inserted in ELF binaries by the compiler
	# zcat /proc/config.gz > .config
	# make menuconfig # enable BTF BPF
	# make -j8;make modules -j8;make modules_install -j8;make install -j8
	cp arch/x86/boot/bzImage /mnt/e/vm/bzImage
	vim /mnt/c/Users/<username>/.wslconfig
	netsh int ipv4 show interfaces
	Get-WMIObject Win32_networkadapter | Select-Object Name, AdapterType, InterfaceIndex | Format-List 

debug:
	# mount -t bpf none /sys/fs/bpf/
	# mount -t debugfs nodev /sys/kernel/debug
	# cat /sys/kernel/debug/tracing/trace_pipe
	# bpftool prog tracelog  //功能同上
	# apt install linux-tools-common
	# bpftool map update id 25 key 0 0 0 0 value 1 0 0 0
    # bpftool map update id 1337 key hex ff 13 37 ff value hex 0 0 0 0 0 0 1a 2b
	# bpftool map dump name METRICS_MAP
	# curl -I mip.chinaz.com
	# curl -H "Accept: application/json" -H "Content-Type: application/json" -I poem.tuweng.com
	# curl -I poem.tuweng.com !!! error, request body size < 78bytes, 放不下redirect的body，  pkg->data_cursor + len_payload > pkg->data_end
	not ssh and not dns and not tls and not ip.addr == 20.212.97.243 and not ip.addr == 13.107.42.16
	not tls and tcp and ip.addr == 47.75.204.169 or not ip.addr == 10.0.0.1
	tcp and ip.addr == 192.168.1.34 or ip.addr == 47.75.204.169
	curl -i -H "Accept: application/json" -H "Content-Type: application/json" -I 192.168.187.189
	
xdpnative:
	jutian@yaoshun-OptiPlex-3050:~$ ethtool -i enp1s0
	driver: r8169
	version: 5.13.0-37-generic
	firmware-version: rtl8168h-2_0.0.2 02/26/15
	expansion-rom-version: 
	bus-info: 0000:01:00.0
	supports-statistics: yes
	supports-test: no
	supports-eeprom-access: no
	supports-register-dump: yes
	supports-priv-flags: no
	jutian@yaoshun-OptiPlex-3050:~$ lspci | grep -i net
	01:00.0 Ethernet controller: Realtek Semiconductor Co., Ltd. RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller (rev 15)
