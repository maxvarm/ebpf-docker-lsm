# Docker-aware KRSI (BPF+LSM) security monitoring and prevention tool
My attempt to connect eBPF LSM hooks with docker context like container ID, name, and image. The tool works by correlating cgroup inode available
from the kernel part with docker container id available from user space. For now, it is possible to audit outbound IPv4 network connections via
`lsm/socket_connect` hook and process creation via `lsm/bprm_check_security` hook.

## Build
A modern, BTF and LSM-capable kernel is required to run the tool (5.7+ I suppose). From my observations, Ubuntu 22.04 does not yet enable LSM
features by default, but I managed to run it Manjaro Linux without any kernel changes. To run the tool.

(BTF/LSM) One of these commands must return two "y":
```bash
zcat /proc/config.gz | grep -E 'CONFIG_DEBUG_INFO_BTF=|CONFIG_BPF_LSM='
cat /boot/config | grep -E 'CONFIG_DEBUG_INFO_BTF=|CONFIG_BPF_LSM='
cat /boot/config-$(uname -r) | grep -E 'CONFIG_DEBUG_INFO_BTF=|CONFIG_BPF_LSM='
```
(LSM hooks) One of these commands must have "bpf" flag:
```bash
zcat /proc/config.gz | grep CONFIG_LSM=
cat /boot/config | grep CONFIG_LSM=
cat /boot/config-$(uname -r) | grep CONFIG_LSM=
```
(Build) You must also install kernel headers, C compiler, and bpftool to build the tool from source. Then:
```bash
git clone --recurse-submodules https://github.com/maxvarm/ebpf-docker-lsm.git
cd ebpf-docker-lsm && make
sudo ./ebpf-docker
```

## Examples
1. Run the tool as root
```bash
sudo ./ebpf-docker
```
2. Check **DEMO_BLOCK_*** macros in ebpf-docker.bpf.c
3. Run some commands to fit into **DEMO_BLOCK_*** condition
4. Check the error and appropriate events in ebpf-docker.log

### Block a specific process only for a specific image:
![image](https://github.com/maxvarm/ebpf-docker-lsm/blob/main/images/1.png?raw=true)

### Block outbound connections to 4444 port from host and containers:
![image](https://github.com/maxvarm/ebpf-docker-lsm/blob/main/images/2.png?raw=true)

### Check how it appears in logs (ebpf-docker.log):
![image](https://github.com/maxvarm/ebpf-docker-lsm/blob/main/images/3.png?raw=true)
