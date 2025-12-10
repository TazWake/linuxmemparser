# Generating a Volatility Kernel Profile Using Debug Symbols

This guide explains how to obtain a DWARF-enabled `vmlinux` suitable for use with `dwarf2json`, even when the original acquisition system does not contain debug symbols. It covers:

- Checking whether the evidence system already contains usable symbols.
- Using Docker to acquire debug symbols for a matching kernel version.
- Validating that the retrieved `vmlinux` contains DWARF data.

This process is safe for DFIR workflows because all symbol generation occurs off-evidence.

---

## 1. Check Whether Debug Symbols Already Exist on the Evidence System

Before attempting symbol extraction from a kernel image (vmlinuz, bzImage), always check if the system already shipped with an unstripped debug kernel.

Run:

```bash
file /boot/vmlinux-* 2>/dev/null
```

If you see: 

```text
ELF 64-bit LSB executable ... not stripped
```

then you may already have a usable DWARF-containing `vmlinux` file.

To confirm, inspect for `.debug_*` sections:

```bash
readelf -S /boot/vmlinux-* | egrep 'debug_info|debug_line'
```

If debug sections show up, you can generate a profile immediately:

```bash
dwarf2json linux --elf /boot/vmlinux-[FILENAME or wildcard] > kernel.json
```

If no debug sections are present (typical for most distros), proceed to Section 2.

---

## 2. Using Docker to Obtain a Matching Debug Kernel

When the evidence machine does not include debug symbols, you can retrieve them from the appropriate Ubuntu Debug Symbol (“ddebs”) repositories using a throwaway Docker container. This is the recommended DFIR workflow and keeps modifications away from the evidence.

### 2.1 Identify the Kernel Version

From the evidence:

```bash
uname -r
```

Example:

```text
5.15.0-1031-aws
```

This identifies both the ABI and the correct debug package name. Note, if the system is not powered up, you will need to extract this from the filesystem. One option is to look at the symlink for the current kernel version in the `/boot` folder.

### 2.2 Start a Matching Ubuntu Container

Kernel `5.15.0-1031-aws` belongs to `Ubuntu 20.04 (focal)`, so we can start a focal container:

```bash
docker pull ubuntu:20.04
docker run --name kernel-dbg -it ubuntu:20.04 bash
```

Inside the container:

```bash
apt update
apt install -y wget gnupg lsb-release binutils
```

### 2.3 Enable Ubuntu Debug Symbol Repositories

Inside the container:

```bash
wget -O - https://ddebs.ubuntu.com/dbgsym-release-key.asc | apt-key add -

cat >/etc/apt/sources.list.d/ddebs.list << 'EOF'
deb http://ddebs.ubuntu.com focal main restricted universe multiverse
deb http://ddebs.ubuntu.com focal-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com focal-proposed main restricted universe multiverse
EOF

apt-get update
```

### 2.4 Install the Debug Kernel Package

Search for a matching debug symbol package:

```bash
apt-cache search 5.15.0-1031-aws-dbgsym
```

You should see packages such as:

```text
linux-image-unsigned-5.15.0-1031-aws-dbgsym
linux-image-5.15.0-1031-aws-dbgsym
```

Install one:

```bash
apt install -y linux-image-unsigned-5.15.0-1031-aws-dbgsym
```

This installs a full DWARF-enabled `vmlinux` under:

```text
/usr/lib/debug/boot/vmlinux-5.15.0-1031-aws
```

### 2.5 Copy the DWARF vmlinux to the Host

On the host, run: (Ensure the filename matches the file you are looking for)

```bash
docker cp kernel-dbg:/usr/lib/debug/boot/vmlinux-5.15.0-1031-aws ./vmlinux-debug
```

You now have a symbol-rich vmlinux suitable for profile generation.

---

## 3. Validate That the Retrieved Kernel Contains DWARF

Before using this, ensure the file really contains debug information:

```bash
readelf -S vmlinux-debug | egrep 'debug_info|debug_line'
```

Expected output includes sections such as:

```text
.debug_info
.rela.debug_info
.debug_line
.rela.debug_line
```

If these exist, the file is valid.

---

## 4. Generate the Kernel Profile

Use `dwarf2json`[^1]:

```bash
dwarf2json linux --elf vmlinux-debug > kernel-<version>.json
```

Example:

```bash
dwarf2json linux --elf vmlinux-debug > kernel-5.15.0-1031-aws.json
```

[^1]:  https://github.com/volatilityfoundation/dwarf2json
