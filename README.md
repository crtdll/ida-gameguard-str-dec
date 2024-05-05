# GameGuard String Decryption (IDA)

This script is designed to identify the decryption function within any GameGuard module, decrypting them and subsequently labeling them in both the decompilation and assembly, while also outputting them to a file.

## Usage
Load your preferred GameGuard module dump into IDA, then utilize `File -> Script File` to load it.

## Notes
Some interesting strings to look out for:
```
x64dbg.exe
[IsScanSkip] skip: WhiteList. %d, %ws
d3dhook.dll
Inject Check: %lu, %s
SUSPECT_KERNEL_MANIPULATION
Scan64Thread SuspendThread
checkp text section md5 : %s
checkp md5 : %d, %s
GG_GRT_VIRUS
\kaspersky lab\
MD5 Succ %d %d
BinaryPattern Succ %d %d
Check threads(%d): h:%d %d (%d)
e8: %x %x (%x): %x %x %x %x %x %x %x %x %x
[LS] checkpkernelmem, addr: %p, base: %p size: %x, image: %s, i: %d
(PID: %lu, Ret: %p) BitBlt(%x, %d, %d, %d, %d, %x, %d, %d, %x)
process allowed, API : %02x, procHash : %08x
```
