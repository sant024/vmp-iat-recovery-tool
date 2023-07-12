# vmp-iat-recovery-tool

## What is this?
A tool to recover the import address table of x64 bit PE binaries obfuscated with VMProtect 3.x. 



## Usage

1. Edit the file name in main.rs to the name of the process
2. Set "rebuild_iat" to true to patch the binary (currently broken)
3. Open the terminal and perform cargo run 

## How it works

It collects modules within the current running process, and saves them. It then emulates the program and adds a code hook to log import calls. Once that is done, the import address table
is repaired.


## Disclaimer

This tool is currently unstable and may not work correctly. 
The code is for educational purposes.
