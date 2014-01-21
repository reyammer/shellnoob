# ShellNoob

Writing shellcodes has always been super fun, but some parts are extremely
boring and error prone. Focus only on the fun part, and use **ShellNoob**! 

For a quick overview, check the slides for the Black Hat Arsenal talk:
[link](https://media.blackhat.com/us-13/Arsenal/us-13-Fratantonio-ShellNoob-Slides.pdf)

Want to contribute? Feature request? Bug report? Swears? **All** feedback is
welcome!! (But some kind of feedback is more welcome than others :-)).

Feel free to ping me on twitter [@reyammer](https://twitter.com/reyammer) or to
email me at yanick[AT]cs.ucsb.edu any questions!


## Contributors & Acknowledgments

- Levente Polyak ([@anthraxx42](https://twitter.com/anthraxx42))
    - added Python 3 support
    - bug fixes
- @ToolsWatch & Black Hat crews
    - They gave me a chance to show off my tool :D


## News

- *01/21/2014* - ShellNoob 2.1 is out! It comes with full support for Python 3 and tons of bug fixes. Full credits go to Levente Polyak!

- *07/29/2013* - ShellNoob 2.0 is out!

- *06/08/2013* - ShellNoob got accepted at Black Hat Arsenal! See announcement here: [link](http://www.blackhat.com/us-13/arsenal.html#Fratantonio).


## Features

- convert shellcode between different formats and sources. Formats currently supported: asm, bin, hex, obj, exe, C, python, ruby, pretty, safeasm, completec, shellstorm. (All details in the "Formats description" section.)
- interactive asm-to-opcode conversion (and viceversa) mode. This is useful when you cannot use specific bytes in the shellcode and you want to figure out if a specific assembly instruction will cause problems.
- support for both ATT & Intel syntax. Check the ```--intel``` switch.
- support for 32 and 64 bits (when playing on x86\_64 machine). Check the ```--64``` switch.
- resolve syscall numbers, constants, and error numbers (now implemented for real! :-)).
- portable and easily deployable (it only relies on gcc/as/objdump and python). It is just *one self-contained python script*, and it supports both Python2.7+ and Python3+.
- in-place development: you run ShellNoob directly on the target architecture!
- built-in support for Linux/x86, Linux/x86\_64, Linux/ARM, FreeBSD/x86, FreeBSD/x86\_64.
- "*prepend breakpoint*" option. Check the ```-c``` switch.
- read from stdin / write to stdout support (use "-" as filename)
- uber cheap debugging: check the ```--to-strace``` and ```--to-gdb``` option!
- Use ShellNoob as a Python module in your scripts! Check the "ShellNoob as a library" section.
- Verbose mode shows the low-level steps of the conversion: useful to debug / understand / learn!
- Extra plugins: binary patching made easy with the ```--file-patch```, ```--vm-patch```, ```--fork-nopper``` options! (all details below)


## Use Cases

### Built-in help
```bash
$ ./shellnoob.py -h
shellnoob.py [--from-INPUT] (input_file_path | - ) [--to-OUTPUT] [output_file_path | - ]
shellnoob.py -c (prepend a breakpoint (Warning: only few platforms/OS are supported!)
shellnoob.py --64 (64 bits mode, default: 32 bits)
shellnoob.py --intel (intel syntax mode, default: att)
shellnoob.py -q (quite mode)
shellnoob.py -v (or -vv, -vvv)
shellnoob.py --to-strace (compiles it & run strace)
shellnoob.py --to-gdb (compiles it & run gdb & set breakpoint on entrypoint)

Standalone "plugins"
shellnoob.py -i [--to-asm | --to-opcode ] (for interactive mode)
shellnoob.py --get-const <const>
shellnoob.py --get-sysnum <sysnum>
shellnoob.py --get-errno <errno>
shellnoob.py --file-patch <exe_fp> <file_offset> <data> (in hex). (Warning: tested only on x86/x86_64)
shellnoob.py --vm-patch <exe_fp> <vm_address> <data> (in hex). (Warning: tested only on x86/x86_64)
shellnoob.py --fork-nopper <exe_fp> (this nops out the calls to fork(). Warning: tested only on x86/x86_64)

"Installation"
shellnoob.py --install [--force] (this just copies the script in a convinient position)
shellnoob.py --uninstall [--force]

Supported INPUT format: asm, obj, bin, hex, c, shellstorm
Supported OUTPUT format: asm, obj, exe, bin, hex, c, completec, python, bash, ruby, pretty, safeasm
All combinations from INPUT to OUTPUT are supported!
```

### Installation (only if you want)
```bash
$ ./shellnoob.py --install
```
This will just copy the script to /usr/local/bin/snoob. That's it. (Run ```./shellnoob.py --uninstall``` to undo).

### Convert shellcode from/to different formats with a uber flexible CLI.
```bash
$ snoob --from-asm shell.asm --to-bin shell.bin
```

Some equivalent alternatives (the tool will try to guess what you want given the file extension..)  
```bash
$ snoob --from-asm shell.asm --to-bin
$ snoob shell.asm --to-bin
$ snoob shell.asm --to-bin - > shell.bin
$ cat shell.asm | snoob --from-asm - --to-bin - > shell.bin
```

### Formats description
- "asm" - standard assembly. ATT syntax by default, use ```--intel``` to use Intel syntax. (see "asm as output" section for more details)
- "bin" - raw binary ('\\x41\\x42\\x43\\x44')
- "hex" - raw binary encoded in hex ('41424344')
- "obj" - an ELF
- "exe" - an executable ELF
- "c" - something ready to embed in a C program.
- "python", "bash", "ruby" - same here.
- "completec" - compilable C that properly set the memory as RWX (to support self-modifying shellcodes)
- "safeasm" - assembly that is 100% assemblable: sometimes objdump's output, from which the "asm" is taken, is not assemblable. This will output the "raw" bytes (in .byte notation) so that it's assemblable by "as".
- "shellstorm" - The ```--from-shellstorm``` switch takes as argument a <shellcode_id>. ShellNoob will grab the selected shellcode from the shell-storm shellcode DB, and it will convert it to the selected
  format.


### Easy debugging
```bash
$ snoob -c shell.asm --to-exe shell
$ gdb -q shell
$ run
Reading symbols from ./shell...(no debugging symbols found)...done.
(gdb) run
Starting program: ./shell

Program received signal SIGTRAP, Trace/breakpoint trap.
0x08048055 in ?? ()
(gdb) 
```

Or you can use the new ```--to-strace``` and ```--to-gdb``` switches!
```bash
$ snoob open-read-write.asm --to-strace
Converting open-read-write.asm (asm) into /tmp/tmpBaQbzP (exe)
execve("/tmp/tmpBaQbzP", ["/tmp/tmpBaQbzP"], [/* 97 vars */]) = 0
[ Process PID=12237 runs in 32 bit mode. ]
open("/tmp/secret", O_RDONLY)           = 3
read(3, "thesecretisthedolphin\n", 255) = 22
write(1, "thesecretisthedolphin\n", 22thesecretisthedolphin
) = 22
_exit(0)  
```

```bash
$ snoob open-read-write.asm --to-gdb
Converting open-read-write.asm (asm) into /tmp/tmpZdImWw (exe)
Reading symbols from /tmp/tmpZdImWw...(no debugging symbols found)...done.
(gdb) Breakpoint 1 at 0x8048054
(gdb)
```
Note how ShellNoob automatically sets a breakpoint on the entry point!

### Get syscall numbers, constants and errno
```bash
$ snoob --get-sysnum read
i386 ~> 3
x86_64 ~> 0
$ snoob --get-sysnum fork
i386 ~> 2
x86_64 ~> 57
```
```bash
$ snoob --get-const O_RDONLY
O_RDONLY ~> 0
$ snoob --get-const O_CREAT
O_CREAT ~> 64
$ snoob --get-const EINVAL
EINVAL ~> 22
```
```bash
$ snoob --get-errno EINVAL
EINVAL ~> Invalid argument
$ snoob --get-errno 22
22 ~> Invalid argument
$ snoob --get-errno EACCES
EACCES ~> Permission denied
$ snoob --get-errno 13
13 ~> Permission denied
```

### Interactive mode
```bash
$ ./shellnoob.py -i --to-opcode
asm_to_opcode selected
>> mov %eax, %ebx
mov %eax, %ebx ~> 89c3
>> 
```
```bash
./shellnoob.py -i --to-asm
opcode_to_asm selected
>> 89c3
89c3 ~> mov %eax,%ebx
>>
```

### ShellNoob as a library
```python
$ python
>>> from shellnoob import ShellNoob
>>> sn = ShellNoob(flag_intel=True)

>>> sn.asm_to_hex('nop; mov ebx,eax; xor edx,edx')
'9089c331d2'
>>> sn.hex_to_inss('9089c331d2')
['nop', 'mov ebx,eax', 'xor edx,edx']

>>> sn.do_resolve_syscall('fork')
i386 ~> 2
x86_64 ~> 57
```

### Asm as ouput format
When "asm" is the output format, ShellNoob will try its best. Objdump is used as disassembler, but its output is not bullet-proof.
ShellNoob tries to augment the disasm by adding the bytes (.byte notation), and, when appropriate, it will display the equivalent in ASCII (.ascii notation). This is useful when you want to modify/assemble the output of objdump but you need to do a quick fix.

Example with the .byte notation:
```
jmp 0x37              # .byte 0xeb,0x35      
pop %ebx              # .byte 0x5b          
mov %ebx,%eax         # .byte 0x89,0xd8      
add $0xb,%eax         # .byte 0x83,0xc0,0x0b 
xor %ecx,%ecx         # .byte 0x31,0xc9      
```

Example with the .ascii notation:
```
das                   # .ascii "/"
je 0xac               # .ascii "tm"
jo 0x70               # .ascii "p/"
jae 0xa8              # .ascii "se"
arpl %si,0x65(%edx)   # .ascii "cre"
je 0xa0               # .ascii "tX
```

## License

ShellNoob is release under the MIT license. Check the COPYRIGHT file.
