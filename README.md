# ShellNoob

Writing shellcodes has always been super fun, but some parts are extremely
boring and error prone. Focus only on the fun part, and use *ShellNoob*! 

## News
ShellNoob got accepted at Black Hat Arsenal! See announcement here: [link](http://www.blackhat.com/us-13/arsenal.html#Fratantonio).

The new (updated) version will be publicly released during Black Hat Briefings.

## Features

- convert shellcode between different formats (currently supported: asm, bin, hex, obj, exe, C, python, ruby, pretty)
- interactive opcode-to-binary conversion (and viceversa) mode. This is useful when you cannot use specific bytes in the shellcode.
- resolve syscall numbers and constants (not exactly implemented yet :-))
- portable and easily deployable (it only relies on gcc/as/objdump and 
  python). And it just one python file!
- in-place development: you run ShellNoob directly on the target architecture!
- other options: prepend breakpoint, 32bit/64bit switch.
- read from stdin / write to stdout support (use "-" as filename)

## Use Cases

### Built-in help
```bash
$ ./shellnoob.py -h
./shellnoob.py [--from-INPUT] (input_file_path | - ) [--to-OUTPUT] [output_file_path | - ]
./shellnoob.py -i (for interactive mode)
./shellnoob.py -c (insert a breakpoint at the beginning of the shellcode)
./shellnoob.py --64 (64bits mode)
./shellnoob.py --get-const <const>
./shellnoob.py --get-sysnum <sysnum>

supported INPUT format: asm, obj, bin, hex
supported OUTPUT format: asm, obj, exe, bin, hex, C, python, bash, ruby, pretty
```

### Convert a shellcode written in assembly (shellcode.asm) to binary format.
```bash
./shellnoob.py --from-asm shellcode.asm --to-bin shellcode.bin
```

Some alternatives (the tool will try to guess what you want given the file extension..)
```bash
$ ./shellnoob.py --from-asm shellcode.asm --to-bin
$ ./shellnoob.py shellcode.asm --to-bin
$ ./shellnoob.py shellcode.asm --to-bin - > shellcode.bin
$ cat shellcode.asm | ./shellnoob.py --from-asm - --to-bin - > shellcode.bin
```

### Test the shellcode with gdb
```bash
$ ./shellnoob.py -c shellcode.asm --to-exe shellcode
$ gdb -q shellcode
$ run
Reading symbols from ./shellcode...(no debugging symbols found)...done.
(gdb) run
Starting program: ./shellcode

Program received signal SIGTRAP, Trace/breakpoint trap.
0x08048055 in ?? ()
(gdb) 
```

### Get syscall numbers and constants (_partially_ supported :-))
```bash
$ ./shellnoob.py --get-sysnum read
Value: 3
```
```bash
./shellnoob.py --get-const O_RDONLY
Value: 0
```

### Interactive mode session!
```bash
$ ./shellnoob.py -i
ins_to_opcode (1) or opcode_to_ins (2)?: 1
ins_to_opcode selected
>> mov %eax, %ebx
mov %eax, %ebx ~> 89c3
>> 
```
```bash
./shellnoob.py -i
ins_to_opcode (1) or opcode_to_ins (2)?: 2
opcode_to_ins selected
>> 89c3
89c3 ~> mov %eax,%ebx
>>
```

## TODO
- proper implementation of --get-sysnum and --get-const :-)
- use readline to save the history (in interactive mode)
- test on the different platforms
