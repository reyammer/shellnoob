#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2013 Yanick Fratantonio
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import print_function
__author__ = 'Yanick Fratantonio <yanick@cs.ucsb.edu>'
__description__ = 'Toolkit to write shellcodes'
__version__ = "2.0"

import os
import sys
import re
import stat
import traceback
import shutil
import socket
from tempfile import mktemp, NamedTemporaryFile
from subprocess import call, Popen, PIPE
import binascii
PY2 = sys.version_info.major == 2

try:
    import IPython
except ImportError:
    pass

if PY2:
    import urllib2
    input = raw_input
    cbytes = lambda source, encoding='utf-8': bytes(source)
    cstr = lambda source, encoding='utf-8': str(source)
    urlread = lambda url: urllib2.urlopen(url).read()
    HTTPError = urllib2.HTTPError
else:
    import urllib
    import urllib.request
    import urllib.error
    cbytes = lambda source, encoding='utf-8': bytes(source, encoding)
    cstr = lambda source, encoding='utf-8': str(source, encoding)
    urlread = lambda url: urllib.request.urlopen(url).read()
    HTTPError = urllib.error.HTTPError

######################
### main functions ###
######################

def print_usage():
    script_fn = os.path.basename(sys.argv[0])
    print('%s [--from-INPUT] (input_file_path | - ) [--to-OUTPUT] [output_file_path | - ]' % script_fn, file=sys.stderr)
    print('%s -c (prepend a breakpoint (Warning: only few platforms/OS are supported!)' % script_fn, file=sys.stderr)
    print('%s --64 (64 bits mode, default: 32 bits)' % script_fn, file=sys.stderr)
    print('%s --intel (intel syntax mode, default: att)' % script_fn, file=sys.stderr)
    print('%s -q (quite mode)' % script_fn, file=sys.stderr)
    print('%s -v (or -vv, -vvv)' % script_fn, file=sys.stderr)
    print('%s --to-strace (compiles it & run strace)' % script_fn, file=sys.stderr)
    print('%s --to-gdb (compiles it & run gdb & set breakpoint on entrypoint)' % script_fn, file=sys.stderr)
    print('', file=sys.stderr)
    print('Standalone "plugins"', file=sys.stderr)
    print('%s -i [--to-asm | --to-opcode ] (for interactive mode)' % script_fn, file=sys.stderr)
    print('%s --get-const <const>' % script_fn, file=sys.stderr)
    print('%s --get-sysnum <sysnum>' % script_fn, file=sys.stderr)
    print('%s --get-strerror <errno>' % script_fn, file=sys.stderr)
    print('%s --file-patch <exe_fp> <file_offset> <data> (in hex). (Warning: tested only on x86/x86_64)' % script_fn, file=sys.stderr)
    print('%s --vm-patch <exe_fp> <vm_address> <data> (in hex). (Warning: tested only on x86/x86_64)' % script_fn, file=sys.stderr)
    print('%s --fork-nopper <exe_fp> (this nops out the calls to fork(). Warning: tested only on x86/x86_64)' % script_fn, file=sys.stderr)
    print('', file=sys.stderr)
    print('"Installation"', file=sys.stderr)
    print('%s --install [--force] (this just copies the script in a convinient position)' % script_fn, file=sys.stderr)
    print('%s --uninstall [--force]' % script_fn, file=sys.stderr)
    print('', file=sys.stderr)
    print('Supported INPUT format: %s' % ', '.join(ShellNoob.INPUT_FMT), file=sys.stderr)
    print('Supported OUTPUT format: %s'  % ', '.join(ShellNoob.OUTPUT_FMT), file=sys.stderr)
    print('All combinations from INPUT to OUTPUT are supported!', file=sys.stderr)
    print('', file=sys.stderr)
    print('Check out the README file for more info.', file=sys.stderr)


class ShellNoob():

    INPUT_FMT = ['asm', 'obj', 'bin', 'hex', 'c', 'shellstorm']
    OUTPUT_FMT = ['asm', 'obj', 'exe', 'bin', 'hex', 'c', 'completec',
                  'python', 'bash', 'ruby', 'pretty', 'safeasm']

    # {kernel#hardware#flag_64_bit#flag_intel}
    objdump_options_map = {
        'Linux#i[2-6]?86#32#att' : '',
        'Linux#i[2-6]?86#32#intel' : '-m i386:intel',
        'Linux#x86_64#32#att' : '',
        'Linux#x86_64#32#intel' : '-m i386:intel',
        'Linux#x86_64#64#att' : '',
        'Linux#x86_64#64#intel' : '-m i386:x86-64:intel',
        'Linux#arm.*#32#.*' : '',
        'FreeBSD#i[2-6]?86#32#.*' : ''
    }

    # {kernel-hardware-flag_64_bit-flag_intel}
    as_options_map = {
        'Linux#i[2-6]?86#32#att' : '',
        'Linux#i[2-6]?86#32#intel' : '-msyntax=intel -mnaked-reg',
        'Linux#x86_64#32#att' : '--32',
        'Linux#x86_64#32#intel' : '--32 -msyntax=intel -mnaked-reg',
        'Linux#x86_64#64#att' : '',
        'Linux#x86_64#64#intel' : '-msyntax=intel -mnaked-reg',
        'Linux#arm.*#32#.*' : '',
        'FreeBSD#i[2-6]?86#32#.*' : ''
    }

    # {kernel-hardware-flag_64_bit-flag_intel}
    ld_options_map = {
        'Linux#i[2-6]?86#32#.*' : '',
        'Linux#x86_64#32#.*' : '-m elf_i386',
        'Linux#x86_64#64#.*' : '',
        'Linux#arm.*#32#.*' : '',
        'FreeBSD#i[2-6]?86#32#.*' : '-m elf_i386_fbsd'
    }

    # {kernel-hardware-flag_64_bit-flag_intel}
    gcc_options_map = {
        'Linux#i[2-6]?86#32#.*' : '',
        'Linux#x86_64#32#.*' : '-m32',
        'Linux#x86_64#64#.*' : '',
        'Linux#arm.*#32#.*' : '',
        'FreeBSD#i[2-6]?86#32#.*' : '-m elf_i386_fbsd'
    }

    # {kernel-hardware}
    breakpoint_hex_map = {
        '.*#i[2-6]?86' : 'cc',
        '.*#x86_64' : 'cc'
    }

    # {kernel-hardware}
    comment_as_char = {
        '.*#i[2-6]?86' : '#',
        '.*#x86_64' : '#',
        '.*#arm.*' : '@',
    }

    # [hardware]
    hw_with_align = ['arm.*']

    shellcode_t = ('.section .text\n'
                   '%s\n'
                  )

    completec_t = (
'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

%s

int main() {
    // make sure the memory is RWX to support self-modifying shellcode
    char *target = (char *) memalign(4096, 2048);
    mprotect(target, 2048, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(target, shellcode, 2048);
    (*(void (*)()) target)();
    return 0;
}
'''
)

    shellstorm_t = 'http://www.shell-storm.org/shellcode/files/shellcode-%s.php'


    def __init__(self, flag_64_bit=False, flag_intel=False, with_breakpoint=False, verbose=0, keep_files=False):
        self.shellnoob_fp = os.path.abspath(__file__)
        self.flag_64_bit = '64' if flag_64_bit else '32'
        self.flag_intel = 'intel' if flag_intel else 'att'
        self.with_breakpoint = with_breakpoint
        self.verbose = verbose
        self.debug = True if self.verbose >= 4 else False
        self.keep_files = keep_files
        self.kernel = self.get_kernel()
        self.hardware = self.get_hardware()
        self.set_conv_functions()
        self.check_compatibility()

    def set_conv_functions(self):
        for i in self.INPUT_FMT:
            for o in self.OUTPUT_FMT:
                func_name = '%s_to_%s' % (i, o)
                if self.debug: print('Creating %s' % func_name, file=sys.stderr)
                if i == o: continue

                if func_name not in ShellNoob.__dict__:
                    # conversion not implemented: let's go through hex
                    setattr(ShellNoob, func_name, self.gen_conv_function(i, o))

    def gen_conv_function(self, input_fmt, output_fmt):
        # generate on-the-fly a conversion function going through the "hex" format
        to_hex_func_name = '%s_to_hex' % input_fmt
        from_hex_func_name = 'hex_to_%s' % output_fmt
        to_hex = ShellNoob.__dict__[to_hex_func_name]
        from_hex = ShellNoob.__dict__[from_hex_func_name]

        def conv(self, input_s, with_breakpoint=False):
            _hex = to_hex(self, input_s, with_breakpoint)
            _output = from_hex(self, _hex)
            return _output

        return conv

    def check_compatibility(self):
        try:
            self.get_objdump_options()
        except ShellNoobException as e:
            print('ERROR: %s' % e.message, file=sys.stderr)
            sys.exit(2)
        try:
            self.get_as_options()
        except ShellNoobException as e:
            print('ERROR: %s' % e.message, file=sys.stderr)
            sys.exit(2)
        try:
            self.get_ld_options()
        except ShellNoobException as e:
            print('ERROR: %s' % e.message, file=sys.stderr)
            sys.exit(2)
        if self.with_breakpoint:
            try:
                self.get_breakpoint_hex()
            except ShellNoobException as e:
                print('ERROR: %s' % e.message, file=sys.stderr)
                sys.exit(2)


    def get_objdump_options(self, kernel=None, hardware=None, flag_64_bit=None, flag_intel=None):
        # use the passed settings, if specified
        kernel = kernel if kernel is not None else self.kernel
        hardware = hardware if hardware is not None else self.hardware
        flag_64_bit = flag_64_bit if flag_64_bit is not None else self.flag_64_bit
        flag_intel = flag_intel if flag_intel is not None else self.flag_intel

        for entry, options in self.objdump_options_map.items():
            e_kernel, e_hardware, e_64, e_intel = entry.split('#')
            if not re.search(e_kernel, kernel): continue
            if not re.search(e_hardware, hardware): continue
            if not re.search(e_64, flag_64_bit): continue
            if not re.search(e_intel, flag_intel): continue
            if self.debug: print('MATCH with %s ~> %s' % (entry, options), file=sys.stderr)
            return options
        raise ShellNoobException('objdump_options not found for the current setup')


    def get_as_options(self, kernel=None, hardware=None, flag_64_bit=None, flag_intel=None):
        # use the passed settings, if specified
        kernel = kernel if kernel is not None else self.kernel
        hardware = hardware if hardware is not None else self.hardware
        flag_64_bit = flag_64_bit if flag_64_bit is not None else self.flag_64_bit
        flag_intel = flag_intel if flag_intel is not None else self.flag_intel

        for entry, options in self.as_options_map.items():
            e_kernel, e_hardware, e_64, e_intel = entry.split('#')
            if not re.search(e_kernel, kernel): continue
            if not re.search(e_hardware, hardware): continue
            if not re.search(e_64, flag_64_bit): continue
            if not re.search(e_intel, flag_intel): continue
            if self.debug: print('MATCH with %s ~> %s' % (entry, options), file=sys.stderr)
            return options
        raise ShellNoobException('as_options not found for the current setup')


    def get_ld_options(self, kernel=None, hardware=None, flag_64_bit=None, flag_intel=None):
        # use the passed settings, if specified
        kernel = kernel if kernel is not None else self.kernel
        hardware = hardware if hardware is not None else self.hardware
        flag_64_bit = flag_64_bit if flag_64_bit is not None else self.flag_64_bit
        flag_intel = flag_intel if flag_intel is not None else self.flag_intel

        for entry, options in self.ld_options_map.items():
            e_kernel, e_hardware, e_64, e_intel = entry.split('#')
            if not re.search(e_kernel, kernel): continue
            if not re.search(e_hardware, hardware): continue
            if not re.search(e_64, flag_64_bit): continue
            if not re.search(e_intel, flag_intel): continue
            if self.debug: print('MATCH with %s ~> %s' % (entry, options), file=sys.stderr)
            return options
        raise ShellNoobException('ld_options not found for the current setup')


    def get_gcc_options(self, kernel=None, hardware=None, flag_64_bit=None, flag_intel=None):
        # use the passed settings, if specified
        kernel = kernel if kernel is not None else self.kernel
        hardware = hardware if hardware is not None else self.hardware
        flag_64_bit = flag_64_bit if flag_64_bit is not None else self.flag_64_bit
        flag_intel = flag_intel if flag_intel is not None else self.flag_intel

        for entry, options in self.gcc_options_map.items():
            e_kernel, e_hardware, e_64, e_intel = entry.split('#')
            if not re.search(e_kernel, kernel): continue
            if not re.search(e_hardware, hardware): continue
            if not re.search(e_64, flag_64_bit): continue
            if not re.search(e_intel, flag_intel): continue
            if self.debug: print('MATCH with %s ~> %s' % (entry, options), file=sys.stderr)
            return options
        raise ShellNoobException('gcc_options not found for the current setup')


    def get_breakpoint_hex(self, kernel=None, hardware=None):
        # use the passed settings, if specified
        kernel = kernel if kernel is not None else self.kernel
        hardware = hardware if hardware is not None else self.hardware

        for entry, _hex in self.breakpoint_hex_map.items():
            e_kernel, e_hardware = entry.split('#')
            if not re.search(e_kernel, kernel): continue
            if not re.search(e_hardware, hardware): continue
            if self.debug: print('MATCH with %s-%s ~> %s' % (e_kernel, e_hardware, _hex), file=sys.stderr)
            return _hex
        raise ShellNoobException('the breakpoint feature is not supported in the current configuration')


    def get_comment_as_char(self, kernel=None, hardware=None):
        # use the passed settings, if specified
        kernel = kernel if kernel is not None else self.kernel
        hardware = hardware if hardware is not None else self.hardware
        for entry, comment_char in self.comment_as_char.items():
            e_kernel, e_hardware = entry.split('#')
            if not re.search(e_kernel, kernel): continue
            if not re.search(e_hardware, hardware): continue
            if self.debug: print('MATCH with %s ~> %s' % (entry, comment_char), file=sys.stderr)
            return comment_char


    ######################
    # standalone plugins #
    ######################

    def do_resolve_syscall(self, syscall, kernel=None, hardware=None):
        global cstr
        kernel = kernel if kernel is not None else self.kernel
        hardware = hardware if hardware is not None else self.hardware

        if (kernel, hardware) == ('Linux', 'x86_64'):
            platforms = {'i386' : ['asm/unistd_32.h'],
                         'x86_64' : ['asm/unistd_64.h']
                        }
            symbol = '__NR_%s' % syscall
        else:
            platforms = {'i386' : ['sys/syscall.h']}
            symbol = 'SYS_%s' % syscall
        body = 'printf("%%d", %s); return 0;' % (symbol)

        for platform, includes in reversed(sorted(platforms.items())):
            try:
                tmp_exe_fp = self.include_and_body_to_exe_fp(includes, body)
            except ShellNoobException:
                print('ERROR: syscall %s not found for platform %s' % (syscall, platform), file=sys.stderr)
                continue

            p = Popen(tmp_exe_fp, stdout=PIPE)
            output, error = p.communicate()
            retval = p.returncode
            if retval == 0:
                print('%s ~> %s' % (platform, cstr(output, "utf-8")))
            else:
                print('ERROR: reval %s while resolving syscall %s' % (retval, syscall), file=sys.stderr)
            if not self.keep_files:
                os.unlink(tmp_exe_fp)


    def do_resolve_const(self, const):
        includes = ['sys/types.h',
                    'sys/stat.h',
                    'fcntl.h',
                   ]
        body = 'printf("%%d", %s); return 0;' % (const)

        try:
            tmp_exe_fp = self.include_and_body_to_exe_fp(includes, body)
        except ShellNoobException:
            print('ERROR: constant %s not found' % const, file=sys.stderr)
            return

        p = Popen(tmp_exe_fp, stdout=PIPE)
        output, error = p.communicate()
        retval = p.returncode
        if retval == 0:
            print('%s ~> %s' % (const, int(output)))
        else:
            print('ERROR: reval %s while resolving const %s' % (retval, const), file=sys.stderr)
        if not self.keep_files:
            os.unlink(tmp_exe_fp)


    def do_resolve_errno(self, errno):
        global cstr
        includes = ['string.h']

        body = 'printf("%%s", strerror(%s)); return 0;' % (errno)

        try:
            tmp_exe_fp = self.include_and_body_to_exe_fp(includes, body)
        except ShellNoobException:
            print('ERROR: errno %s not found' % const, file=sys.stderr)
            return

        p = Popen(tmp_exe_fp, stdout=PIPE)
        output, error = p.communicate()
        retval = p.returncode
        if retval == 0:
            print('%s ~> %s' % (errno, cstr(output, "utf-8")))
        else:
            print('ERROR: reval %s while resolving errno %s' % (retval, errno), file=sys.stderr)
        if not self.keep_files:
            os.unlink(tmp_exe_fp)


    def do_interactive_mode(self, args):
        global cbytes
        asm_to_opcode_flag = None
        if '--to-opcode' in args:
            asm_to_opcode_flag = True
        elif '--to-asm' in args:
            asm_to_opcode_flag = False
        if asm_to_opcode_flag is None:
            print('asm_to_opcode (1) or opcode_to_asm (2)?: ', end='')
            answer = input()
            while answer != '1' and answer != '2':
                print('seriously? dude, choose between 1 and 2: ', end='')
                answer = input()
            asm_to_opcode_flag = True if answer == '1' else False
        assert asm_to_opcode_flag is not None
        if asm_to_opcode_flag:
            print('asm_to_opcode selected (type "quit" or ^C to end)')
            ins = ''
            quit = False
            while not quit:
                while not ins:
                    print('>> ', end='')
                    ins = input().strip(' \t\n')
                    if ins.lower() == 'quit':
                        quit = True
                if quit: continue
                try:
                    _hex = self.ins_to_hex(ins)
                    print('%s ~> %s' % (ins, _hex))
                except Exception as e:
                    print('ERROR: %s' % e, file=sys.stderr)
                    if self.verbose >= 3:
                        print(traceback.format_exc(), file=sys.stderr)
                        print('--------------------------', file=sys.stderr)
                ins = ''
        else:
            print('opcode_to_asm selected (type "quit" or ^C to end)')
            _hex = ''
            quit = False
            while not quit:
                while not _hex:
                    print('>> ', end='')
                    _hex = input().strip(' \t\n')
                    if _hex.lower() == 'quit':
                        quit = True
                if quit: continue
                try:
                    _hex = _hex.replace(' ','').strip(' \t\n')
                    asm = self.hex_to_pretty(_hex)
                    print('%s ~> %s' % (cbytes(_hex), asm))
                except Exception as e:
                    print('ERROR: %s' % e, file=sys.stderr)
                    if self.verbose >= 3:
                        print(traceback.format_exc(), file=sys.stderr)
                        print('--------------------------', file=sys.stderr)
                _hex = ''


    def do_conversion(self, input_fp, output_fp, input_fmt, output_fmt):
        global cbytes
        if self.verbose >= 0:
            if input_fmt == '-':
                msg = 'Converting from stdin (%s) ' % input_fmt
            else:
                msg = 'Converting %s (%s) ' % (input_fp, input_fmt)
            if output_fp == '-':
                msg += 'to stdout (%s)' % output_fmt
            else:
                msg += 'into %s (%s)' % (output_fp, output_fmt)
            print(msg, file=sys.stderr)

        # reading the input
        if input_fp == '-':
            _input = sys.stdin.read()
        else:
            if input_fmt == 'shellstorm':
                _input = input_fp  # shellcode id
            else:
                _input = open(input_fp, 'rb').read()

        conv_func_name = '%s_to_%s' % (input_fmt, output_fmt)
        try:
            _output = getattr(self, conv_func_name)(_input)
        except AttributeError as err:
            print('ERROR: conversion mode "%s" is not supported.' % conv_func_name, file=sys.stderr)
            if self.verbose >= 3: print(traceback.format_exc(), end='')
            sys.exit(2)
        except ShellNoobException as err:
            print('%s' % err, file=sys.stderr)
            if self.verbose >= 3: print(traceback.format_exc(), end='')
            sys.exit(2)

        if not isinstance(_output, bytes):
            _output = cbytes(_output)
        # writing the output
        if output_fp == '-':
            sys.stdout.write(_output)
        else:
            open(output_fp, 'wb').write(_output)

        if output_fmt == 'exe' and output_fp != '-':
            # chmod 700
            os.chmod(output_fp, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def do_strace(self, input_fp, input_fmt):
        if self.verbose >= 3: print('IN do_strace', file=sys.stderr)

        exe_fp = mktemp()

        self.do_conversion(input_fp, exe_fp, input_fmt, 'exe')

        p = Popen('strace %s' % exe_fp, shell=True)
        p.wait()

        if not self.keep_files:
            os.unlink(exe_fp)
        if self.verbose >= 3: print('OUT do_strace', file=sys.stderr)

    def do_gdb(self, input_fp, input_fmt):
        if self.verbose >= 3: print('IN do_gdb', file=sys.stderr)

        exe_fp = mktemp()

        self.do_conversion(input_fp, exe_fp, input_fmt, 'exe')

        start_addr = None
        try:
            start_addr = self.get_start_address(exe_fp)
        except:
            print('WARNING: failed to get the start address :-(', file=sys.stderr)
            print(traceback.format_exc(), file=sys.stderr)
            print('------------------------', file=sys.stderr)

        if start_addr:
            cmd = '(echo "break *%s"; cat) | gdb -q %s' % (start_addr, exe_fp)
        else:
            cmd = 'gdb -q %s' % exe_fp
        p = Popen(cmd, shell=True)
        p.wait()

        if not self.keep_files:
            os.unlink(exe_fp)

        if self.verbose >= 3: print('OUT do_gdb', file=sys.stderr)


    #############################
    # executable patching utils #
    #############################

    def get_bits(self, exe_fp):
        bits = None
        if '32-bit' in os.popen('file %s' % exe_fp).read():
            bits = 32
        elif '64-bit' in os.popen('file %s' % exe_fp).read():
            bits = 64
        assert bits is not None
        return bits

    def get_text_section_info(self, exe_fp):
        bits = self.get_bits(exe_fp)
        vm_address, file_offset, size = None, None, None
        lines = os.popen('readelf -S %s' % exe_fp).read().split('\n')
        if bits == 32:
            for line in lines:
                m = re.search('.text\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
                if not m: continue
                vm_address = int(m.group(1), 16)
                file_offset = int(m.group(2), 16)
                size = int(m.group(3), 16)
                break
        elif bits == 64:
            for line in lines:
                if vm_address is None and file_offset is None:
                    m = re.search('.text\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
                    if not m: continue
                    vm_address = int(m.group(1), 16)
                    file_offset = int(m.group(2), 16)
                    continue
                else:
                    m = re.search('\s+([0-9a-f]+)\s+[0-9a-f]+', line)
                    if not m: raise Exception('error while parsing readelf -S (64bit)')
                    size = int(m.group(1), 16)
                    break
        else:
            raise Exception('weird number of bits')

        assert vm_address is not None and file_offset is not None and size is not None

        return vm_address, file_offset, size

    def get_file_offset_from_vm_address(self, exe_fp, vm_address):
        start_vm, start_file, size = self.get_text_section_info(exe_fp)
        assert start_vm <= vm_address <= start_vm + size
        return vm_address - start_vm + start_file

    def do_fork_nopper(self, exe_fp):
        lines = os.popen('objdump -d %s' % exe_fp).read().split('\n')
        for line in lines:
            if self.verbose >= 1:
                print(line)
            m = re.search('([0-9a-f]+):\s+[0-9a-f ]+\s+call.*fork', line)
            if not m: continue
            vm_address = int(m.group(1), 16)
            file_offset = self.get_file_offset_from_vm_address(exe_fp, vm_address)
            print('Found call to fork @ 0x%x (file offset 0x%x)' % (vm_address, file_offset))
            self.do_exe_patch(exe_fp, b'\x90\x90\x90\x31\xc0', file_offset)

    def do_exe_patch(self, exe_fp, data, file_offset=None, vm_address=None, replace=True):
        if not replace:
            raise Exception('unsupported')

        if file_offset is None and vm_address is None:
            raise Exception('you need to specify at least one of the two ;)')

        if file_offset is None:
            file_offset = self.get_file_offset_from_vm_address(exe_fp, vm_address)

        f = open(exe_fp, 'rb+')
        f.seek(file_offset)
        f.write(data)
        f.close()


    ###################
    ### conversions ###
    ###################

    def asm_to_hex(self, asm, with_breakpoint=None):
        global cstr
        if self.verbose >= 3: print('IN asm_to_hex', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint
        obj = self.asm_to_obj(asm, with_breakpoint)
        _hex = self.obj_to_hex(obj, with_breakpoint=False)

        if self.verbose >= 3: print('OUT asm_to_hex', file=sys.stderr)
        return cstr(_hex)

    def bin_to_hex(self, _bin, with_breakpoint=None):
        global cbytes
        if self.verbose >= 3: print('IN bin_to_hex', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        prepend = self.get_breakpoint_hex() if with_breakpoint else ''
        if self.verbose >= 3: print('OUT bin_to_hex', file=sys.stderr)
        return cbytes(prepend) + binascii.hexlify(_bin)

    def obj_to_hex(self, obj, with_breakpoint=None):
        if self.verbose >= 3: print('IN obj_to_hex', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        tmp_obj_f = NamedTemporaryFile(delete=False)
        tmp_obj_fp = tmp_obj_f.name
        tmp_obj_f.write(obj)
        tmp_obj_f.close()

        tmp_bin_fp = mktemp()

        cmd = 'objcopy -O binary %s %s' % (tmp_obj_fp, tmp_bin_fp)
        retval = self.exec_cmd(cmd, 'obj_to_hex')
        try:
            assert retval == 0
        except:
            raise Exception('Error while converting from obj_to_hex. Not valid ELF?')

        _bin = open(tmp_bin_fp, 'rb').read()
        _hex = self.bin_to_hex(_bin, with_breakpoint)

        if not self.keep_files:
            os.unlink(tmp_obj_fp)
            os.unlink(tmp_bin_fp)

        if self.verbose >= 3: print('OUT obj_to_hex', file=sys.stderr)
        return _hex

    def c_to_hex(self, c, with_breakpoint=None):
        if self.verbose >= 3: print('IN c_to_hex', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        print('WARNING: c_to_hex just extracts the \\xXX looking parts. Check that everything it\'s fine!', file=sys.stderr)

        def get_next_hex(buf):
            slash_x_idx = buf.find('\\x')
            if slash_x_idx == -1:
                return '', ''
            return buf[slash_x_idx+2:slash_x_idx+4], buf[slash_x_idx+4:]

        prepend = self.get_breakpoint_hex() if with_breakpoint else ''

        _hex = ''
        _next = c
        while _next:
            hex_byte, _next = get_next_hex(_next)
            _hex += hex_byte
        _hex = prepend + _hex

        if self.verbose >= 3: print('OUT c_to_hex', file=sys.stderr)
        return _hex

    def shellstorm_to_hex(self, shellstorm_id, with_breakpoint=None):
        global cstr, urlread
        if self.verbose >= 3: print('IN shellstorm_to_hex', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        print('WARNING: shellstorm_to_hex just extracts the \\xXX looking parts. Check that everything it\'s fine!', file=sys.stderr)

        shellstorm_url = self.shellstorm_t % shellstorm_id
        try:
            content = cstr(urlread(shellstorm_url))
        except HTTPError as err:
            raise ShellNoobException('ERROR: failed fetching shellcode from %s (%s)' % (shellstorm_url, err))

        # prefilter some html stuff
        after_pre_idx = content.find('<pre>') + len('<pre>')
        before_body_idx = content.find('<body>')
        content = content[after_pre_idx:before_body_idx]

        _hex = self.c_to_hex(content, with_breakpoint)

        if self.verbose >= 3: print('OUT shellstorm_to_hex', file=sys.stderr)
        return _hex



    ################
    ### hex_to_* ###
    ################

    def hex_to_asm(self, _hex, with_breakpoint=None):
        if self.verbose >= 3: print('IN hex_to_asm', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        obj = self.hex_to_obj(_hex, with_breakpoint)
        asm = self.obj_to_asm(obj, with_breakpoint=False)

        if self.verbose >= 3: print('OUT hex_to_asm', file=sys.stderr)
        return asm

    def hex_to_obj(self, _hex, with_breakpoint=None):
        if self.verbose >= 3: print('IN hex_to_obj', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if not isinstance(_hex, str):
            _hex = cstr(_hex)
        if len(_hex) != 0 and _hex.endswith('\n'):
            _hex = _hex.rstrip('\n')
            print('Warning: stripped a \'\\n\' at the end of the hex', file=sys.stderr)
        if len(_hex) == 0 or len(_hex) % 2 != 0:
            raise Exception('Not valid _hex: %s' % _hex)

        prepend = self.get_breakpoint_hex() if with_breakpoint else ''
        _hex = prepend + _hex

        asm = self.hex_to_asm_bytes(_hex)
        obj = self.asm_to_obj(asm, with_breakpoint=False)

        if self.verbose >= 3: print('OUT hex_to_obj', file=sys.stderr)
        return obj

    def hex_to_exe(self, _hex, with_breakpoint=None):
        if self.verbose >= 3: print('IN hex_to_exe', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        completec = self.hex_to_completec(_hex, with_breakpoint)
        exe = self.c_to_exe(completec, with_breakpoint=False)
        if self.verbose >= 3: print('OUT hex_to_exe', file=sys.stderr)
        return exe

    def hex_to_bin(self, _hex, with_breakpoint=None):
        global cstr
        if self.verbose >= 3: print('IN hex_to_bin', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if not isinstance(_hex, str):
            _hex = cstr(_hex)
        if len(_hex) != 0 and _hex.endswith('\n'):
            _hex = _hex.rstrip('\n')
            print('Warning: stripped a \'\\n\' at the end of the hex', file=sys.stderr)
        if len(_hex) == 0 or len(_hex) % 2 != 0:
            raise Exception('Not valid _hex: %s' % _hex)

        prepend = self.get_breakpoint_hex() if with_breakpoint else ''
        _hex = prepend + _hex

        if self.verbose >= 3: print('OUT hex_to_bin', file=sys.stderr)
        return binascii.unhexlify(_hex)

    def hex_to_c(self, _hex, with_breakpoint=None):
        if self.verbose >= 3: print('IN hex_to_c', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if not isinstance(_hex, str):
            _hex = cstr(_hex)
        if len(_hex) != 0 and _hex.endswith('\n'):
            _hex = _hex.rstrip('\n')
            print('Warning: stripped a \'\\n\' at the end of the hex', file=sys.stderr)
        if len(_hex) == 0 or len(_hex) % 2 != 0:
            raise Exception('Not valid _hex: %s' % _hex)

        prepend = self.get_breakpoint_hex() if with_breakpoint else ''
        _hex = prepend + _hex

        template = 'char shellcode[] = "%s";'
        content = ''
        for idx in range(0, len(_hex), 2):
            content += '\\x%s' % _hex[idx:idx+2]
        out = template % content
        if self.verbose >= 3: print('OUT hex_to_c', file=sys.stderr)
        return out

    def hex_to_python(self, _hex, with_breakpoint=None):
        global cstr
        if self.verbose >= 3: print('IN hex_to_python', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if not isinstance(_hex, str):
            _hex = cstr(_hex)
        if len(_hex) != 0 and _hex.endswith('\n'):
            _hex = _hex.rstrip('\n')
            print('Warning: stripped a \'\\n\' at the end of the hex', file=sys.stderr)
        if len(_hex) == 0 or len(_hex) % 2 != 0:
            raise Exception('Not valid _hex: %s' % _hex)

        prepend = self.get_breakpoint_hex() if with_breakpoint else ''
        _hex = prepend + _hex

        template = '%s'
        content = ''
        for idx in range(0, len(_hex), 2):
            content += '\\x%s' % _hex[idx:idx+2]
        out = template % content

        if self.verbose >= 3: print('OUT hex_to_python', file=sys.stderr)
        return out

    def hex_to_bash(self, _hex, with_breakpoint=None):
        if self.verbose >= 3: print('IN hex_to_bash', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        out = self.hex_to_python(_hex, with_breakpoint)

        if self.verbose >= 3: print('OUT hex_to_bash', file=sys.stderr)
        return out

    class AreYouFuckingKiddingMeException(Exception):
        pass

    def hex_to_ruby(self, _hex, with_breakpoint=None):
        if self.verbose >= 3: print('IN hex_to_ruby', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        # I'm not a ruby fan, and I really needed to put an easter egg :-)
        raise AreYouFuckingKiddingMeException()

    def hex_to_pretty(self, _hex, with_breakpoint=None):
        if self.verbose >= 3: print('IN hex_to_pretty', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        obj = self.hex_to_obj(_hex, with_breakpoint)
        exe = self.obj_to_pretty(obj, with_breakpoint=False)
        if self.verbose >= 3: print('OUT hex_to_pretty', file=sys.stderr)
        return exe

    def obj_to_pretty(self, obj, with_breakpoint=None):
        if self.verbose >= 3: print('IN obj_to_pretty', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if with_breakpoint:
            raise Exception('the with_breakpoint option is NOT supported in obj_to_exe')

        if self.need_to_align():
            _hex = self.obj_to_hex(obj)
            if self.debug: print('hex lenght: ',len(_hex), file=sys.stderr)
            aligned_hex = self.align_hex(_hex)
            if self.debug: print('aligned hex lenght: ' , len(aligned_hex), file=sys.stderr)
            if _hex != aligned_hex:
                obj = self.hex_to_obj(aligned_hex, with_breakpoint=False)

        tmp_obj_f = NamedTemporaryFile(delete=False)
        tmp_obj_fp = tmp_obj_f.name
        tmp_obj_f.write(obj)
        tmp_obj_f.close()

        tmp_pretty_fp = mktemp()

        objdump_options = self.get_objdump_options()
        cmd = 'objdump -d %s %s > %s' % (objdump_options,
                                         tmp_obj_fp,
                                         tmp_pretty_fp
                                        )
        self.exec_cmd(cmd, caller='obj_to_pretty')

        pretty = open(tmp_pretty_fp).read()

        started = False
        lines = []
        for line in pretty.split('\n'):
            if not started and 'Disassembly of section .text:' in line:
                started = True
            if not started: continue
            lines.append(line)
        pretty = '\n'.join(lines)

        if not self.keep_files:
            os.unlink(tmp_obj_fp)
            os.unlink(tmp_pretty_fp)

        if self.verbose >= 3: print('OUT obj_to_pretty', file=sys.stderr)
        return pretty


    #########################
    ### additional blocks ###
    #########################

    def asm_to_obj(self, asm, with_breakpoint=None):
        global cstr
        if self.verbose >= 3: print('IN asm_to_obj', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if isinstance(asm, bytes):
            asm = cstr(asm)
        prepend = self.hex_to_asm_bytes(self.get_breakpoint_hex()) if with_breakpoint else ''

        asm = prepend + asm + '\n'
        tmp_asm_f = NamedTemporaryFile(delete=False)
        tmp_asm_fp = tmp_asm_f.name
        tmp_asm_f.write(asm.encode("utf-8"))
        tmp_asm_f.close()

        tmp_obj_fp = mktemp()

        as_options = self.get_as_options()

        cmd = 'as %s -o %s %s' % (as_options, tmp_obj_fp, tmp_asm_fp)
        self.exec_cmd(cmd, caller='asm_to_obj')
        if not os.path.isfile(tmp_obj_fp):
            raise Exception("not valid shellcode (asm_to_obj)")

        # delete all the symbols
        cmd = 'strip %s' % tmp_obj_fp
        self.exec_cmd(cmd, caller='asm_to_obj')

        obj = open(tmp_obj_fp, 'rb').read()

        if not self.keep_files:
            os.unlink(tmp_asm_fp)
            os.unlink(tmp_obj_fp)

        if self.verbose >= 3: print('OUT asm_to_obj', file=sys.stderr)
        return obj

    def obj_to_asm(self, obj, with_breakpoint=None):
        if self.verbose >= 3: print('IN obj_to_asm', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if self.need_to_align():
            _hex = self.obj_to_hex(obj)
            aligned_hex = self.align_hex(_hex)
            if _hex != aligned_hex:
                obj = self.hex_to_obj(aligned_hex, with_breakpoint=False)

        tmp_obj_f = NamedTemporaryFile(delete=False)
        tmp_obj_fp = tmp_obj_f.name
        tmp_obj_f.write(obj)
        tmp_obj_f.close()

        objdump_options = self.get_objdump_options()
        cmd = 'objdump -d %s %s | tr -s " "' % (objdump_options,
                                    tmp_obj_fp,
                                   )
        if self.verbose >= 2: print('(obj_to_asm) Executing: %s' % cmd, file=sys.stderr)
        obj_out = os.popen(cmd).read()
        lines = obj_out.split('\n')
        started = False

        prepend = hex_to_asm_bytes(self.get_breakpoint_hex()) if with_breakpoint else ''

        out_lines = []
        max_asm_len, max_help_asm_len = 0, 0
        for line in lines:
            if not started and 'Disassembly of section .text:' in line:
                started = True
                continue
            if not started: continue

            comment_char = self.get_comment_as_char()

            # asm started
            m = re.search('[0-9a-f]+:\s+([0-9a-f ]+)\t(.*)$', line)
            if not m:
                continue
            _hex = m.group(1).replace(' ', '').strip(' \t\n')
            help_asm = self.hex_to_asm_bytes(_hex).rstrip('\n')
            try:
                _ascii = '.ascii "%s"' % _hex
                _ascii = _ascii.strip(' \t\n')
            except UnicodeDecodeError:
                _ascii = ''
            asm = m.group(2).strip(' \t\n')
            sc_idx = asm.find(';')
            if sc_idx != -1:
                asm = asm[:sc_idx]

            if len(asm) > max_asm_len:
                max_asm_len = len(asm)
            if len(help_asm) > max_help_asm_len:
                max_help_asm_len = len(help_asm)

            out_line = (asm, help_asm, _ascii)
            out_lines.append(out_line)

        out = prepend
        out_fmt = '  {:<%d}\t{:} {:<%d} {:} {:}\n' % (max_asm_len, max_help_asm_len)
        for (asm, help_asm, _ascii) in out_lines:
            out += out_fmt.format(asm, comment_char, help_asm, comment_char, _ascii)

        if not self.keep_files:
            os.unlink(tmp_obj_fp)

        shellcode = self.shellcode_t % out

        if self.verbose >= 3: print('OUT obj_to_asm', file=sys.stderr)
        return shellcode

    def asm_to_exe(self, asm, with_breakpoint=None):
        if self.verbose >= 3: print('IN asm_to_exe', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        _hex = self.asm_to_hex(asm, with_breakpoint)
        exe = self.hex_to_exe(_hex, with_breakpoint=False)

        if self.verbose >= 3: print('OUT asm_to_exe', file=sys.stderr)
        return exe

    def obj_to_exe(self, obj, with_breakpoint=None):
        if self.verbose >= 3: print('IN obj_to_exe', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if with_breakpoint:
            raise Exception('the with_breakpoint option is NOT supported in obj_to_exe')

        tmp_obj_f = NamedTemporaryFile(delete=False)
        tmp_obj_fp = tmp_obj_f.name
        tmp_obj_f.write(obj)
        tmp_obj_f.close()

        tmp_exe_fp = mktemp()

        ld_options = self.get_ld_options()

        # note: ld -V to list all the emulations
        cmd = 'ld -N %s %s -o %s' % (ld_options, tmp_obj_fp, tmp_exe_fp)
        retval = self.exec_cmd(cmd, True, caller='obj_to_exe')

        exe = open(tmp_exe_fp, 'rb').read()

        if not self.keep_files:
            os.unlink(tmp_obj_fp)
            os.unlink(tmp_exe_fp)

        if self.verbose >= 3: print('OUT obj_to_exe', file=sys.stderr)
        return exe

    def hex_to_safeasm(self, _hex, with_breakpoint=None):
        global cstr
        if self.verbose >= 3: print('IN hex_to_safeasm', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        if not isinstance(_hex, str):
            _hex = cstr(_hex)
        if len(_hex) != 0 and _hex.endswith('\n'):
            _hex = _hex.rstrip('\n')
            print('Warning: stripped a \'\\n\' at the end of the hex', file=sys.stderr)
        if len(_hex) == 0 or len(_hex) % 2 != 0:
            raise Exception('Not valid _hex: %s' % _hex)

        prepend = self.get_breakpoint_hex() if with_breakpoint else ''
        _hex = prepend + _hex

        asm = self.hex_to_asm_bytes(_hex)
        shellcode = self.shellcode_t % asm

        if self.verbose >= 3: print('OUT hex_to_safeasm', file=sys.stderr)
        return shellcode

    def hex_to_completec(self, _hex, with_breakpoint=None):
        if self.verbose >= 3: print('IN hex_to_completec', file=sys.stderr)
        with_breakpoint = with_breakpoint if with_breakpoint is not None else self.with_breakpoint

        c = self.hex_to_c(_hex, with_breakpoint)
        completec = self.completec_t % c

        if self.verbose >= 3: print('OUT hex_to_completec', file=sys.stderr)
        return completec

    def c_to_exe(self, c, with_breakpoint=None):
        global cbytes
        # NOTE assumption: the input is "compileable C"
        if self.verbose >= 3: print('IN c_to_exe', file=sys.stderr)

        if with_breakpoint:
            raise Exception('the with_breakpoint option is NOT supported in c_to_exe')

        if not isinstance(c, bytes):
            c = cbytes(c)
        tmp_c_f = NamedTemporaryFile(suffix='.c', delete=False)
        tmp_c_fp = tmp_c_f.name
        tmp_c_f.write(c)
        tmp_c_f.close()

        tmp_exe_fp = mktemp()

        gcc_options = self.get_gcc_options()
        cmd = 'gcc %s -o %s %s' % (gcc_options, tmp_exe_fp, tmp_c_fp)
        retval = self.exec_cmd(cmd, True, caller='c_to_exe')

        exe = open(tmp_exe_fp, 'rb').read()

        if not self.keep_files:
            os.unlink(tmp_c_fp)
            os.unlink(tmp_exe_fp)

        if self.verbose >= 3: print('OUT c_to_exe', file=sys.stderr)
        return exe


    ########################
    # additional functions #
    ########################

    def ins_to_hex(self, ins):
        asm = self.inss_to_asm([ins])
        _hex = self.asm_to_hex(asm)
        return _hex

    def hex_to_inss(self, _hex):
        asm = self.hex_to_asm(_hex)
        inss = asm.split('\n')[1:]
        inss = filter(lambda i:i.strip(' \t'), inss)
        inss = map(lambda i:i.split('#')[0], inss)
        inss = map(lambda i:i.strip(' \t'), inss)
        return list(inss)

    def inss_to_asm(self, inss):
        out = '\n'.join(inss)
        shellcode = self.shellcode_t % out
        return shellcode

    def asm_to_inss(self, asm):
        inss = []
        for i in asm.split('\n'):
            i = i.strip(' \t\n')
            if not i: continue
            inss.append(i)
        return inss


    ###########
    # helpers #
    ###########

    def hex_to_asm_bytes(self, _hex):
        hex_list = ['0x%s' % _hex[i:i+2] for i in range(0, len(_hex), 2)]
        asm = '.byte ' + ','.join(hex_list) + '\n'
        return asm

    def include_and_body_to_exe_fp(self, includes, body):
        global cbytes
        std_includes = set(('stdio.h', 'stdlib.h', 'errno.h'))
        includes = set(includes)
        includes.update(std_includes)

        c_prog = ''
        for inc in includes:
            c_prog += '#include<%s>\n' % inc

        c_prog += 'int main() {\n'
        c_prog += body
        c_prog += '}\n'

        tmp_c_fp = mktemp() + '.c'
        tmp_exe_fp = mktemp()

        with open(tmp_c_fp, 'wb') as f:
            f.write(cbytes(c_prog))

        cmd = 'gcc %s -o %s' % (tmp_c_fp, tmp_exe_fp)
        retval = self.exec_cmd(cmd, 'include_and_body_to_exe_fp')
        if retval != 0:
            output = ''
            raise ShellNoobException()

        if not self.keep_files:
            os.unlink(tmp_c_fp)

        return tmp_exe_fp

    def get_start_address(self, exe_fp):
        cmd = 'objdump -f %s' % exe_fp
        p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        _out, _err = p.communicate()
        assert p.returncode == 0

        _out = cstr(_out)
        for line in _out.split('\n'):
            line = line.strip(' \t\n')
            m = re.search('^start address (0x[0-9a-f]+)$', line)
            if not m: continue
            start_addr = m.group(1)
            return start_addr

        raise Exception('start address not found for %s' % exe_fp)

    def exec_cmd(self, cmd, redirect_stderr=False, caller=None):
        if self.verbose >= 2: print('(exec_cmd: "%s") Executing: "%s"' % (caller, cmd), file=sys.stderr)

        if redirect_stderr:
            with open('/dev/null', 'wb') as f:
                retval = call(cmd, stderr=f, shell=True)
        else:
            retval = call(cmd, shell=True)

        if self.verbose >= 2: print('(exec_cmd: "%s") Ret value: %s' % (caller, retval), file=sys.stderr)
        return retval

    def do_objdump_switch(self):
        # do we need to invert the bytes from objdump?
        return self.get_hardware().startswith('arm')

    def switch_bytes(self, _hex):
        # input: a hex string, like 34ab01ac

        # group them by 2 chars
        _hex = [_hex[i:i+2] for i in range(0, len(_hex), 2)]
        # reverse the list
        _hex = list(reversed(_hex))
        # build a string
        _hex = ''.join(_hex)
        return _hex

    def need_to_align(self, hardware=None):
        # use the passed settings, if specified
        hardware = hardware if hardware is not None else self.hardware
        for e_hardware in self.hw_with_align:
            if not re.search(e_hardware, hardware): continue
            if self.debug: print('MATCH with %s ~> %s' % (entry, options), file=sys.stderr)
            return True
        return False

    def align_hex(self, _hex):
        assert len(_hex) % 2 == 0
        if (len(_hex)/2) % 4 != 0:
            _hex = _hex + '00'*(4 - ((len(_hex)/2) % 4))
        assert len(_hex) % 8 == 0
        return _hex


    @staticmethod
    def get_kernel():
        return os.popen('uname -s').read().strip()

    @staticmethod
    def get_hardware():
        return os.popen('uname -m').read().strip()

    @staticmethod
    def do_install(force=False):
        if os.getuid() != 0:
            print('ERROR: I need root!', file=sys.stderr)
            sys.exit(1)
        install_dir = '/usr/local/bin'
        shellnoob_fp = os.path.join(install_dir, 'snoob')
        print('This will copy shellnoob into %s' % shellnoob_fp, file=sys.stderr)
        if not force:
            input('Press a key to proceed..')
        shutil.copyfile(__file__, shellnoob_fp)
        os.chmod(shellnoob_fp, stat.S_IRWXU | stat.S_IRWXG | stat.S_IROTH | stat.S_IXOTH)
        print('SUCCESS. "snoob -h" should display shellnoob\'s help', file=sys.stderr)

    @staticmethod
    def do_uninstall(force=False):
        if os.getuid() != 0:
            print('ERROR: I need root!', file=sys.stderr)
            sys.exit(1)
        install_dir = '/usr/local/bin'
        shellnoob_fp = os.path.join(install_dir, 'snoob')
        print('This will delete shellnoob from %s' % shellnoob_fp, file=sys.stderr)
        if not force:
            input('Press a key to proceed..')
        os.unlink(shellnoob_fp)


class ShellNoobException(Exception):
    pass

def main():

    args = sys.argv[1:]

    ########################################################################
    # WARNING  WARNING  WARNING WARNING  WARNING WARNING  WARNING  WARNING #
    # This is the most awful CLI argument parsing ever. I started to do    #
    # it manually as I wanted a uber flexible CLI interface. I'm pretty    #
    # sure it's possible to achieve the same with optparse/argparse, but   #
    # I'm too noob for that. Somebody should write a OptParseNoob tool :-) #
    ########################################################################

    # check for help
    if '-h' in args or '--help' in args or len(args) == 0:
        print_usage()
        sys.exit(0)

    # check for install/uninstall
    if '--install' in args:
        force = True if '--force' in args else False
        ShellNoob.do_install(force)
        sys.exit(0)
    elif '--uninstall' in args:
        force = True if '--force' in args else False
        ShellNoob.do_uninstall(force)
        sys.exit(0)


    # parse the switches
    flag_64_bit = False
    if '--64' in args:
        flag_64_bit = True
        args.remove('--64')
    flag_intel = False
    if '--intel' in args:
        flag_intel = True
        args.remove('--intel')
    with_breakpoint = False
    if '-c' in args:
        with_breakpoint = True
        args.remove('-c')
    keep_files = False
    if '-k' in args:
        keep_files = True
        args.remove('-k')
    verbose = 0
    if '-vvvv' in args:
        verbose = 4
        args.remove('-vvvv')
    if '-vvv' in args:
        verbose = 3
        args.remove('-vvv')
    elif '-vv' in args:
        verbose = 2
        args.remove('-vv')
    elif '-v' in args:
        verbose = 1
        args.remove('-v')
    if '-q' in args:
        verbose = -1
        args.remove('-q')

    snoob = ShellNoob(flag_64_bit=flag_64_bit, flag_intel=flag_intel,
                      with_breakpoint=with_breakpoint, verbose=verbose,
                      keep_files=keep_files
                     )

    # parse the plugin switches
    if '-i' in args:
        snoob.do_interactive_mode(args)
        sys.exit(0)
    if '--get-const' in args:
        idx = args.index('--get-const')
        const = args[idx+1]
        snoob.do_resolve_const(const)
        sys.exit(0)
    if '--get-sysnum' in args:
        idx = args.index('--get-sysnum')
        syscall = args[idx+1]
        snoob.do_resolve_syscall(syscall)
        sys.exit(0)
    if '--get-errno' in args:
        idx = args.index('--get-errno')
        errno = args[idx+1]
        snoob.do_resolve_errno(errno)
        sys.exit(0)
    do_strace_flag = False
    if '--to-strace' in args:
        do_strace_flag = True
        args.remove('--to-strace')
    do_gdb_flag = False
    if '--to-gdb' in args:
        do_gdb_flag = True
        args.remove('--to-gdb')

    if '--fork-nopper' in args:
        idx = args.index('--fork-nopper')
        exe_fp = args[idx+1]
        snoob.do_fork_nopper(exe_fp)
        sys.exit(0)
    if '--file-patch' in args:
        idx = args.index('--file-patch')
        exe_fp = args[idx+1]
        file_offset = int(args[idx+2], 16)
        data = binascii.unhexlify(args[idx+3])
        snoob.do_exe_patch(exe_fp, data, file_offset=file_offset)
        sys.exit(0)
    if '--vm-patch' in args:
        idx = args.index('--vm-patch')
        exe_fp = args[idx+1]
        vm_address = int(args[idx+2], 16)
        data = binascii.unhexlify(args[idx+3])
        snoob.do_exe_patch(exe_fp, data, vm_address=vm_address)
        sys.exit(0)

    # parse the conversion arguments

    curr_arg_idx = 0

    # determine the input format
    input_fmt = None
    curr_arg = args[curr_arg_idx]
    if curr_arg.startswith('--from-'):
        input_fmt = curr_arg[len('--from-'):].lower()
        if input_fmt not in snoob.INPUT_FMT:
            raise Exception('input format "%s" not supported' % input_fmt)
        curr_arg_idx += 1

    input_fp = args[curr_arg_idx]
    if input_fmt != 'shellstorm' and input_fp != '-':
        input_fp = os.path.abspath(input_fp)
        if not os.path.isfile(input_fp):
            raise Exception('file %s does NOT exist' % input_fp)
    curr_arg_idx += 1

    if not input_fmt:
        # ok, let's guess the input fmt
        dot_idx = input_fp.rfind('.')
        if dot_idx == -1:
            raise Exception('Failed to guess the input format :/')
        ext = input_fp[dot_idx+1:]
        if ext in ['asm', 's', 'S', 'shell']:
            input_fmt = 'asm'
        elif ext in ['o', 'obj']:
            input_fmt = 'obj'
        elif ext in ['bin']:
            input_fmt = 'bin'
        elif ext in ['hex']:
            input_fmt = 'hex'
        elif ext in ['c', 'C']:
            input_fmt = 'c'
        else:
            raise Exception('Input format "%s" is not supported' % input_fmt)


    if do_strace_flag:
        if snoob.verbose >= 1: print('do_strace mode selected', file=sys.stderr)
        snoob.do_strace(input_fp, input_fmt)
        sys.exit(0)
    if do_gdb_flag:
        if snoob.verbose >= 1: print('do_gdb mode selected', file=sys.stderr)
        snoob.do_gdb(input_fp, input_fmt)
        sys.exit(0)


    output_fmt = None
    curr_arg = args[curr_arg_idx]
    if curr_arg.startswith('--to-'):
        output_fmt = curr_arg[len('--to-'):].lower()
        if output_fmt not in snoob.OUTPUT_FMT:
            raise Exception('output format "%s" not supported' % output_fmt)
        curr_arg_idx += 1

    output_fp = None
    if curr_arg_idx < len(args):
        output_fp = args[curr_arg_idx]
        curr_arg_idx += 1

    if not output_fmt:
        # ok, let's guess the output fmt
        dot_idx = output_fp.rfind('.')
        if dot_idx == -1:
            raise Exception('Failed to guess the output format :/')
        ext = output_fp[dot_idx+1:]
        if ext in ['asm', 's', 'S', 'shell']:
            output_fmt = 'asm'
        elif ext in ['o', 'obj']:
            output_fmt = 'obj'
        elif ext in ['exe']:
            output_fmt = 'exe'
        elif ext in ['bin']:
            output_fmt = 'bin'
        elif ext in ['hex']:
            output_fmt = 'hex'
        elif ext in ['c', 'C']:
            output_fmt = 'c'
        elif ext in ['py', 'python']:
            output_fmt = 'python'
        elif ext in ['sh', 'bash']:
            output_fmt = 'bash'
        elif ext in ['rb', 'ruby']:
            output_fmt = 'ruby'
        elif ext in ['pretty']:
            output_fmt = 'pretty'
        elif ext in ['safeasm']:
            output_fmt = 'safeasm'
        else:
            raise Exception('Output format "%s" is not supported' % output_fmt)

    if output_fp == '-':
        pass
    elif output_fp != None:
        output_fp = os.path.abspath(output_fp)
    elif input_fp and input_fp != '-':
        # choose the output_fp starting from the input_fp and input_fmt
        input_pfx = input_fp[:input_fp.rfind('.')]
        if output_fmt == 'completec':
            output_ext = 'c'
        else:
            output_ext = output_fmt
        output_fp = '%s.%s' % (input_pfx, output_ext)
    else:
        raise Exception('Specify the input/output filename!')

    snoob.do_conversion(input_fp, output_fp, input_fmt, output_fmt)


if __name__== '__main__':
    main()
