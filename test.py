#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import shutil
import re
import traceback
from os.path import dirname, join
from hashlib import md5
from tempfile import mkdtemp
from subprocess import Popen, PIPE
try:
    import IPython
except ImportError:
    pass

from shellnoob import ShellNoob, cstr, cbytes

GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'

SHELLNOOB_FP = os.path.join(os.path.dirname(__file__), 'shellnoob.py')
SECRET_STR = 'thesecretisthedolphin'

# expcted values for the different tests / architecture-OS

# test functions

supported_features = {
    # TODO use regex!
    'Linux#i686' : {
        'test_resolve_const' : [
            (['O_RDONLY'], ('^O_RDONLY ~> 0\n$', '', 0)),
            (['O_RDWR'], ('^O_RDWR ~> 2\n$', '', 0)),
        ],
        'test_resolve_syscall' : [
            (['read'], ('^i386 ~> 3\n$', '', 0)),
            (['write'], ('^i386 ~> 4\n$', '', 0)),
        ],
        'test_conversion' : [
            ([True], ('^$', '^$', 0)),
        ],
        'test_interactive' : [
            (['1\nmov %ebx,%eax\nnop\nquit\n',''], ('[^\n]+~> 89d8\n[^\n]+~> 90', '', 0)),
            (['1\nmov eax,ebx\nnop\nquit\n','--intel'], ('[^\n]+~> 89d8\n[^\n]+~> 90', '', 0)),
            (['2\n89d890\nquit\n',''], ('0:.*mov\s+%ebx,%eax\n\s+2:.*nop\n', '', 0)),
            (['2\n89d890\nquit\n','--intel'], ('0:.*mov\s+eax,ebx\n\s+2:.*nop\n', '', 0)),
        ],
        'test_get_start_address' : [
            ([], ('^$', '^$', 0)),
        ],
    },
    'Linux#x86_64' : {
        'test_resolve_const' : [
            (['O_RDONLY'], ('^O_RDONLY ~> 0\n$', '', 0)),
            (['O_RDWR'], ('^O_RDWR ~> 2\n$', '', 0)),
        ],
        'test_resolve_syscall' : [
            (['read'], ('^x86_64 ~> 0\ni386 ~> 3\n$', '', 0)),
            (['write'], ('^x86_64 ~> 1\ni386 ~> 4\n$', '', 0)),
        ],
        'test_conversion' : [
            ([True], ('^$', '^$', 0)),
        ],
        'test_interactive' : [
            (['1\nmov %ebx,%eax\nnop\nquit\n',''], ('[^\n]+~> 89d8\n[^\n]+~> 90', '', 0)),
            (['1\nmov eax,ebx\nnop\nquit\n','--intel'], ('[^\n]+~> 89d8\n[^\n]+~> 90', '', 0)),
            (['1\nmov %rbx,%rax\nnop\nquit\n','--64'], ('[^\n]+~> 4889d8\n[^\n]+~> 90', '', 0)),
            (['1\nmov rax,rbx\nnop\nquit\n','--intel --64'], ('[^\n]+~> 4889d8\n[^\n]+~> 90', '', 0)),
            (['2\n89d890\nquit\n',''], ('0:.*mov\s+%ebx,%eax\n\s+2:.*nop\n', '', 0)),
            (['2\n89d890\nquit\n','--intel'], ('0:.*mov\s+eax,ebx\n\s+2:.*nop\n', '', 0)),
            (['2\n4889d890\nquit\n','--64'], ('0:.*mov\s+%rbx,%rax\n\s+3:.*nop\n', '', 0)),
            (['2\n4889d890\nquit\n','--intel --64'], ('0:.*mov\s+rax,rbx\n\s+3:.*nop\n', '', 0)),
        ],
        'test_get_start_address' : [
            ([], ('^$', '^$', 0)),
        ],
    },
    'Linux#armv5tejl' : {
        'test_resolve_const' : [
            (['O_RDONLY'], ('^O_RDONLY ~> 0\n$', '', 0)),
            (['O_RDWR'], ('^O_RDWR ~> 2\n$', '', 0)),
        ],
    },
}

def test_resolve_const(const):
    stdout, stderr, retval = run_with_args('--get-const %s' % const)
    return stdout, stderr, retval

def test_resolve_syscall(syscall):
    stdout, stderr, retval = run_with_args('--get-sysnum %s' % syscall)
    return stdout, stderr, retval

def test_conversion(with_breakpoint=False):

    stdout, stderr = '', ''

    tmp_dir = mkdtemp()
    asm_fp = join(tmp_dir, 'shellcode.asm')
    asm2_fp = join(tmp_dir, 'shellcode2.asm')
    obj_fp = join(tmp_dir, 'shellcode.obj')
    exe_fp = join(tmp_dir, 'shellcode.exe')
    bin_fp = join(tmp_dir, 'shellcode.bin')
    bin2_fp = join(tmp_dir, 'shellcode2.bin')
    hex_fp = join(tmp_dir, 'shellcode.hex')
    c_fp = join(tmp_dir, 'shellcode.c')
    python_fp = join(tmp_dir, 'shellcode.py')
    bash_fp = join(tmp_dir, 'shellcode.sh')
    pretty_fp = join(tmp_dir, 'shellcode.pretty')
    safeasm_fp = join(tmp_dir, 'shellcode.safeasm')

    secret_fp = '/tmp/secret'
    os.system('echo "%s" > %s' % (SECRET_STR, secret_fp))

    kernel = ShellNoob.get_kernel()
    if kernel == 'Linux':
        shutil.copyfile(join(dirname(__file__), 'samples/x86-linux/open-read-write.asm'), asm_fp)
    elif kernel == 'FreeBSD':
        shutil.copyfile(join(dirname(__file__), 'samples/x86-freebsd/open-read-write.asm'), asm_fp)
    else:
        raise Exception('testing on kernel %s not supported' % kernel)

    _out, _err, _val = run_with_args('%s --to-bin' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-hex' % bin_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-obj' % hex_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-hex' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-bin %s' % (hex_fp, bin2_fp))
    stdout += _out; stderr += _err; assert _val == 0;

    assert (md5(open(bin_fp,'rb').read()).hexdigest() ==
            md5(open(bin2_fp,'rb').read()).hexdigest())

    _out, _err, _val = run_with_args('%s --to-obj' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-exe' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-bin' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-hex' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-c' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-python' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-bash' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-pretty' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-safeasm' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;

    _out, _err, _val = run_with_args('%s --to-asm %s' % (obj_fp, asm2_fp))
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-exe' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-bin' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-hex' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-c' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-python' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-bash' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-pretty' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('%s --to-safeasm' % obj_fp)
    stdout += _out; stderr += _err; assert _val == 0;

    _out, _err, _val = run_with_args('-c %s --to-obj' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('-c %s --to-exe' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('-c %s --to-bin' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('-c %s --to-hex' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('-c %s --to-c' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('-c %s --to-python' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('-c %s --to-bash' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('-c %s --to-pretty' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;
    _out, _err, _val = run_with_args('-c %s --to-safeasm' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;

    # TODO add "chain" tests

    _out, _err, _val = run_with_args('%s --to-exe' % asm_fp)
    assert os.popen(exe_fp).read().rstrip() == SECRET_STR
    print('Output of the shellcode matches!')

    shutil.rmtree(tmp_dir)
    os.unlink(secret_fp)
    return stdout.strip(), stderr, 0


def test_get_start_address():
    stdout, stderr = '', ''

    tmp_dir = mkdtemp()
    asm_fp = join(tmp_dir, 'shellcode.asm')
    exe_fp = join(tmp_dir, 'shellcode.exe')

    secret_fp = '/tmp/secret'
    os.system('echo "%s" > %s' % (SECRET_STR, secret_fp))

    kernel = ShellNoob.get_kernel()
    if kernel == 'Linux':
        shutil.copyfile(join(dirname(__file__), 'samples/x86-linux/open-read-write.asm'), asm_fp)
    elif kernel == 'FreeBSD':
        shutil.copyfile(join(dirname(__file__), 'samples/x86-freebsd/open-read-write.asm'), asm_fp)
    else:
        raise Exception('testing on kernel %s not supported' % kernel)

    _out, _err, _val = run_with_args('%s --to-exe' % asm_fp)
    stdout += _out; stderr += _err; assert _val == 0;

    snoob = ShellNoob()
    start_addr = snoob.get_start_address(exe_fp)
    assert re.match('0x[0-9a-f]+', start_addr)

    shutil.rmtree(tmp_dir)
    os.unlink(secret_fp)
    return stdout, stderr, 0


def test_interactive(_input, args):
    stdout, stderr = '', ''
    _out, _err, _val = run_with_args_input(_input, args + ' -i')
    stdout += _out; stderr += _err; assert _val == 0;

    return stdout, stderr, 0


def run_with_args_input(_input='', args=''):
    args += ' -q'
    cmd = '%s %s' % (SHELLNOOB_FP, args)
    print('Launching: %s (with input)' % (cmd))
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate(input=cbytes(_input))
    retval = p.returncode

    return cstr(stdout), cstr(stderr), int(retval)


def run_with_args(args=''):
    args += ' -q'
    cmd = '%s %s' % (SHELLNOOB_FP, args)
    print('Launching: %s' % cmd)
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate(input='')
    retval = p.returncode

    return cstr(stdout), cstr(stderr), int(retval)

def run_all_tests():
    kernel, hardware = ShellNoob.get_kernel(), ShellNoob.get_hardware()
    entry = '%s#%s' % (kernel, hardware)

    tot_test = 0
    ok_test = 0

    try:
        tests = supported_features[entry]
    except KeyError:
        print('ERROR: No tests for this setup "%s"' % entry)
        sys.exit(1)
    for test_name, entries in tests.items():
        for e in entries:
            tot_test += 1
            _input, expected = e
            print('Running test %s - %s - %s' % (test_name, _input, str(expected)))
            e_stdout, e_stderr, e_retval = expected
            try:
                stdout, stderr, retval = globals()[test_name](*_input)
                if not re.search(e_stdout, stdout):
                    print(RED + 'ERROR STDOUT %s != %s (expected)' % (stdout, e_stdout) + ENDC)
                    continue
                if not re.search(e_stderr, stderr):
                    print(RED + 'ERROR STDERR?g %s != %s (expected)' % (stderr, e_stderr) + ENDC)
                    continue
                if retval != e_retval:
                    print(RED + 'ERROR RETVAL %s != %s (expected)' % (retval, e_retval) + ENDC)
                    continue
                print(GREEN + 'OK' + ENDC)
                ok_test += 1
            except Exception as e:
                print(RED + 'ERROR Exception while executing %s' % test_name + ENDC)
                print(traceback.format_exc())
                print('---------------------------')

    if ok_test == tot_test:
        print(GREEN + '%s/%s OK' % (ok_test, tot_test) + ENDC)
    else:
        print(RED + '%s/%s ERROR' % (ok_test, tot_test) + ENDC)



def main():
    args = sys.argv

    if '-t' in args:
        t_idx = args.index('-t')
        test_name = args[t_idx+1]
        try:
            globals()[test_name]()
        except Exception as e:
            print('ERROR EXCEPTION while running test %s' % test_name)
            print(traceback.format_exc())
        sys.exit(0)

    run_all_tests()

if __name__== '__main__':
    main()
