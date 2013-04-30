#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shutil
from os.path import dirname, join
from hashlib import md5
from tempfile import mkdtemp
try:
    import IPython
except ImportError:
    pass

SHELLNOOB_FP = os.path.join(os.path.dirname(__file__), 'shellnoob.py')
SECRET_STR = 'thesecretisthedolphin'

def run(args):
    cmd = '%s %s' % (SHELLNOOB_FP, args)
    print 'Running: %s' % cmd
    os.system(cmd)

def test():
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

    os.system('echo "%s" > /tmp/secret' % SECRET_STR)
    shutil.copyfile(join(dirname(__file__), 'samples/x86-linux/open-read-write.asm'), asm_fp)

    run('%s --to-bin' % asm_fp)
    run('%s --to-hex' % bin_fp)
    run('%s --to-obj' % hex_fp)
    run('%s --to-hex' % obj_fp)
    run('%s --to-bin %s' % (hex_fp, bin2_fp))

    assert (md5(open(bin_fp,'rb').read()).hexdigest() ==
            md5(open(bin2_fp,'rb').read()).hexdigest())

    run('%s --to-obj' % asm_fp)
    run('%s --to-exe' % asm_fp)
    run('%s --to-bin' % asm_fp)
    run('%s --to-hex' % asm_fp)
    run('%s --to-c' % asm_fp)
    run('%s --to-python' % asm_fp)
    run('%s --to-bash' % asm_fp)
    run('%s --to-pretty' % asm_fp)

    run('%s --to-asm %s' % (obj_fp, asm2_fp))
    run('%s --to-exe' % obj_fp)
    run('%s --to-bin' % obj_fp)
    run('%s --to-hex' % obj_fp)
    run('%s --to-c' % obj_fp)
    run('%s --to-python' % obj_fp)
    run('%s --to-bash' % obj_fp)
    run('%s --to-pretty' % obj_fp)

    run('-c %s --to-obj' % asm_fp)
    run('-c %s --to-exe' % asm_fp)
    run('-c %s --to-bin' % asm_fp)
    run('-c %s --to-hex' % asm_fp)
    run('-c %s --to-c' % asm_fp)
    run('-c %s --to-python' % asm_fp)
    run('-c %s --to-bash' % asm_fp)
    run('-c %s --to-pretty' % asm_fp)

    run('%s --to-exe' % asm_fp)
    assert os.popen(exe_fp).read().rstrip() == SECRET_STR
    print 'Output of the shellcode matches!'

    shutil.rmtree(tmp_dir)

def main():
    test()

if __name__== '__main__':
    main()
