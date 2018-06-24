#!/usr/bin/env python
from __future__ import print_function
import os
import sys
import time
import shlex
import subprocess
from binascii import unhexlify, hexlify


def timeit(func, *args, **kwa):
    begin = time.time()
    result = func(*args, **kwa)
    end = time.time()
    return end-begin, result


class PQCError(Exception):
    pass


def _decode_line(line, hexdecode=True):
    pair = line.decode('utf-8').split('=')
    if hexdecode:
        return pair[0], unhexlify(pair[1])
    return pair[0], pair[1]


def pqc_cli_api(cli_path, subcmd, *args, **kwa):
    hex_args = [hexlify(_) for _ in args]
    cmdline = [cli_path, subcmd] + hex_args
    process = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = process.communicate()[0]
    if process.returncode != 0:
        raise PQCError("Status code %d for command: %s" % (process.returncode, cmdline))
    return dict([_decode_line(_, **kwa) for _ in stdout.splitlines()])


class PQCBase(object):
    def __init__(self, cli_path):
        self._cli_path = cli_path
        if not os.path.exists(cli_path):
            raise RuntimeError("PQC CLI executable doesn't exist: %s" % (cli_path,))
        self._params = self.api('params', hexdecode=False)

    @property
    def params(self):
        return self._params

    def api(self, cmd, *args, **kwa):
        return pqc_cli_api(self._cli_path, cmd, *args, **kwa)


class PQCKEM(PQCBase):
    def __init__(self, cli_path):
        super(PQCKEM, self).__init__(cli_path)

    def keypair(self):
        res = self.api('kem-gen')
        return res['PK'], res['SK']

    def encaps(self, pk):
        res = self.api('kem-enc', pk)
        return res['CT'], res['SS']

    def decaps(self, ct, sk):
        return self.api('kem-dec', ct, sk)['SS']


class PQCSign(PQCBase):
    def __init__(self, cli_path):
        super(PQCSign, self).__init__(cli_path)

    def keypair(self):
        res = self.api('sign-gen')
        return res['PK'], res['SK']

    def sign(self, sk, message):
        return self.api('sign', sk, message)['SM']

    def open(self, pk, signed_message):
        return self.api('sign-open', pk, signed_message)['M']


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == 'test':
        from pqcalgos import PQC_KEM_PATHS, PQC_SIGN_PATHS

        for kem_path in PQC_KEM_PATHS:
            print("Testing KEM", kem_path)
            x = PQCKEM(kem_path)
            duration, (pk, sk) = timeit(x.keypair)
            print(" - keypair: %.2fs pk=%d sk=%d" % (duration, len(pk), len(sk)))
            duration, (ct, ss) = timeit(x.encaps, pk)
            print(" - encaps: %.2fs ct=%d ss=%d" % (duration, len(ct), len(ss)))
            duration, check_ss = timeit(x.decaps, ct, sk)
            print(" - decaps: %.2fs ss=%d" % (duration, len(check_ss)))
            assert ss == check_ss

        for sign_path in PQC_SIGN_PATHS:
            print("Testing SIGN", sign_path)
            x = PQCSign(sign_path)
            duration, (pk, sk) = timeit(x.keypair)
            print(" - keypair: %.2fs pk=%d sk=%d" % (duration, len(pk), len(sk)))
            msg = os.urandom(128)
            duration, smsg = timeit(x.sign, sk, msg)
            print(" - sign: %.2fs msgs=%d" % (duration, len(smsg)))
            duration, cmsg = timeit(x.open, pk, smsg)
            print(" - open: %.2fs cmsg=%d" % (duration, len(cmsg)))
            assert msg == cmsg

        sys.exit(0)

    if len(sys.argv) < 3:
        print("Usage: %s <./path/to/pqc_cli> cmd [arg [arg ...]]" % (sys.argv[0],))
        print(" or, to test: %s test" % (sys.argv[0],))
        sys.exit(1)

    hexdecode = sys.argv[2] != 'params'
    print("Hex", hexdecode)
    res = pqc_cli_api(sys.argv[1], sys.argv[2], *sys.argv[3:], hexdecode=hexdecode)

    for k, v in res.items():
        if not hexdecode:
            print(k, '=', v)
        else:
            print(k, '=', hexlify(v))
