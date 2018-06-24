from __future__ import print_function
import sys


PQC_KEM_PATHS = [
    './NTRU-HRSS-KEM-20171130/Optimized_Implementation/crypto_kem/ntruhrss701/pqc_cli',
    './SIKE/Optimized_Implementation/portable/SIKEp503/pqc_cli'
]

PQC_SIGN_PATHS = [
    './sphincs+-reference-implementation-20180313/crypto_sign/sphincs-haraka-128s/pqc_cli'
]


if __name__ == "__main__":
    args = sys.argv[1:]
    if not len(args):
        args = ['all']
    pqc_type = args[0]
    pqc_paths = []
    if pqc_type == 'kem':
        pqc_paths = PQC_KEM_PATHS
    elif pqc_type == 'sign':
        pqc_paths = PQC_SIGN_PATHS
    elif pqc_type == 'all':
        pqc_paths = PQC_KEM_PATHS + PQC_SIGN_PATHS
    else:
        print("ERROR: unknown type %s" % (pqc_type,), file=sys.stderr)
        sys.exit(1)
    print('\n'.join(pqc_paths))
    sys.exit(0)
