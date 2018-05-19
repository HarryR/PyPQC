
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/rand.h>

#include "rng.h"
#include "api.h"


/*
 * This CLI program can be used to perform operations
 *
 * e.g.
 *
 *  pqc_cli <operation> [arg [arg ...]]
 * 	pqc_cli kem-enc <secret-key> <public-key> <session-key>
 *
 * Operations:
 *
 *  kem-keygen - create random public / secret key components
 *               (pk,sk) <- KEM.KeyGen()
 *    e.g.   pqc_cli kem-keygen
 *            
 *  kem-enc    - encrypt key for public key holder  
 *               (ct, ss) <- KEM.Encaps(pk)
 *    e.g.   pqc_cli kem-enc <pk>
 *
 *  kem-dec    - decrypt encapsulated ciphertext
 *               ss <- KEM.Decaps(ct,sk) 
 *    e.g.   pqc_cli kem-dec <ct> <sk>
 */


struct hexarg_s {
    const char *name;
    size_t len;
    unsigned char *out;
};

typedef struct hexarg_s hexarg_t;


static int hex2bin( const char *ptr, unsigned char *output_arg )
{
    int idx = 0;
    char buf[3];
    buf[2] = '\0';

    while ( *ptr )
    {
        if ( ptr[1] == '\0' || ! isxdigit(ptr[0]) || ! isxdigit(ptr[1]) )
        {
            return 0;
        }

        buf[0] = *ptr++;
        buf[1] = *ptr++;

        output_arg[idx] = (unsigned char)strtoul(buf, NULL, 16);
        idx++;
    }

    return 1;
}


static int parse_arg( hexarg_t *arg_spec, const char *arg )
{
    if( strlen(arg) != (arg_spec->len / 2) )
    {
        fprintf(stderr, "Error: arg '%s' expected %lu bytes (hex encoded), got %.1f bytes\n",
                arg_spec->name, arg_spec->len, strlen(arg) / 2.0);
        return 0;
    }

    if( ! hex2bin(arg, arg_spec->out) )
    {
        fprintf(stderr, "Error: parsing arg '%s', hex encoded?\n", arg_spec->name);
        return 0;
    }

    return 1;
}


static int parse_args( int argc, char **argv, int num, hexarg_t *arg_spec )
{
    int n;

    if( argc < num )
    {
        fprintf(stderr, "Error: %d args required, %d provided\n", num, argc);
        
        for( n = 0; n < num; n++ )
        {
            hexarg_t *arg = &arg_spec[n];

            fprintf(stderr, "  arg %d - '%s' - %lu bytes (hex encoded)\n",
                    n, arg->name, arg->len);
        }

        exit(1);
    }

    for( n = 0; n < num; n++ )
    {
        hexarg_t *arg = &arg_spec[n];

        if( ! parse_arg(arg, argv[n]) )
        {
            return 0;
        }
    }

    return 1;
}


void print_hex (unsigned char *data, size_t n)
{
    size_t i;

    for( i = 0; i < n; i++ )
    {
        printf("%02X", (unsigned)data[i] & 0xFF);
    }  
}


int main( int argc, char **argv )
{
    int ret_val;
    unsigned char       seed[48];

    if( argc < 2 ) {
        fprintf(stderr, "Usage: %s <operation> [arg [arg ...]]\n", argv[0]);
        exit(1);
    }

    RAND_bytes(seed, sizeof(seed));
    randombytes_init(seed, NULL, 256);

    if( 0 == strcmp(argv[1], "kem-gen") )
    {
        unsigned char out_pk[CRYPTO_PUBLICKEYBYTES];
        unsigned char out_sk[CRYPTO_SECRETKEYBYTES];

        if ( (ret_val = crypto_kem_keypair(out_pk, out_sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            exit(6);
        }

        printf("PK=");
        print_hex(out_pk, sizeof(out_pk));
        printf("\n");

        printf("SK=");
        print_hex(out_sk, sizeof(out_sk));
        printf("\n");
    }
    else if( 0 == strcmp(argv[1], "kem-enc") )
    {
        unsigned char arg_pk[CRYPTO_PUBLICKEYBYTES];
        unsigned char out_ct[CRYPTO_CIPHERTEXTBYTES];
        unsigned char out_ss[CRYPTO_BYTES];

        hexarg_t arg_spec[] = {
            {"pk", sizeof(arg_pk), arg_pk}
        };

        if( ! parse_args(argc-2, &argv[2], 1, arg_spec) )
        {
            exit(4);
        }

        if ( (ret_val = crypto_kem_enc(out_ct, out_ss, arg_pk)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            exit(5);
        }

        printf("CT=");
        print_hex(out_ct, sizeof(out_ct));
        printf("\n");

        printf("SS=");
        print_hex(out_ss, sizeof(out_ss));
        printf("\n");
    }
    else if( 0 == strcmp(argv[1], "kem-dec") )
    {
        unsigned char arg_ct[CRYPTO_CIPHERTEXTBYTES];
        unsigned char arg_sk[CRYPTO_SECRETKEYBYTES];
        unsigned char out_ss[CRYPTO_BYTES];

        hexarg_t arg_spec[] = {
            {"ct", sizeof(arg_ct), arg_ct},
            {"sk", sizeof(arg_sk), arg_sk},
        };

        if( ! parse_args(argc-2, &argv[2], 2, arg_spec) )
        {
            exit(3);
        }

        if ( (ret_val = crypto_kem_dec(out_ss, arg_ct, arg_sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            exit(7);
        }

        printf("SS=");
        print_hex(out_ss, sizeof(out_ss));
        printf("\n");
    }
    else
    {
        fprintf(stderr, "Error: Unknown operation '%s'\n", argv[1]);
        exit(2);
    }

    return 0;
}
