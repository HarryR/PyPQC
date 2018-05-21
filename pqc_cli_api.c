
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

typedef int (*cmd_fn_t)( int argc, char **argv );

typedef struct {
    const char *name;
    cmd_fn_t cmd;
} cmd_t;


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
    size_t arg_len = strlen(arg);
    int do_free = 0;

    if( arg_spec->len == 0 )
    {
        arg_spec->len = arg_len / 2;
        do_free = 1;
        arg_spec->out = malloc(arg_spec->len);
    }

    if( (arg_len / 2) != arg_spec->len )
    {
        fprintf(stderr, "Error: arg '%s' expected %lu bytes (hex encoded), got %.1f bytes\n",
                arg_spec->name, arg_spec->len, arg_len / 2.0);
        
        if( do_free )
        {
            free(arg_spec->out);
            arg_spec->out = 0;
        }

        return 0;
    }

    if( ! hex2bin(arg, arg_spec->out) )
    {
        fprintf(stderr, "Error: parsing arg '%s', hex encoded?\n", arg_spec->name);
        
        if( do_free )
        {
            free(arg_spec->out);
            arg_spec->out = 0;
        }

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


int cmd_params( int argc, char **argv )
{
    printf("ALGNAME=%s\n", CRYPTO_ALGNAME);
#ifdef CRYPTO_SECRETKEYBYTES
    printf("CRYPTO_SECRETKEYBYTES=%d\n", CRYPTO_SECRETKEYBYTES);
#endif
#ifdef CRYPTO_PUBLICKEYBYTES
    printf("CRYPTO_PUBLICKEYBYTES=%d\n", CRYPTO_PUBLICKEYBYTES);
#endif
#ifdef CRYPTO_BYTES
    printf("CRYPTO_BYTES=%d\n", CRYPTO_BYTES);
#endif
#ifdef CRYPTO_CIPHERTEXTBYTES
    printf("CRYPTO_CIPHERTEXTBYTES=%d\n", CRYPTO_CIPHERTEXTBYTES);
#endif
    return 0;
}


#ifdef BUILD_KEM

int cmd_kem_gen( int argc, char **argv )
{
    int ret_val;
    unsigned char out_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char out_sk[CRYPTO_SECRETKEYBYTES];

    if ( (ret_val = crypto_kem_keypair(out_pk, out_sk)) != 0) {
        fprintf(stderr, "crypto_kem_keypair returned <%d>\n", ret_val);
        exit(6);
    }

    printf("PK=");
    print_hex(out_pk, sizeof(out_pk));
    printf("\n");

    printf("SK=");
    print_hex(out_sk, sizeof(out_sk));
    printf("\n");

    return 0;
}


int cmd_kem_enc( int argc, char **argv )
{
    int ret_val;
    unsigned char arg_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char out_ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char out_ss[CRYPTO_BYTES];

    hexarg_t arg_spec[] = {
        {"pk", sizeof(arg_pk), arg_pk}
    };

    if( ! parse_args(argc, argv, 1, arg_spec) )
    {
        exit(4);
    }

    if ( (ret_val = crypto_kem_enc(out_ct, out_ss, arg_pk)) != 0) {
        fprintf(stderr, "crypto_kem_enc returned <%d>\n", ret_val);
        exit(5);
    }

    printf("CT=");
    print_hex(out_ct, sizeof(out_ct));
    printf("\n");

    printf("SS=");
    print_hex(out_ss, sizeof(out_ss));
    printf("\n");

    return 0;
}


int cmd_kem_dec( int argc, char **argv )
{
    int ret_val;
    unsigned char arg_ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char arg_sk[CRYPTO_SECRETKEYBYTES];
    unsigned char out_ss[CRYPTO_BYTES];

    hexarg_t arg_spec[] = {
        {"ct", sizeof(arg_ct), arg_ct},
        {"sk", sizeof(arg_sk), arg_sk},
    };

    if( ! parse_args(argc, argv, 2, arg_spec) )
    {
        exit(3);
    }

    if ( (ret_val = crypto_kem_dec(out_ss, arg_ct, arg_sk)) != 0) {
        fprintf(stderr, "crypto_kem_dec returned <%d>\n", ret_val);
        exit(7);
    }

    printf("SS=");
    print_hex(out_ss, sizeof(out_ss));
    printf("\n");

    return 0;
}

// BUILD_KEM
#endif


#ifdef BUILD_SIGN

int cmd_sign_gen( int argc, char **argv )
{
    int ret_val;
    unsigned char out_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char out_sk[CRYPTO_SECRETKEYBYTES];

    if ( (ret_val = crypto_sign_keypair(out_pk, out_sk)) != 0) {
        fprintf(stderr, "crypto_sign_keypair returned <%d>\n", ret_val);
        exit(7);
    }

    printf("PK=");
    print_hex(out_pk, sizeof(out_pk));
    printf("\n");

    printf("SK=");
    print_hex(out_sk, sizeof(out_sk));
    printf("\n");

    return 0;
}
 

int cmd_sign( int argc, char **argv )
{
    int ret_val;
    unsigned char arg_sk[CRYPTO_SECRETKEYBYTES];
    unsigned char *out_sm = 0;
    unsigned long long out_smlen = 0;

    hexarg_t arg_spec[] = {
        {"sk", sizeof(arg_sk), arg_sk},
        {"m", 0, 0},
    };

    if( ! parse_args(argc, argv, 2, arg_spec) )
    {
        exit(3);
    }

    out_sm = (unsigned char *)calloc(arg_spec[1].len + CRYPTO_BYTES, sizeof(unsigned char));

    if ( (ret_val = crypto_sign(out_sm, &out_smlen, arg_spec[1].out, arg_spec[1].len, arg_sk)) != 0)
    {
        fprintf(stderr, "crypto_sign returned <%d>\n", ret_val);
        exit(8);
    }

    printf("SM=");
    print_hex(out_sm, out_smlen);
    printf("\n");

    free(out_sm);

    return 0;
}


int cmd_sign_open( int argc, char **argv )
{
    int ret_val;
    unsigned char arg_pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char *out_m = 0;
    unsigned long long out_mlen = 0;

    hexarg_t arg_spec[] = {
        {"pk", sizeof(arg_pk), arg_pk},
        {"sm", 0, 0},
    };

    if( ! parse_args(argc, argv, 2, arg_spec) )
    {
        exit(3);
    }

    out_m = (unsigned char *)calloc(arg_spec[1].len, sizeof(unsigned char));

    if ( (ret_val = crypto_sign_open(out_m, &out_mlen, arg_spec[1].out, arg_spec[1].len, arg_pk)) != 0) {
        fprintf(stderr, "crypto_sign_open returned <%d>\n", ret_val);
        return 4;
    }

    printf("M=");
    print_hex(out_m, out_mlen);
    printf("\n");

    free(out_m);

    return 0;
}

// BUILD_SIGN
#endif


int main( int argc, char **argv )
{
    cmd_t cmds[] = {
        {"params", cmd_params},

#ifdef BUILD_KEM
        {"kem-gen", cmd_kem_gen},
        {"kem-enc", cmd_kem_enc},
        {"kem-dec", cmd_kem_dec},
#endif

#ifdef BUILD_SIGN
        {"sign-gen", cmd_sign_gen},
        {"sign", cmd_sign},
        {"sign-open", cmd_sign_open},
#endif
    };
    int num_cmds = sizeof(cmds) / sizeof(cmd_t);

    unsigned char seed[48];

    RAND_bytes(seed, sizeof(seed));
    randombytes_init(seed, NULL, 256);

    if( argc < 2 || 0 == strcmp(argv[1], "help") )
    {
        fprintf(stderr, "Usage: %s <operation> [arg [arg ...]]\n", argv[0]);

        fprintf(stderr, "\nOperations:\n");

        for( int i = 0; i < num_cmds; i++ )
        {
            fprintf(stderr, "  %s\n", cmds[i].name);
        }

        exit(1);
    }

    for( int i = 0; i < num_cmds; i++ )
    {
        if( 0 == strcmp(argv[1], cmds[i].name) )
        {
            return cmds[i].cmd(argc-2, &argv[2]);
        }
    }

    fprintf(stderr, "Error: unknown command '%s'\n", argv[1]);

    return 1;
}
