#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <xmp.h>

static void rip_samples(struct xmp_module_info *mi) {
    int i, j;
    struct xmp_module *mod = mi->mod;

    printf("Name: %s\n", mod->name);
    printf("Type: %s\n", mod->type);
    printf("Number of patterns: %d\n", mod->pat);
    printf("Number of tracks: %d\n", mod->trk);
    printf("Number of channels: %d\n", mod->chn);
    printf("Number of instruments: %d\n", mod->ins);
    printf("Number of samples: %d\n", mod->smp);
    printf("Initial speed: %d\n", mod->spd);
    printf("Initial BPM: %d\n", mod->bpm);
    printf("Length in patterns: %d\n", mod->len);

    printf("\n");

    printf("Samples:\n");
    for (i = 0; i < mod->smp; i++) {
        struct xmp_sample *smp = &mod->xxs[i];


        fprintf(stderr, "Sample len: %d\n", smp->len);
        if (smp->len > 0 && smp->data != NULL) {

            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            size_t len;
            unsigned char buffer[1024];
            do {
                SHA256_Update(&ctx, smp->data, smp->len);
            } while (len == BUFSIZ);
            SHA256_Final(buffer, &ctx);

            fprintf(stderr,"sample %d: ", i);
            char checksum[65];
            for (len = 0; len < SHA256_DIGEST_LENGTH; len++)
                sprintf(checksum + (len * 2), "%02x", buffer[len]);
            checksum[64] = '\0';
            fprintf(stderr,"%s\n", checksum);
        }
    }
}

int main(int argc, char **argv)
{
    static xmp_context ctx;
    static struct xmp_module_info mi;
    int i;

    ctx = xmp_create_context();

    for (i = 1; i < argc; i++) {
        if (xmp_load_module(ctx, argv[i]) < 0) {
            fprintf(stderr, "%s: error loading %s\n", argv[0],
                    argv[i]);
            continue;
        }

        if (xmp_start_player(ctx, 44100, 0) == 0) {
            xmp_get_module_info(ctx, &mi);
            rip_samples(&mi);
            xmp_end_player(ctx);
        }

        xmp_release_module(ctx);
    }

    xmp_free_context(ctx);

    return 0;
}
