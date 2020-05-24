#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <xmp.h>
#include <mysql.h>

#define DELETE_SAMPLE "DELETE FROM sample WHERE modfile = ?"

#define INSERT_MODFILE "REPLACE INTO modfile(title, filename) VALUES (?,?)"

#define INSERT_SAMPLE "INSERT INTO sample(name, filename, sha256, modfile, pos, len) VALUES (?,?,?,?,?,?)"


void insert_modfile(MYSQL *mysql, char *name, char *file) {

    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[2];

    stmt = mysql_stmt_init(mysql);
    if (!stmt) {
        fprintf(stderr, " mysql_stmt_init(), out of memory\n");
        exit(0);
    }
    if (mysql_stmt_prepare(stmt, INSERT_MODFILE, strlen(INSERT_MODFILE)))
    {
        fprintf(stderr, " mysql_stmt_prepare(), INSERT failed\n");
        fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
        exit(0);
    }

    memset(bind, 0, sizeof(bind));

    unsigned long l = strlen(name);
    bind[0].buffer_type= MYSQL_TYPE_STRING;
    bind[0].buffer= (char *) name;
    bind[0].buffer_length= strlen(name);
    bind[0].is_null= 0;
    bind[0].length= &l;

    unsigned long l2 = strlen(file);
    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *) file;
    bind[1].buffer_length= strlen(file);
    bind[1].is_null= 0;
    bind[1].length= &l2;

    if (mysql_stmt_bind_param(stmt, bind))
    {
        fprintf(stderr, " mysql_stmt_bind_param() failed\n");
        fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    }

    if (mysql_stmt_execute(stmt))
    {
        fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
        fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
    }
}

static MYSQL* get_db_con(char *user, char *pass, char *host, char *db, int port) {
    MYSQL *con = mysql_init(NULL);
    if (con == NULL)
    {
        fprintf(stderr, "%s\n", mysql_error(con));
        exit(1);
    }

    if (mysql_real_connect(con, host, user, pass, db, port, NULL, 0) == NULL)
    {
        fprintf(stderr, "%s\n", mysql_error(con));
        mysql_close(con);
        exit(1);
    }
    return con;
}

static void rip_samples(MYSQL *con, char *filename, struct xmp_module_info *mi) {
    int i, j;
    struct xmp_module *mod = mi->mod;

    insert_modfile(con, mod->name, filename);

    printf("Samples:\n");
    for (i = 0; i < mod->smp; i++) {
        struct xmp_sample *smp = &mod->xxs[i];

        if (smp->len > 0 && smp->data != NULL) {

            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            size_t len;
            unsigned char buffer[1024];
            do {
                SHA256_Update(&ctx, smp->data, smp->len);
            } while (len == BUFSIZ);
            SHA256_Final(buffer, &ctx);

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

    MYSQL *con = get_db_con("", "", "", "", 3306);

    ctx = xmp_create_context();

    for (i = 1; i < argc; i++) {
        if (xmp_load_module(ctx, argv[i]) < 0) {
            fprintf(stderr, "%s: error loading %s\n", argv[0],
                    argv[i]);
            continue;
        }

        if (xmp_start_player(ctx, 44100, 0) == 0) {
            xmp_get_module_info(ctx, &mi);
            rip_samples(con, argv[i], &mi);
            xmp_end_player(ctx);
        }

        xmp_release_module(ctx);
    }

    xmp_free_context(ctx);

    return 0;
}
