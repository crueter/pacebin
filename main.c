#include "mongoose.h"
#include "index.h"

#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <time.h>

char *port = "8081";
char *data_dir = "/srv/pacebin";
char *seed = "secret";
char *proto = "http://";

static struct mg_http_serve_opts s_http_server_opts;

static void rec_mkdir(const char *dir) {
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }

    mkdir(tmp, S_IRWXU);
}

bool exists(char *filename) {
    struct stat buffer;
    return (stat (filename, &buffer) == 0);
}

char *get_file_filename(char *path) {
    char *filename = malloc(strlen(data_dir) + strlen(path) + 8);
    snprintf(filename, strlen(data_dir) + strlen(path) + 8, "%s/files/%s", data_dir, path);
    return filename;
}

char *get_del_filename(char *path) {
    char *filename = malloc(strlen(data_dir) + strlen(path) + 6);
    snprintf(filename, strlen(data_dir) + strlen(path) + 6, "%s/del/%s", data_dir, path);
    return filename;
}

bool file_exists(char *path) {
    char *filename = get_file_filename(path);
    bool ret = exists(filename);
    free(filename);
    return ret;
}

char *get_file_filename_shortid(char *shortid, char *file) {
    char *full = malloc(strlen(shortid) + strlen(file) + 2);
    snprintf(full, strlen(shortid) + strlen(file) + 2, "%s/%s", shortid, file);
    char *ret = get_file_filename(full);
    free(full);
    return ret;
}

char *get_del_filename_shortid(char *shortid, char *file) {
    char *full = malloc(strlen(shortid) + strlen(file) + 2);
    snprintf(full, strlen(shortid) + strlen(file) + 2, "%s/%s", shortid, file);
    char *ret = get_del_filename(full);
    free(full);
    return ret;
}

char *gen_random_shortid() {
    srand(time(NULL));
    char *shortid = malloc(17);
    do {
        for(size_t i = 0; i < 16; ++i) {
            sprintf(shortid + i, "%x", rand() % 16);
        }
    } while (file_exists(shortid));
    return shortid;
}

char *gen_del_key(char *shortid, char *file) {
    char *salt = malloc(20);
    char *rand_str = malloc(17);
    srand(time(NULL));
    for (size_t i = 0; i < 16; ++i) {
        rand_str[i] = 37 + (rand() % 90); // random printable char
        if (rand_str[i] == 92 || rand_str[i] == 58 ||
            rand_str[i] == 59 || rand_str[i] == 42) --i; // chars not allowed for salts
    }
    rand_str[16] = 0;
    sprintf(salt, "$6$%s", rand_str);
    free(rand_str);

    char *use_link = malloc(strlen(shortid) + strlen(file) + strlen(seed) + 1);
    sprintf(use_link, "%s%s%s", seed, shortid, file);

    char *del_key = crypt(use_link, salt);
    free(salt);
    free(use_link);

    return del_key;
}

void trim(char *str) {
    char *_str = str;
    int len = strlen(_str);

    while(*_str && *_str == '/') ++_str, --len;

    memmove(str, _str, len + 1);
}

void handle_post(struct mg_connection *nc, struct mg_str content, char *host, char *filename) {
    char *shortid = gen_random_shortid();
    if (strlen(filename) >= 255) {
        return mg_http_reply(nc, 413, "", "filename length can not exceed 255 characters");
    } else if (strlen(filename) == 0) {
        return mg_http_reply(nc, 400, "", "please provide a filename");
    }

    char *shortid_dir = get_file_filename(shortid);
    char *shortid_del_dir = get_del_filename(shortid);

    mkdir(shortid_dir, S_IRWXU);
    mkdir(shortid_del_dir, S_IRWXU);

    free(shortid_dir);
    free(shortid_del_dir);

    unsigned char *ucont = (unsigned char *) content.ptr;
    char *file = get_file_filename_shortid(shortid, filename);
    if (!mg_file_write(file, ucont, content.len)) {
        fprintf(stderr, "failed to write to file %s", file);
        mg_http_reply(nc, 500, "", "failed to write data");
        return free(shortid);
    }
    free(file);

    char *del_key = gen_del_key(shortid, filename);
    char *del_file = get_del_filename_shortid(shortid, filename);
    if (!mg_file_write(del_file, del_key, strlen(del_key))) {
        fprintf(stderr, "failed to write to file %s", del_file);
        mg_http_reply(nc, 500, "", "failed to write data");
        free(shortid);
        return free(del_file);
    }
    free(del_file);

    char *del_header = malloc(256);
    sprintf(del_header, "X-Delete-With: %s\r\n", del_key);

    mg_http_reply(nc, 201, del_header, "%s%s/%s/%s", proto, host, shortid, filename);

    free(del_header);
    free(shortid);
}

void handle_delete(struct mg_connection *nc, char *link, char *del_key) {
    if (file_exists(link)) {
        char *link_del_file = get_del_filename(link);
        char *key = mg_file_read(link_del_file, NULL);
        if (strcmp(key, del_key) == 0) {
#define remove_free(stmt) { char *tmp = stmt; remove(tmp); free(tmp); }
            remove_free(link_del_file);
            remove_free(get_del_filename(link));
            remove_free(get_file_filename(link));
            char *shortid = strtok(link, "/");
            remove_free(get_file_filename(shortid));
            remove_free(get_del_filename(shortid));
#undef remove_free
            mg_http_reply(nc, 204, "", "");
        } else {
            mg_http_reply(nc, 403, "", "incorrect deletion key");
        }
        free(key);
    } else {
        mg_http_reply(nc, 404, "", "this file does not exist");
    }
}

static void ev_handler(struct mg_connection *nc, int ev, void *p, void *f) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) p;
        char *uri = malloc(hm->uri.len + 1);

        snprintf(uri, hm->uri.len + 1, "%s", hm->uri.ptr);
        trim(uri);

        struct mg_str *pmhost = mg_http_get_header(hm, "Host");
        struct mg_str mhost;
        if (pmhost == NULL) {
            fprintf(stderr, "request sent with no Host header");
            mhost = mg_str("<UNKNOWN DOMAIN>");
        } else {
            mhost = *pmhost;
        }

        char *host = malloc(mhost.len + 1);
        snprintf(host, mhost.len + 1, "%s", mhost.ptr);

        char *body = strdup(hm->body.ptr);

        struct mg_str *pmtype = mg_http_get_header(hm, "Content-Type");
        if (pmtype) {
            struct mg_str mtype = *pmtype;

            if (strncmp(mtype.ptr, "multipart/form-data", 19) == 0) {
                struct mg_http_part part;

                size_t ofs = 0;
                while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) > 0) {
                    body = malloc(part.body.len + 1);
                    snprintf(body, part.body.len + 1, "%s", part.body.ptr);
                }
            }
        }

        if (strncmp(hm->method.ptr, "POST", hm->method.len) == 0 || strncmp(hm->method.ptr, "PUT", hm->method.len) == 0) {
            handle_post(nc, hm->body, host, uri); // FIXME: return 400 on bad Content-Type
        } else if (strncmp(hm->method.ptr, "DELETE", hm->method.len) == 0) {
            handle_delete(nc, uri, body);
        } else if (strncmp(hm->method.ptr, "GET", hm->method.len) == 0) {
            if (strlen(uri) == 0) {
                return mg_http_reply(nc, 200, "Content-Type: text/html\r\n", INDEX_HTML,
                                     host, host, host, host, host); // FIXME: need better solution
            }

            mg_http_serve_dir(nc, hm, &s_http_server_opts);
        } else {
            mg_http_reply(nc, 405, "Allow: GET, PUT, POST, DELETE\r\n", "");
        }

        free(uri);
        free(host);
        free(body);
    }
}

int main(int argc, char *argv[]) {
    int index;
    int c;

    opterr = 0;
    setvbuf(stdout, NULL, _IONBF, 0);

    while ((c = getopt (argc, argv, "p:d:s:kh")) != -1) {
        switch (c) {
        case 'p':
            port = optarg;
            break;
        case 'd':
            data_dir = optarg;
            break;
        case 's':
            seed = optarg;
            break;
        case 'k':
            proto = "https://";
            break;
        case 'h':
            printf("pacebin: a minimal file-upload service\n");
            printf("usage: %s [-p port] [-d data_dir] [-s seed] [-k]\n\n", argv[0]);
            printf("options:\n");
            printf("-p <port>\t\tport to use (default 8081)\n");
            printf("-d <data directory>\tdirectory to store data (default /srv/pacebin)\n");
            printf("-s <seed>\t\tsecret seed to use (DO NOT SHARE THIS; default 'secret')\n");
            printf("-k\t\t\treturns HTTPS URLs when uploading files, use with an HTTPS-enabled reverse proxy\n\n");
            printf("source: https://short.swurl.xyz/pacebin (submit bug reports, suggestions, etc. here)\n");
            return 0;
        case '?':
            if (optopt == 'p' || optopt == 'd' || optopt == 's') {
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            }
            else if (isprint (optopt)) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            }
            else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
            return 1;
        default:
            abort();
        }
    }

    for (index = optind; index < argc; index++) {
        printf ("Non-option argument %s\n", argv[index]);
    }

    char *files_dir = strcat(strdup(data_dir), "/files");
    char *del_dir = strcat(strdup(data_dir), "/del");

    rec_mkdir(files_dir);
    rec_mkdir(del_dir);

    free(files_dir);
    free(del_dir);

    struct mg_mgr mgr;
    struct mg_connection *nc;

    char *root = malloc(strlen(data_dir) + 7);
    snprintf(root, strlen(data_dir) + 7, "%s/files", data_dir);
    memset(&s_http_server_opts, 0, sizeof(s_http_server_opts));
    s_http_server_opts.root_dir = root;

    mg_mgr_init(&mgr);
    printf("Starting web server on port %s\n", port);
    char *str_port = malloc(20);
    sprintf(str_port, "http://0.0.0.0:%s", port);
    nc = mg_http_listen(&mgr, str_port, ev_handler, &mgr);
    if (nc == NULL) {
        printf("Failed to create listener\n");
        return 1;
    }

    for (;;) { mg_mgr_poll(&mgr, 1000); }
    mg_mgr_free(&mgr);
    return 0;
}

