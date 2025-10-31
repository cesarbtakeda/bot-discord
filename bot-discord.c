
// Compilar: gcc bot_discord_all_files.c -o bot_discord -lcurl -ljson-c -lwebsockets -lpthread
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <libwebsockets.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define API_URL "https://discord.com/api/v10"
#define LOG_FILE "comandos.txt"
#define ENV_FILE "env.txt"

// === Variáveis globais ===
char *TOKEN = NULL;
char *CLIENT_ID = NULL;
static struct lws *wsi_gateway = NULL;
static int heartbeat_interval = 0;
static int running = 1;
static pthread_t hb_thread;

// === Helpers CURL ===
struct curl_response {
    char *body;
    size_t size;
    long http_code;
};

static size_t curl_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct curl_response *r = (struct curl_response *)userdata;
    char *tmp = realloc(r->body, r->size + realsize + 1);
    if (!tmp) return 0;
    r->body = tmp;
    memcpy(&(r->body[r->size]), ptr, realsize);
    r->size += realsize;
    r->body[r->size] = '\0';
    return realsize;
}

// === Carrega tokens ===
int load_env() {
    FILE *fp = fopen(ENV_FILE, "r");
    if (!fp) { fprintf(stderr, "Erro: não foi possível abrir %s\n", ENV_FILE); return 0; }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *k = strtok(line, "=");
        char *v = strtok(NULL, "\n");
        if (!k || !v) continue;
        if (strcmp(k, "BOT_TOKEN") == 0) TOKEN = strdup(v);
        else if (strcmp(k, "CLIENT_ID") == 0) CLIENT_ID = strdup(v);
    }
    fclose(fp);
    if (!TOKEN || !CLIENT_ID) {
        fprintf(stderr, "Erro: BOT_TOKEN ou CLIENT_ID ausente em %s\n", ENV_FILE);
        return 0;
    }
    printf("Tokens carregados com sucesso de %s\n", ENV_FILE);
    return 1;
}

void free_tokens() {
    if (TOKEN) free(TOKEN);
    if (CLIENT_ID) free(CLIENT_ID);
}

// === Log de comandos ===
void log_command(const char *cmd, const char *user_id, const char *username) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) return;
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        size_t len = strlen(time_str);
        if (len > 0 && time_str[len-1] == '\n') time_str[len-1] = '\0';
    } else time_str = "unknown time";
    fprintf(fp, "[%s] Comando: %s | Usuario: %s (ID: %s)\n", time_str, cmd, username?username:"Desconhecido", user_id?user_id:"Desconhecido");
    fclose(fp);
    sleep(1);
}

// === Nome aleatório para arquivos ===
void random_filename(char *buf, size_t size, const char *prefix) {
    const char *chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    int len = 8;
    if (!buf || size < 20) return;
    size_t pos = 0;
    pos += snprintf(buf + pos, size - pos, "%s_", prefix ? prefix : "file");
    for (int i = 0; i < len && pos + 2 < size; i++) {
        buf[pos++] = chars[rand() % (int)strlen(chars)];
    }
    buf[pos] = '\0';
    strncat(buf, ".txt", size - strlen(buf) - 1);
}

// === Envia resposta simples (fallback) ===
void send_response_as_file_or_message(const char *token, const char *content) {
    if (!token || !content) return;
    CURL *curl = curl_easy_init();
    if (!curl) return;
    char url[512];
    snprintf(url, sizeof(url), "%s/webhooks/%s/%s/messages/@original", API_URL, CLIENT_ID, token);
    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "content", json_object_new_string(content));
    struct curl_slist *headers = NULL;
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bot %s", TOKEN);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string(root));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    json_object_put(root);
    curl_easy_cleanup(curl);
}

// === Envia arquivo (PATCH @original) ===
void send_file_response(const char *interaction_token, const char *filename, const char *content) {
    if (!interaction_token) return;
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        send_response_as_file_or_message(interaction_token, "Erro ao criar arquivo.");
        return;
    }
    fwrite(content ? content : "(vazio)", 1, strlen(content ? content : "(vazio)"), fp);
    fclose(fp);

    CURL *curl = curl_easy_init();
    if (!curl) { unlink(filename); return; }

    char url[1024];
    snprintf(url, sizeof(url), "%s/webhooks/%s/%s/messages/@original", API_URL, CLIENT_ID, interaction_token);

    curl_mime *mime = curl_mime_init(curl);
    if (!mime) { curl_easy_cleanup(curl); unlink(filename); return; }

    curl_mimepart *json_part = curl_mime_addpart(mime);
    curl_mime_data(json_part, "{\"content\":\"Resultado em anexo.\"}", CURL_ZERO_TERMINATED);
    curl_mime_type(json_part, "application/json");
    curl_mime_name(json_part, "payload_json");

    curl_mimepart *file_part = curl_mime_addpart(mime);
    curl_mime_filedata(file_part, filename);
    curl_mime_name(file_part, "files[0]");
    curl_mime_filename(file_part, filename);

    struct curl_slist *headers = NULL;
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bot %s", TOKEN);
    headers = curl_slist_append(headers, auth);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);

    struct curl_response resp = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_perform(curl);

    if (resp.http_code < 200 || resp.http_code >= 300) {
        fprintf(stderr, "HTTP %ld ao enviar arquivo\n", resp.http_code);
        if (resp.body) fprintf(stderr, "Resposta: %s\n", resp.body);
    }

    if (resp.body) free(resp.body);
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    unlink(filename);
}

// === Execução genérica de comandos ===
char *exec_cmd(const char *base_cmd, const char *args) {
    if (!base_cmd) return strdup("Erro: comando inválido.");
    char cmd[8192];
    if (!args || args[0] == '\0' || strstr(args, "--help") || strstr(args, "-h")) {
        snprintf(cmd, sizeof(cmd), "%s --help", base_cmd);
    } else {
        if (strcmp(base_cmd, "subfinder") == 0) {
            if (strstr(args, "-d ")) snprintf(cmd, sizeof(cmd), "subfinder %s", args);
            else snprintf(cmd, sizeof(cmd), "subfinder -d %s", args);
        } else {
            snprintf(cmd, sizeof(cmd), "%s %s", base_cmd, args);
        }
    }
    FILE *fp = popen(cmd, "r");
    if (!fp) return strdup("Erro: comando não encontrado.");
    size_t cap = 2 * 1024 * 1024;
    char *buffer = malloc(cap);
    if (!buffer) { pclose(fp); return strdup("Erro de memória."); }
    size_t total = 0, n;
    while ((n = fread(buffer + total, 1, 65536, fp)) > 0) {
        total += n;
        if (total + 65536 >= cap) {
            char *tmp = realloc(buffer, cap * 2);
            if (!tmp) break;
            buffer = tmp; cap *= 2;
        }
    }
    pclose(fp);
    buffer[total < cap ? total : cap-1] = '\0';
    return buffer;
}

char *exec_echo(const char *args) {
    return strdup(args && args[0] ? args : "(nenhum texto)");
}

char *exec_curl(const char *args) {
    if (!args || strstr(args, "--help") || strstr(args, "-h")) return exec_cmd("curl", args);
    if (!args || args[0] == '\0') return strdup("Use: curl <url> ou curl --help");
    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "curl -s -w \"\\nHTTP_STATUS:%%{http_code}\" %s", args);
    FILE *fp = popen(cmd, "r");
    if (!fp) return strdup("Erro: curl falhou.");
    size_t cap = 1024 * 1024;
    char *buffer = malloc(cap);
    if (!buffer) { pclose(fp); return strdup("Erro de memória."); }
    size_t total = 0, n;
    while ((n = fread(buffer + total, 1, 65536, fp)) > 0) {
        total += n;
        if (total + 65536 >= cap) {
            char *tmp = realloc(buffer, cap * 2);
            if (!tmp) break;
            buffer = tmp; cap *= 2;
        }
    }
    pclose(fp);
    buffer[total < cap ? total : cap-1] = '\0';

    char *status_line = strstr(buffer, "HTTP_STATUS:");
    if (status_line) {
        *status_line = '\0';
        status_line += strlen("HTTP_STATUS:");
        while (*status_line == ' ' || *status_line == '\n' || *status_line == '\r') status_line++;
        char *result = malloc(strlen(buffer) + strlen(status_line) + 128);
        if (!result) { free(buffer); return strdup("Erro de memória."); }
        snprintf(result, strlen(buffer) + strlen(status_line) + 128, "%s\n\nStatus HTTP: %s", buffer[0] ? buffer : "(vazio)", status_line);
        free(buffer);
        return result;
    }
    char *result = strdup(buffer);
    free(buffer);
    return result;
}

// === NMAP em arquivo ===
void exec_nmap(const char *args, const char *interaction_token) {
    if (!args || args[0] == '\0' || strstr(args, "--help") || strstr(args, "-h")) {
        char *help = exec_cmd("nmap", "--help");
        char filename[128];
        random_filename(filename, sizeof(filename), "nmap_help");
        send_file_response(interaction_token, filename, help ? help : "(vazio)");
        free(help);
        return;
    }

    char cmd[8192];
    snprintf(cmd, sizeof(cmd), "nmap %s", args);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        char filename[128];
        random_filename(filename, sizeof(filename), "nmap_error");
        send_file_response(interaction_token, filename, "Erro: nmap não encontrado.");
        return;
    }

    char outtmp[128];
    random_filename(outtmp, sizeof(outtmp), "nmap_output");
    FILE *of = fopen(outtmp, "w");
    if (!of) { pclose(fp); send_response_as_file_or_message(interaction_token, "Erro ao criar arquivo nmap."); return; }

    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        fwrite(buf, 1, n, of);
    }
    pclose(fp);
    fclose(of);

    FILE *rf = fopen(outtmp, "r");
    if (rf) {
        fseek(rf, 0, SEEK_END);
        long sz = ftell(rf);
        fseek(rf, 0, SEEK_SET);
        char *content = malloc(sz + 1);
        if (content) {
            fread(content, 1, sz, rf);
            content[sz] = '\0';
            send_file_response(interaction_token, outtmp, content);
            free(content);
        } else {
            send_file_response(interaction_token, outtmp, "Resultado muito grande; veja o arquivo.");
        }
        fclose(rf);
    } else {
        send_file_response(interaction_token, outtmp, "Erro ao ler resultado nmap.");
    }
    unlink(outtmp);
}

// === PING: ping -c 4 <host> ===
void exec_ping(const char *host, const char *interaction_token) {
    if (!host || host[0] == '\0') {
        char filename[128];
        random_filename(filename, sizeof(filename), "ping_error");
        send_file_response(interaction_token, filename, "Erro: forneça um IP ou domínio.\nUso: /ping <host>");
        return;
    }

    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "ping -c 4 %s", host);
    char *output = exec_cmd("ping", cmd + 5);

    char filename[128];
    random_filename(filename, sizeof(filename), "ping");
    send_file_response(interaction_token, filename, output ? output : "Erro ao executar ping.");
    if (output) free(output);
}

// === PONG: resposta direta ===
void send_pong_response(const char *interaction_token) {
    if (!interaction_token) return;
    CURL *curl = curl_easy_init();
    if (!curl) return;

    char url[1024];
    snprintf(url, sizeof(url), "%s/webhooks/%s/%s/messages/@original", API_URL, CLIENT_ID, interaction_token);

    struct json_object *payload = json_object_new_object();
    json_object_object_add(payload, "content", json_object_new_string("pong"));

    struct curl_slist *headers = NULL;
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bot %s", TOKEN);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string(payload));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_perform(curl);

    curl_slist_free_all(headers);
    json_object_put(payload);
    curl_easy_cleanup(curl);
}

// === Defer (ACK) ===
void send_defer_response(const char *id, const char *token) {
    if (!id || !token) return;
    CURL *curl = curl_easy_init();
    if (!curl) return;
    char url[512];
    snprintf(url, sizeof(url), "%s/interactions/%s/%s/callback", API_URL, id, token);
    struct json_object *defer = json_object_new_object();
    json_object_object_add(defer, "type", json_object_new_int(5));
    struct curl_slist *headers = NULL;
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bot %s", TOKEN);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string(defer));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    json_object_put(defer);
    curl_easy_cleanup(curl);
}

// === REGISTRO DE COMANDOS COM RETRY INTELIGENTE ===
int register_command_with_retry(const char *name, const char *desc, int has_required_arg) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[512];
    snprintf(url, sizeof(url), "%s/applications/%s/commands", API_URL, CLIENT_ID);

    struct json_object *cmd = json_object_new_object();
    json_object_object_add(cmd, "name", json_object_new_string(name));
    json_object_object_add(cmd, "description", json_object_new_string(desc));
    json_object_object_add(cmd, "type", json_object_new_int(1));
    struct json_object *options = json_object_new_array();

    if (strcmp(name, "pong") != 0) {
        struct json_object *opt = json_object_new_object();
        json_object_object_add(opt, "name", json_object_new_string("args"));
        json_object_object_add(opt, "description", json_object_new_string(has_required_arg ? "Argumentos obrigatórios" : "Argumentos (use --help)"));
        json_object_object_add(opt, "type", json_object_new_int(3));
        json_object_object_add(opt, "required", json_object_new_boolean(has_required_arg));
        json_object_array_add(options, opt);
    }
    json_object_object_add(cmd, "options", options);

    struct curl_slist *headers = NULL;
    char auth[512];
    snprintf(auth, sizeof(auth), "Authorization: Bot %s", TOKEN);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth);

    int success = 0;
    int tries = 0;
    double wait = 1.0;

    while (!success && tries < 12) {
        struct curl_response resp = {0};
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string(cmd));
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "curl erro ao registrar %s: %s\n", name, curl_easy_strerror(res));
            if (resp.body) free(resp.body);
            tries++;
            usleep((useconds_t)(wait * 1000000));
            wait = wait < 5.0 ? wait + 0.5 : 5.0;
            continue;
        }

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp.http_code);

        if (resp.http_code >= 200 && resp.http_code < 300) {
            printf("Comando GLOBAL %s registrado com sucesso!\n", name);
            success = 1;
        } else if (resp.http_code == 429 && resp.body) {
            struct json_object *j = json_tokener_parse(resp.body);
            double retry_after = 1.0;
            if (j) {
                struct json_object *ra = NULL;
                if (json_object_object_get_ex(j, "retry_after", &ra)) {
                    retry_after = json_object_get_double(ra);
                }
                json_object_put(j);
            }
            retry_after = retry_after > 0.1 ? retry_after : 1.0;
            printf("Rate limited ao registrar %s. Esperando %.3f segundos...\n", name, retry_after);
            usleep((useconds_t)(retry_after * 1000000 + 500000)); // +0.5s margem
            tries++;
        } else {
            fprintf(stderr, "Falha ao registrar %s - HTTP %ld\n", name, resp.http_code);
            if (resp.body) fprintf(stderr, "Resposta: %s\n", resp.body);
            tries++;
            usleep((useconds_t)(wait * 1000000));
            wait = wait < 5.0 ? wait + 0.5 : 5.0;
        }

        if (resp.body) free(resp.body);
    }

    curl_slist_free_all(headers);
    json_object_put(cmd);
    curl_easy_cleanup(curl);
    return success;
}

void register_commands() {
    printf("Registrando comandos GLOBAIS com retry inteligente...\n");
    const char *commands[][3] = {
        {"nmap", "Scan de rede (resultado em .txt)", "0"},
        {"curl", "Requisição HTTP", "0"},
        {"wget", "Download de arquivos", "0"},
        {"whois", "Consulta WHOIS", "0"},
        {"subfinder", "Enumera subdomínios", "0"},
        {"echo", "Imprime texto", "0"},
        {"nikto", "Scan de vulnerabilidades web", "0"},
        {"gobuster", "Brute force de diretórios", "0"},
        {"ffuf", "Fuzzing de web", "0"},
        {"msfvenom", "Gera payloads Metasploit", "0"},
        {"ping", "Ping com 4 pacotes (IP ou domínio)", "1"},
        {"pong", "Retorna 'pong' instantaneamente", "0"},
        {"stop", "Tentativa de cancelar comando", "0"},
        {NULL, NULL, NULL}
    };

    for (int i = 0; commands[i][0]; i++) {
        register_command_with_retry(commands[i][0], commands[i][1], atoi(commands[i][2]));
        usleep(1200000); // 1.2s entre comandos
    }
    printf("Registro finalizado.\n");
}

// === Contexto por interação ===
typedef struct {
    char *interaction_id;
    char *interaction_token;
    char *cmd_name;
    char *args;
    char *user_id;
    char *username;
} interaction_context_t;

void free_interaction_context(interaction_context_t *ctx) {
    if (ctx->interaction_id) free(ctx->interaction_id);
    if (ctx->interaction_token) free(ctx->interaction_token);
    if (ctx->cmd_name) free(ctx->cmd_name);
    if (ctx->args) free(ctx->args);
    if (ctx->user_id) free(ctx->user_id);
    if (ctx->username) free(ctx->username);
    free(ctx);
}

// === Thread: executa comando isolado ===
void *handle_command_thread(void *arg) {
    interaction_context_t *ctx = (interaction_context_t *)arg;
    log_command(ctx->cmd_name, ctx->user_id, ctx->username);

    char *result = NULL;

    if (strcmp(ctx->cmd_name, "nmap") == 0) {
        exec_nmap(ctx->args, ctx->interaction_token);
    } else if (strcmp(ctx->cmd_name, "ping") == 0) {
        exec_ping(ctx->args, ctx->interaction_token);
    } else if (strcmp(ctx->cmd_name, "stop") == 0) {
        char filename[128];
        random_filename(filename, sizeof(filename), "stop");
        send_file_response(ctx->interaction_token, filename,
            "**/stop não funciona com múltiplos comandos simultâneos.**\n"
            "Cada comando roda em thread separada.");
    } else if (strcmp(ctx->cmd_name, "curl") == 0) {
        result = exec_curl(ctx->args);
    } else if (strcmp(ctx->cmd_name, "wget") == 0) {
        result = exec_cmd("wget -qO-", ctx->args);
    } else if (strcmp(ctx->cmd_name, "whois") == 0) {
        result = exec_cmd("whois", ctx->args);
    } else if (strcmp(ctx->cmd_name, "subfinder") == 0) {
        result = exec_cmd("subfinder", ctx->args);
    } else if (strcmp(ctx->cmd_name, "echo") == 0) {
        result = exec_echo(ctx->args);
    } else if (strcmp(ctx->cmd_name, "nikto") == 0) {
        result = exec_cmd("nikto", ctx->args);
    } else if (strcmp(ctx->cmd_name, "gobuster") == 0) {
        result = exec_cmd("gobuster", ctx->args);
    } else if (strcmp(ctx->cmd_name, "ffuf") == 0) {
        result = exec_cmd("ffuf", ctx->args);
    } else if (strcmp(ctx->cmd_name, "msfvenom") == 0) {
        result = exec_cmd("msfvenom", ctx->args);
    } else {
        char filename[128];
        random_filename(filename, sizeof(filename), "unknown");
        char msg[256];
        snprintf(msg, sizeof(msg), "Comando '%s' não reconhecido.", ctx->cmd_name);
        send_file_response(ctx->interaction_token, filename, msg);
        free_interaction_context(ctx);
        return NULL;
    }

    if (result) {
        char filename[128];
        random_filename(filename, sizeof(filename), ctx->cmd_name);
        send_file_response(ctx->interaction_token, filename, result);
        free(result);
    }

    free_interaction_context(ctx);
    return NULL;
}

// === WebSocket ===
void send_ws(struct lws *wsi, struct json_object *obj) {
    const char *json = json_object_to_json_string(obj);
    unsigned char buf[LWS_PRE + 4096];
    int n = snprintf((char *)&buf[LWS_PRE], 4096, "%s", json);
    lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_TEXT);
}

void send_heartbeat(struct lws *wsi) {
    struct json_object *hb = json_object_new_object();
    json_object_object_add(hb, "op", json_object_new_int(1));
    json_object_object_add(hb, "d", json_object_new_int(251));
    send_ws(wsi, hb);
    json_object_put(hb);
}

void *heartbeat_loop(void *arg) {
    while (running && heartbeat_interval > 0) {
        usleep((useconds_t)heartbeat_interval * 1000);
        if (wsi_gateway) send_heartbeat(wsi_gateway);
    }
    return NULL;
}

static int callback_discord(struct lws *wsi, enum lws_callback_reasons reason,
                            void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            printf("Conectado ao Gateway!\n");
            wsi_gateway = wsi;
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            struct json_object *root = json_tokener_parse((const char *)in);
            if (!root) break;

            struct json_object *op_obj = NULL;
            if (!json_object_object_get_ex(root, "op", &op_obj)) { json_object_put(root); break; }
            int op = json_object_get_int(op_obj);

            if (op == 10) {
                struct json_object *hello_data = NULL;
                if (json_object_object_get_ex(root, "d", &hello_data)) {
                    struct json_object *interval_obj = NULL;
                    if (json_object_object_get_ex(hello_data, "heartbeat_interval", &interval_obj)) {
                        heartbeat_interval = json_object_get_int(interval_obj);
                        printf("Heartbeat: %dms\n", heartbeat_interval);
                    }
                }
                struct json_object *identify = json_object_new_object();
                struct json_object *d = json_object_new_object();
                json_object_object_add(d, "token", json_object_new_string(TOKEN));
                json_object_object_add(d, "intents", json_object_new_int(0));
                struct json_object *props = json_object_new_object();
                json_object_object_add(props, "$os", json_object_new_string("linux"));
                json_object_object_add(props, "$browser", json_object_new_string("custom-bot"));
                json_object_object_add(d, "properties", props);
                json_object_object_add(identify, "op", json_object_new_int(2));
                json_object_object_add(identify, "d", d);
                send_ws(wsi, identify);
                json_object_put(identify);
                pthread_create(&hb_thread, NULL, heartbeat_loop, NULL);
            } else if (op == 0) {
                struct json_object *event_type = NULL;
                if (!json_object_object_get_ex(root, "t", &event_type)) { json_object_put(root); break; }
                const char *event = json_object_get_string(event_type);

                if (strcmp(event, "INTERACTION_CREATE") == 0) {
                    struct json_object *interaction = NULL;
                    json_object_object_get_ex(root, "d", &interaction);
                    if (!interaction) { json_object_put(root); break; }

                    struct json_object *id_obj = NULL, *token_obj = NULL, *data = NULL;
                    if (!json_object_object_get_ex(interaction, "id", &id_obj) ||
                        !json_object_object_get_ex(interaction, "token", &token_obj) ||
                        !json_object_object_get_ex(interaction, "data", &data)) {
                        json_object_put(root); break;
                    }

                    const char *id = json_object_get_string(id_obj);
                    const char *token = json_object_get_string(token_obj);

                    struct json_object *name_obj = NULL;
                    if (!json_object_object_get_ex(data, "name", &name_obj)) { json_object_put(root); break; }
                    const char *cmd_name = json_object_get_string(name_obj);

                    const char *user_id = "Desconhecido", *username = "Desconhecido";
                    struct json_object *member = NULL;
                    if (json_object_object_get_ex(interaction, "member", &member)) {
                        struct json_object *user = NULL;
                        if (json_object_object_get_ex(member, "user", &user)) {
                            struct json_object *uid = NULL, *uname = NULL;
                            if (json_object_object_get_ex(user, "id", &uid)) user_id = json_object_get_string(uid);
                            if (json_object_object_get_ex(user, "username", &uname)) username = json_object_get_string(uname);
                        }
                    }

                    send_defer_response(id, token);

                    char args[2048] = {0};
                    struct json_object *options = NULL;
                    if (json_object_object_get_ex(data, "options", &options) && json_object_array_length(options) > 0) {
                        struct json_object *opt = json_object_array_get_idx(options, 0);
                        struct json_object *value_obj = NULL;
                        if (json_object_object_get_ex(opt, "value", &value_obj)) {
                            const char *value = json_object_get_string(value_obj);
                            if (value) strncpy(args, value, sizeof(args)-1);
                        }
                    }

                    if (strcmp(cmd_name, "pong") == 0) {
                        log_command(cmd_name, user_id, username);
                        send_pong_response(token);
                        json_object_put(root);
                        return 0;
                    }

                    interaction_context_t *ctx = malloc(sizeof(interaction_context_t));
                    ctx->interaction_id = strdup(id);
                    ctx->interaction_token = strdup(token);
                    ctx->cmd_name = strdup(cmd_name);
                    ctx->args = strdup(args);
                    ctx->user_id = strdup(user_id);
                    ctx->username = strdup(username);

                    pthread_t thread;
                    pthread_create(&thread, NULL, handle_command_thread, ctx);
                    pthread_detach(thread);
                }
            }
            json_object_put(root);
            break;
        }

        case LWS_CALLBACK_CLOSED:
            running = 0;
            break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    { "discord-protocol", callback_discord, 0, 0 },
    { NULL, NULL, 0, 0 }
};

void connect_gateway() {
    struct lws_context_creation_info info = {0};
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    struct lws_context *context = lws_create_context(&info);
    if (!context) { fprintf(stderr, "Erro ao criar contexto lws\n"); return; }

    struct lws_client_connect_info i = {0};
    i.context = context;
    i.address = "gateway.discord.gg";
    i.port = 443;
    i.path = "/?v=10&encoding=json";
    i.host = i.address;
    i.origin = i.address;
    i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    i.protocol = protocols[0].name;
    i.pwsi = &wsi_gateway;

    if (!lws_client_connect_via_info(&i)) {
        fprintf(stderr, "Falha ao iniciar conexão WS\n");
    }

    while (running) lws_service(context, 1000);
    lws_context_destroy(context);
}

void handle_sigint(int sig) {
    (void)sig;
    running = 0;
    if (wsi_gateway) lws_callback_on_writable(wsi_gateway);
    printf("Encerrando...\n");
}

int main() {
    srand((unsigned)time(NULL));
    signal(SIGINT, handle_sigint);
    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (!load_env()) {
        fprintf(stderr, "Falha ao carregar env. Saindo.\n");
        return 1;
    }

    register_commands();
    connect_gateway();

    free_tokens();
    curl_global_cleanup();
    return 0;
}
