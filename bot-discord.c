[128];
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
