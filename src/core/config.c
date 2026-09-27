#define _POSIX_C_SOURCE 200809L

#include "sentinel/config.h"
#include "sentinel/buf.h"
#include "sentinel/json.h"
#include "sentinel/paths.h"
#include "sentinel/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void config_init(sentinel_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->interval = 300;
}

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) { fclose(f); return NULL; }
    char *data = malloc((size_t)len + 1);
    if (!data) { fclose(f); return NULL; }
    size_t n = fread(data, 1, (size_t)len, f);
    fclose(f);
    data[n] = '\0';
    if (out_len) *out_len = n;
    return data;
}

int config_load(sentinel_config_t *config, const char *path)
{
    if (!config || !path) return 0;

    size_t len;
    char *text = read_file(path, &len);
    if (!text) return 0;

    json_value_t *root = json_parse(text, len);
    free(text);
    if (!root || root->type != JSON_OBJECT) { json_free(root); return 0; }

    double interval = json_get_num(root, "interval", -1);
    if (interval > 0) config->interval = (int)interval;

    const char *tok = json_get_str(root, "telegram_token");
    const char *cid = json_get_str(root, "telegram_chat_id");
    const char *swh = json_get_str(root, "slack_webhook");
    const char *dwh = json_get_str(root, "discord_webhook");
    const char *rep = json_get_str(root, "report");

    if (tok) config->telegram_token = tok;
    if (cid) config->telegram_chat_id = cid;
    if (swh) config->slack_webhook = swh;
    if (dwh) config->discord_webhook = dwh;
    if (rep) config->report_path = rep;

    json_value_t *stages = json_get(root, "stages");
    if (stages && stages->type == JSON_ARRAY) {
        config->stage_count = 0;
        for (size_t i = 0; i < stages->count && config->stage_count < 8; i++) {
            const char *s = json_str_at(stages, i);
            if (s) config->stages[config->stage_count++] = s;
        }
    }

    json_free(root);
    return 1;
}

int config_save(const sentinel_config_t *config, const char *path)
{
    if (!config || !path) return 0;

    json_value_t *root = json_object();
    json_object_set_num(root, "interval", config->interval);

    if (config->telegram_token)
        json_object_set_str(root, "telegram_token", config->telegram_token);
    if (config->telegram_chat_id)
        json_object_set_str(root, "telegram_chat_id", config->telegram_chat_id);
    if (config->slack_webhook)
        json_object_set_str(root, "slack_webhook", config->slack_webhook);
    if (config->discord_webhook)
        json_object_set_str(root, "discord_webhook", config->discord_webhook);
    if (config->report_path)
        json_object_set_str(root, "report", config->report_path);

    if (config->stage_count) {
        json_value_t *arr = json_array();
        for (size_t i = 0; i < config->stage_count; i++)
            json_array_push(arr, json_string(config->stages[i]));
        json_object_set(root, "stages", arr);
    }

    char *dump = json_dump(root, 2);
    json_free(root);
    if (!dump) return 0;

    FILE *f = fopen(path, "wb");
    if (!f) { free(dump); return 0; }
    fwrite(dump, 1, strlen(dump), f);
    fclose(f);
    free(dump);
    return 1;
}
