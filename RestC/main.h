#pragma once
#include "mongoose.h"
#include "cJson.h"

void ev_handler(struct mg_connection *nc, int ev, void *ev_data);

void handle_sum_call_urlencoded(struct mg_connection *nc, struct http_message *hm);

void handle_sum_call_json(struct mg_connection *nc, struct http_message *hm);

//void handle_sum_call_get(struct mg_connection *nc, struct http_message *hm);

cJSON *sum_result(double result);

//cJSON *fakeResponse();