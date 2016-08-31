#include "main.h"

static const char *s_http_port = "8000";
static const char *sum_urlencoded_url = "/api/v1/sum-urlencoded";
static const char *sum_json_url = "/api/v1/sum-json";
static const char *sum_get_url = "/api/v1/sum";
static const char *HTTP_METHOD_POST = "POST";
static const char *HTTP_METHOD_GET = "GET";

static struct mg_serve_http_opts s_http_server_opts;

void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
	struct http_message *hm = (struct http_message *) ev_data;

	switch (ev) {
	case MG_EV_HTTP_REQUEST:
		if (mg_vcmp(&hm->method, HTTP_METHOD_POST) == 0) {
			if (mg_vcmp(&hm->uri, sum_urlencoded_url) == 0) {
				handle_sum_call_urlencoded(nc, hm); /* Handle RESTful call with urlencoded */
			}
			else if (mg_vcmp(&hm->uri, sum_json_url) == 0) {
				handle_sum_call_json(nc, hm); /* Handle RESTful call with JSON request */
			}
			else {
				mg_printf(nc, "%s", "HTTP/1.0 501 Not Implemented\r\n""Content-Length: 0\r\n\r\n");
			}
		}
		//else if (mg_vcmp(&hm->method, HTTP_METHOD_GET) == 0) {
		//	if (mg_vcmp(&hm->uri, sum_get_url) == 0) {
		//		handle_sum_call_get(nc, hm);
		//	}
		//}
		else {
			mg_serve_http(nc, hm, s_http_server_opts); /* Serve static content */
		}
		break;
	default:
		break;
	}
}

void handle_sum_call_urlencoded(struct mg_connection *nc, struct http_message *hm) {
	/* Get form variables */
	char n1[100], n2[100];
	mg_get_http_var(&hm->body, "n1", n1, sizeof(n1));
	mg_get_http_var(&hm->body, "n2", n2, sizeof(n2));

	/* Compute the result  */
	double result = strtod(n1, NULL) + strtod(n2, NULL);

	cJSON *retJson = sum_result(result);
	/* Send headers */
	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");

	/* Send body */
	mg_printf_http_chunk(nc, cJSON_Print(retJson));
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}

void handle_sum_call_json(struct mg_connection *nc, struct http_message *hm) {
	/* Get json variables */
	cJSON *json = cJSON_Parse((&hm->body)->p);
	double n1 = cJSON_GetObjectItem(json, "n1")->valuedouble;
	double n2 = cJSON_GetObjectItem(json, "n2")->valuedouble;

	/* Compute the result */
	double result = n1 + n2;

	/* Send headers */
	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");

	cJSON *retJson = sum_result(result);
	/* Send body */
	mg_printf_http_chunk(nc, cJSON_Print(retJson));
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}

//void handle_sum_call_get(struct mg_connection *nc, struct http_message *hm) {
//	/* Get form variables */
//	char n1[100], n2[100];
//	mg_get_http_var(&hm->uri.p + 1, "n2", n2, sizeof(n2));
//
//	/* Compute the result  */
//	double result = strtod(n1, NULL) + strtod(n2, NULL);
//
//	cJSON *retJson = sum_result(result);
//	/* Send headers */
//	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
//
//	/* Send body */
//	mg_printf_http_chunk(nc, cJSON_Print(retJson));
//	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
//}

cJSON *sum_result(double result) {
	cJSON *ret = cJSON_CreateObject();
	cJSON_AddNumberToObject(ret, "result", result);
	return ret;
}

cJSON *fakeResponse() {
	char **errors = (char **)malloc(sizeof(char *) * 2);
	errors[0] = "error1";
	errors[1] = "error2";

	cJSON *retJson = cJSON_CreateObject();
	cJSON_AddTrueToObject(retJson, "sucesso");
	cJSON *errorsJson = cJSON_CreateArray();
	cJSON_AddItemToObject(retJson, "errors", errorsJson);
	int errorsAmount = _msize(errors) / sizeof(char *);
	for (int i = 0; i < errorsAmount; i++) {
		cJSON *errorJson = cJSON_CreateObject();
		cJSON_AddStringToObject(errorJson, "error", errors[i]);
		cJSON_AddItemToArray(errorsJson, errorJson);
	}
	return retJson;
}

int main(int argc, char *argv[]) {
	struct mg_mgr mgr;
	struct mg_connection *nc;
	struct mg_bind_opts bind_opts;
	int i;
	char *cp;
	const char *err_str;
#ifdef MG_ENABLE_SSL
	const char *ssl_cert = NULL;
#endif

	mg_mgr_init(&mgr, NULL);

	/* Use current binary directory as document root */
	if (argc > 0 && ((cp = strrchr(argv[0], DIRSEP)) != NULL)) {
		*cp = '\0';
		s_http_server_opts.document_root = argv[0];
	}

	/* Process command line options to customize HTTP server */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-D") == 0 && i + 1 < argc) {
			mgr.hexdump_file = argv[++i];
		}
		else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			s_http_server_opts.document_root = argv[++i];
		}
		else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
			s_http_port = argv[++i];
		}
		else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
			s_http_server_opts.auth_domain = argv[++i];
#ifdef MG_ENABLE_JAVASCRIPT
		}
		else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc) {
			const char *init_file = argv[++i];
			mg_enable_javascript(&mgr, v7_create(), init_file);
#endif
		}
		else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
			s_http_server_opts.global_auth_file = argv[++i];
		}
		else if (strcmp(argv[i], "-A") == 0 && i + 1 < argc) {
			s_http_server_opts.per_directory_auth_file = argv[++i];
		}
		else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
			s_http_server_opts.url_rewrites = argv[++i];
#ifndef MG_DISABLE_CGI
		}
		else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
			s_http_server_opts.cgi_interpreter = argv[++i];
#endif
#ifdef MG_ENABLE_SSL
		}
		else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
			ssl_cert = argv[++i];
#endif
		}
		else {
			fprintf(stderr, "Unknown option: [%s]\n", argv[i]);
			exit(1);
		}
	}

	/* Set HTTP server options */
	memset(&bind_opts, 0, sizeof(bind_opts));
	bind_opts.error_string = &err_str;
#ifdef MG_ENABLE_SSL
	if (ssl_cert != NULL) {
		bind_opts.ssl_cert = ssl_cert;
	}
#endif
	nc = mg_bind_opt(&mgr, s_http_port, ev_handler, bind_opts);
	if (nc == NULL) {
		fprintf(stderr, "Error starting server on port %s: %s\n", s_http_port,
			*bind_opts.error_string);
		exit(1);
	}

	mg_set_protocol_http_websocket(nc);
	s_http_server_opts.enable_directory_listing = "yes";

	printf("Starting RESTful server on port %s, serving %s\n", s_http_port,
		s_http_server_opts.document_root);
	for (;;) {
		mg_mgr_poll(&mgr, 1000);
	}
	mg_mgr_free(&mgr);

	return 0;
}
