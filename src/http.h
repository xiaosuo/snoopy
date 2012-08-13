
#ifndef __HTTP_H
#define __HTTP_H

typedef void (*http_request_line_handler)(const char *method, const char *path,
		const char *http_version, void *user);
/* A NULL name means the header is ended */
typedef void (*http_header_field_handler)(const char *name, const char *value,
		void *user);
/* A NULL data means the body is ended */
typedef void (*http_body_handler)(const unsigned char *data, int len,
				  void *user);

typedef struct http_inspector http_inspector_t;

http_inspector_t *http_inspector_alloc(void);
void http_inspector_free(http_inspector_t *insp);
int http_inspector_add_request_line_handler(http_inspector_t *insp,
		http_request_line_handler h);
int http_inspector_add_request_header_field_handler(http_inspector_t *insp,
		http_header_field_handler h);
int http_inspector_add_response_body_handler(http_inspector_t *insp,
		http_body_handler h);

typedef struct http_inspect_ctx http_inspect_ctx_t;
http_inspect_ctx_t *http_inspect_ctx_alloc(void);
void http_inspect_ctx_free(http_inspect_ctx_t *ctx);
int http_inspect_client_data(http_inspector_t *insp, http_inspect_ctx_t *ctx,
		const unsigned char *data, int len, void *user);
int http_inspect_server_data(http_inspector_t *insp, http_inspect_ctx_t *ctx,
		const unsigned char *data, int len, void *user);

#endif /* __HTTP_H */
