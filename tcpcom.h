#pragma once

#include <stdint.h>
#include "utils.h"

int tcpcom_init(void** ctx, const char* address, const char* port);
int tcpcom_request(void **ctx, const char* sendbuf, int senbufsz, uint32_t* timespent);
void tcpcom_close(void** ctx);

typedef enum tcpcom_msgcb_ret_e
{
	TCPCOM_RETVAL_CONTINUE = 0,
	TCPCOM_RETVAL_CLOSE = -1,
	TCPCOM_RETVAL_FINISHED = -2
} tcpcom_msgcb_ret;

typedef tcpcom_msgcb_ret(*tcpcom_incoming_message_cb)(const membuf *incoming, membuf *outgoing);

int tcpcom_server(const char* address, const char* port, tcpcom_incoming_message_cb cb);

const char* const tcpcom_httpget = "GET /%s HTTP/1.1\xd\xa"
							"Host: %s:%s\xd\xa"
							"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\xd\xa"
							"Accept: text/html\xd\xa"
							"Accept-Language: en-US,en;q=0.5\xd\xa"
							"Accept-Encoding: identity\xd\xa"
							"Connection: keep-alive\xd\xa"
	                        "Keep-Alive: timeout=5, max=1000\xd\xa"
							"Upgrade-Insecure-Requests: 1\xd\xa"
							"Sec-Fetch-Dest: document\xd\xa"
							"Sec-Fetch-Mode: navigate\xd\xa"
							"Sec-Fetch-Site: none\xd\xa"
							"Sec-Fetch-User: ?1\xd\xa"
							"\xd\xa";

const char* const tcpcom_httpresponse = "HTTP/1.1 %s\xd\xa"
								"Server: localhost\xd\xa"
								"Date: DAY__DD_MMM_YYYY_HH_MM_SS GMT\xd\xa"
								"Content-Type: text/html\xd\xa"
								"Transfer-Encoding: chunked\xd\xa"
								"\xd\xa";

const char* const tcpcom_httpresp200 = "200 OK";
const char* const tcpcom_httpresp400 = "400 Bad Request";
const char* const tcpcom_httpresp500 = "500 Internal Server Error";