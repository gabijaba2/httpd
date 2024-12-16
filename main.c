/* Copyright (C) 2024 gabijaba */

#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define MAX_HEADER_NAME_SIZE 256
#define MAX_HEADER_VALUE_SIZE 256
#define MAX_COUNT_OF_HEADERS 20
#define MAX_URI_LENGTH 8000
#define MAX_METHOD_LENGTH 16
#define MAX_BODY_SIZE 1048576 // 1 MB

// method + ' ' + uri + ' ' + HTTP/X.X + '\r' + '\n'
#define REQUEST_LINE_SIZE MAX_METHOD_LENGTH + 1 + MAX_URI_LENGTH + 1 + 8 + 2

// name + ':' + value + '\r' + '\n'
#define HEADER_LINE_SIZE MAX_HEADER_NAME_SIZE + 1 + MAX_HEADER_VALUE_SIZE + 2

// request line + (header line * max header count) + '\r' + '\n'
#define REQUEST_SIZE REQUEST_LINE_SIZE + (HEADER_LINE_SIZE * MAX_COUNT_OF_HEADERS) + 2 + MAX_BODY_SIZE

bool rejectUnnecessaryBodies = true;

typedef struct _http_header_t
{
        char *name;
	char *value;
} http_header_t;

typedef struct _http_request_t {
        char *method;
        char *requestTarget;
        char *protocol;
        http_header_t *headers;
        int headerCount;
        char *body;
} http_request_t;

char* htmlAliveFile = NULL;
char* cssAliveFile = NULL;
char* htmlDeadFile = NULL;
char* cssDeadFile = NULL;

unsigned char sessionIdArray[255][SHA256_DIGEST_LENGTH*2+1] = {0};
time_t sessionIdTimestamp[255] = {0};
int sessionIdCount = 0;

// 0 alive
// 1 dead
int state = 0;
time_t timeSinceSwitch = {0};
FILE* logFile = NULL;

void log_init(char *fileName)
{
        logFile = fopen(fileName, "a");
        if(!logFile)
        {
                fprintf(stderr, "Unable to create log file");
                exit(1);
        }
}

void log_client(char *ip, int port) {

        fprintf(logFile, "%s:%u\n", ip, port);
}

void log_shutdown() {
        fclose(logFile);
}

char* crypto_make_hash(char* hash)
{
        char *result = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
                snprintf(result + (i*2), SHA256_DIGEST_LENGTH*2 + 1, "%02x", hash[i]);
        }
        return result;
}

char* crypto_generate_session_token(char *ip, char *username, int secret)
{
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        if(!context)
        {
                fprintf(stderr, "Cannot create OpenSSL context!\n");
                exit(1);
        }

        if(!EVP_DigestInit_ex(context, EVP_sha256(), NULL))
        {
                fprintf(stderr, "Cannot set up context to use digest\n");
                exit(1);
        }
        char secretBuf[4*8] = {0};
        snprintf(secretBuf, sizeof(secretBuf), "%d", secret);
        char *input = malloc(strlen(ip) + strlen(username) + strlen(secretBuf));
        if(!input)
        {
                fprintf(stderr, "Unable to allocate memory for input\n");
                exit(1);
        }

        strcpy(input, ip);
        strcat(input, username);
        strcat(input, secretBuf);

        //printf("SHA2 input: %s\n", input);
        if(!EVP_DigestUpdate(context, input, strlen(input)))
        {
                fprintf(stderr, "Unable to update digest with input\n");
                exit(1);
        }

        int hash_length = 0;
        char *result = malloc(SHA256_DIGEST_LENGTH*2);
        if(!EVP_DigestFinal_ex(context, result, &hash_length))
        {
                fprintf(stderr, "Failed to finalize digest\n");
                exit(1);
        }

        result = crypto_make_hash(result);

        EVP_MD_CTX_free(context);
        free(input);

        return result;
}

bool session_is_valid(char *sessionId)
{
        for(int i = 0; i < sessionIdCount; i++)
        {
                if(!strcmp(sessionIdArray[i], sessionId))
                {
                        printf("!!!!!!! time %lu %lu\n", sessionIdTimestamp[i], time(0));
                        if(difftime(time(0), sessionIdTimestamp[i]) < 60)
                        {
                                return true;
                        } else
                        {
                                strcpy(sessionIdArray[i], "");
                                sessionIdTimestamp[i] = 0;
                                return false;
                        }
                }
        }

        return false;
}

void session_add_id(char* sessionId)
{
        if(sessionIdCount + 1 > 255)
        {
                fprintf(stderr, "Session ID overflow");
                exit(1);
        }
        strcpy(sessionIdArray[sessionIdCount], sessionId);
        sessionIdTimestamp[sessionIdCount] = time(0);
        sessionIdCount++;
}


char* http_get_cookie(http_request_t *request, char* cookieName)
{
        char* cookieValue = NULL;
        char* cookieNameNew = malloc(strlen(cookieName)+2);

        strcpy(cookieNameNew, cookieName);
        strcat(cookieNameNew, "=");

        for(int i = 0; i < request->headerCount; i++)
        {
                if(!strcmp(request->headers[i].name, "Cookie")) { // TODO: name is case insensitive
                        cookieValue = strstr(request->headers[i].value, cookieNameNew);
                        cookieValue += strlen(cookieNameNew);
                        break;
                }
        }

        return cookieValue;
}

char* readFile(char *fileName)
{
        FILE *file = fopen(fileName, "r");
        fseek(file, 0, SEEK_END);
        int size = ftell(file);
        fseek(file, 0, SEEK_SET);
        char* buf = malloc(size);
        fread(buf, 1, size, file);
        fclose(file);

        return buf;

}

char* draw_admin_panel()
{
        char *panel_template = readFile("panel.html");
        int size = strlen(panel_template);

        char *panel = malloc(size + 64);
        memset(panel, 0, size + 64);

        if(timeSinceSwitch) {
                snprintf(panel, size + 64, panel_template, timeSinceSwitch, ctime(&timeSinceSwitch));
        } else {
                snprintf(panel, size + 64, panel_template, timeSinceSwitch, "Count down not on");
        }
        return panel;
}

char *clientResponseInfoClass[4] =
{
        "100 Continue",
        "101 Switching Protocols",
        "102 Processing",
        "103 Early Hints"
};

char *clientResponseSuccessClass[10] =
{
        "200 OK",
        "201 Created",
        "202 Accepted",
        "203 Non-Authoritative Information",
        "204 No Content",
        "205 Reset Content",
        "206 Partial Content",
        "207 Multi-Status",
        "208 Already Reported",
        "226 IM Used"
};

char *clientResponseRedirectionClass[9] =
{
        "300 Multiple Choices",
        "301 Moved Permanently",
        "302 Found",
        "303 See Other",
        "304 Not Modified",
        "305 Use Proxy",
        "306 unused",
        "307 Temporary Redirect",
        "308 Permanent Redirect"
};

char *clientResponseClientErrorClass[29] =
{
        "400 Bad Request",
        "401 Unauthorized",
        "402 Payment Required",
        "403 Forbidden",
        "404 Not Found",
        "405 Method Not Allowed",
        "406 Not Acceptable",
        "407 Proxy Authentication Required",
        "408 Request Timeout",
        "409 Conflict",
        "410 Gone",
        "411 Length Required",
        "412 Precondition Failed",
        "413 Content Too Large",
        "414 URI Too Long",
        "415 Unsupported Media Type",
        "416 Range Not Satisfiable",
        "417 Expectation Failed",
        "418 I'm a teapot",
        "421 Misdirected Request",
        "422 Unprocessable Content",
        "423 Locked",
        "424 Failed Dependency",
        "425 Too Early",
        "426 Upgrade Required",
        "428 Precondition Required",
        "429 Too Many Requests",
        "431 Request Header Fields Too Large",
        "451 Unavailable For Legal Reasons"
};

char *clientResponseServerErrorClass[11] =
{
        "500 Internal Server Error",
        "501 Not Implemented",
        "502 Bad Gateway",
        "503 Service Unavailable",
        "504 Gateway Timeout",
        "505 HTTP Version Not Supported",
        "506 Variant Also Negotiates",
        "507 Insufficient Storage",
        "508 Loop Detected",
        "510 Not Extended",
        "511 Network Authentication Required"
};

char *http_response_code_str(int code)
{
        if(code >= 100 && code <= 103)
                return clientResponseInfoClass[code - 100];

        if(code >= 200 && code <= 208)
                return clientResponseSuccessClass[code - 200];
        if(code == 226)
                return clientResponseSuccessClass[9];

        if(code >= 300 && code <= 308)
                return clientResponseRedirectionClass[code - 300];

        if(code >= 400 && code <= 418)
                return clientResponseClientErrorClass[code - 400];

        if(code >= 421 && code <= 426)
                return clientResponseClientErrorClass[code - 400 - 3];

        if(code >= 428 && code <= 429)
                return clientResponseClientErrorClass[code - 400 - 4];
        if(code == 431)
                return clientResponseClientErrorClass[27];
        if(code == 451)
                return clientResponseClientErrorClass[28];

        if(code >= 500 && code <= 508)
                return clientResponseServerErrorClass[code - 500];
        if(code >= 510 && code <= 511)
                return clientResponseServerErrorClass[code - 500 - 1];

        fprintf(stderr, "Invalid response code!\n");
        return NULL;
}

char * http_build_response(int code, char ***headers, int headerCount, char *body, size_t bodySize)
{
        char *responseCode = http_response_code_str(code);

        int totalLength = strlen(responseCode) + 11;
        if(headerCount > 0 && headers)
        {
                for(int i = 0; i < headerCount; i++)
                {
                        if(headers[i])
                        {
                                totalLength += strlen(headers[i]) + 2;
                        }
                }
        }
        if(body)
                //totalLength += strlen(body);
                totalLength += bodySize;

        totalLength++; // NUL terminating char

        char *response = malloc(totalLength);
        snprintf(response, totalLength, "HTTP/1.1 %s\r\n", responseCode);
        if(headerCount > 0 && headers)
        {
                for(int i = 0; i < headerCount; i++)
                {
                        if(headers[i])
                        {
                                strcat(response, headers[i]);
                                strcat(response, "\r\n");
                        }
                }
        }

        if(body)
        {
                strcat(response, "\r\n");
                strcat(response, body);
        }

        return response;
}

int http_parse_request(char *buf, int bytes, http_request_t *request)
{
        memset(request, 0, sizeof(http_request_t));
        request->method 	= malloc(MAX_METHOD_LENGTH	+ 1);
        request->requestTarget 	= malloc(MAX_URI_LENGTH		+ 1);
        request->protocol 	= malloc(8			+ 1);
        request->headers	= malloc(MAX_COUNT_OF_HEADERS * sizeof(http_header_t));
        request->body		= malloc(MAX_BODY_SIZE		+ 1);


        char *line = buf;
        char *next_line = strstr(buf, "\r\n");


    	size_t len;
	len = next_line - line;

        if(!next_line) 
		return 400; // Bad request

	if(len > REQUEST_LINE_SIZE-2)
		return 413; // content too large

        char request_line[REQUEST_LINE_SIZE] = {0};
        strncpy(request_line, line, len);

        if(sscanf(request_line, "%16s %8000s %8s\r\n", request->method, request->requestTarget, request->protocol) < 3)
	{
		return 400; // Bad request
	}

	if( !(!strcmp(request->method, "GET")
	||    !strcmp(request->method, "HEAD")
	||    !strcmp(request->method, "POST")
	||    !strcmp(request->method, "PUT")
	||    !strcmp(request->method, "DELETE")
	||    !strcmp(request->method, "CONNECT")
	||    !strcmp(request->method, "OPTIONS")
	||    !strcmp(request->method, "TRACE")
	||    !strcmp(request->method, "PATCH")) )
	{
		return 501; // not implemented
	}

	if(strcmp(request->protocol, "HTTP/1.1"))
		return 505;

        line = next_line + 2;
        while((next_line = strstr(line, "\r\n")) != NULL && next_line != line)
        {
                len = next_line - line;
                char header_line[MAX_HEADER_NAME_SIZE + 1 + MAX_HEADER_VALUE_SIZE] = {0};

		if(len > MAX_HEADER_NAME_SIZE + 1 + MAX_HEADER_VALUE_SIZE)
		{
			return 413; // content too large
		}
                strncpy(header_line, line, len);

                char *colon = strchr(header_line, ':');
                if(colon)
                {
			if((colon - header_line) > MAX_HEADER_NAME_SIZE || (next_line - colon) > MAX_HEADER_VALUE_SIZE)
				return 413; // content too large

			request->headers[request->headerCount].name = malloc(MAX_HEADER_NAME_SIZE + 1);
			request->headers[request->headerCount].value = malloc(MAX_HEADER_VALUE_SIZE + 1);

                        *colon = '\0';
                        char *key = header_line;
                        char *value = colon +1;

                        while(*value == ' ') value++;
                        strncpy(request->headers[request->headerCount].name, key, MAX_HEADER_NAME_SIZE + 1);
                        strncpy(request->headers[request->headerCount].value, value, MAX_HEADER_NAME_SIZE + 1);
                        request->headerCount++;
                } else { return 400; }

                line = next_line +2;
        }

	bool foundContentLength = false;
	int contentLength = 0;
	for(int i = 0; i < request->headerCount; i++)
	{
		char name[MAX_HEADER_NAME_SIZE + 1];
		memset(name, 0, MAX_HEADER_NAME_SIZE + 1 );
		strcpy(name, request->headers[i].name);
		for(int ii = 0; ii < strlen(name); ii++)
		{
			name[ii] = tolower(name[ii]);
		}		

		if(!strcmp(name, "content-length"))
		{
			foundContentLength = true;
			contentLength = strtol(request->headers[i].value, NULL, 10);
			break;
		}
	}

        if(strstr(line, "\r\n"))
        {	
		line = strstr(line, "\r\n") + 2;
		if(*line)
		{

			if(!foundContentLength)
				return 411; // length required
			if(contentLength == 0)
				return 0; // ignore	

			if(!strcmp(request->method, "POST") || !strcmp(request->method, "PUT") || !strcmp(request->method, "PATCH")) 
			{
				line = strstr(line, "\r\n") + 2;
                		strncpy(request->body, line, 1048576);
			} else
			if(!strcmp(request->method, "GET") 
			|| !strcmp(request->method, "HEAD") 
			|| !strcmp(request->method, "DELETE")
			|| !strcmp(request->method, "CONNECT")
			|| !strcmp(request->method, "OPTIONS")
			&& !rejectUnnecessaryBodies)
			{
				line = strstr(line, "\r\n") + 2;
                		strncpy(request->body, line, 1048576);
			} else {
				return 400; // should we reject or ignore?
			} 
		}

        }

        return 0;
}

char *buf;

bool http_handle_request(int client_fd, struct sockaddr_in client_address) {
        int bytes_read = 0;

        char *resp = malloc(REQUEST_SIZE); // TEMPORARY

        http_request_t request;
        int flag = 0;
        bool shutdown = false;

	if(!buf)
	{
		buf = malloc(REQUEST_SIZE);
		if(!buf)
		{
			fprintf(stderr, "Not enough memory to create a request buffer\n");
			exit(1);
		}
	}

        memset(buf, 0, REQUEST_SIZE);

read:
        bytes_read = read(client_fd, buf, REQUEST_SIZE);

        if(bytes_read < 0)
        {
                if(errno == EAGAIN) {
                        if(flag) {
                                perror("Client timeout\n");
                                close(client_fd);
                                return;
                        }
                        sleep(1);
                        flag++;
                        goto read;
                } else {
                        fprintf(stderr, "Read from client failed, %s\n", strerror(errno));
                        close(client_fd);
                        return;
                }
        }

        if(bytes_read == 0)
        {
                fprintf(stderr, "Client disconnected\n");
                close(client_fd);
                return;
        }

        printf("Received HTTP request:\n%s\n", buf);
        int parse_response = http_parse_request(buf, bytes_read, &request);
        if(parse_response > 0) {
                //form response
		resp = http_build_response(parse_response, NULL, 0, NULL, 0);
        }

        if(strcmp(request.method, "GET") && strcmp(request.method, "POST"))
        {
                // form response 501
		resp = http_build_response(501, NULL, 0, NULL, 0);
        }

        if(strcmp(request.protocol, "HTTP/1.1"))
        {
                // form response 505
                resp = http_build_response(505, NULL, 0, NULL, 0);
        }

        if(strcmp(request.requestTarget, "/")
        && strcmp(request.requestTarget, "/index.html")
        && strcmp(request.requestTarget, "/style.css")
        && strcmp(request.requestTarget, "/admin-secret/switch")
        && strcmp(request.requestTarget, "/admin-secret/shutdown")
        && strcmp(request.requestTarget, "/admin-secret/panel"))
        {
                // form response 404
                resp = http_build_response(404, NULL, 0, NULL, 0);
        }
	printf("SUCCESSFUL PARSE!!!!\n");
        if(!resp[0] && !strcmp(request.method, "GET"))
        {

                if(!strcmp(request.requestTarget, "/") || !strcmp(request.requestTarget, "/index.html"))
                {
                const char *resp_template =
                                "HTTP/1.1 200 OK\r\n"
                                "Server: GabijaServer\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: %lu\r\n"
                                "\r\n%s";
		printf("PREPARING RESPONSE!\n");
                char* htmlAliveFile = readFile("index.html");
                char* htmlDeadFile = readFile("dead.html");
                // 86400 - 1 day
                if(difftime(time(NULL), timeSinceSwitch) < 86400 || !timeSinceSwitch) snprintf(resp, REQUEST_SIZE, resp_template, strlen(htmlAliveFile), htmlAliveFile);
                else snprintf(resp, REQUEST_SIZE, resp_template, strlen(htmlDeadFile), htmlDeadFile);

                } else if (!strcmp(request.requestTarget, "/style.css")){
                const char *resp_template =
                                "HTTP/1.1 200 OK\r\n"
                                "Server: GabijaServer\r\n"
                                "Content-Type: text/css\r\n"
                                "Content-Length: %lu\r\n"
                                "\r\n%s";
                char* cssAliveFile = readFile("style.css");
                char* cssDeadFile = readFile("dead-style.css");

                if(difftime(time(NULL), timeSinceSwitch) < 86400 || !timeSinceSwitch) snprintf(resp, REQUEST_SIZE, resp_template, strlen(cssAliveFile), cssAliveFile);
                else snprintf(resp, REQUEST_SIZE, resp_template, strlen(cssDeadFile), cssDeadFile);

                } else if(!strcmp(request.requestTarget, "/admin-secret/panel")) {
                const char *resp_template =
                                "HTTP/1.1 200 OK\r\n"
                                "Server: GabijaServer\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: %lu\r\n"
                                "\r\n%s";
                char *panel;
                char *sessionId = http_get_cookie(&request, "sessionId");

                panel = readFile("panel_auth.html");
                snprintf(resp, REQUEST_SIZE, resp_template, strlen(panel), panel);
                if(sessionId) {
                        if(session_is_valid(sessionId))
                        {
                                printf("SESSION WAS VALID! %u\n", session_is_valid(sessionId));
                                panel = draw_admin_panel();
                        }
                }

                snprintf(resp, REQUEST_SIZE, resp_template, strlen(panel), panel);

                }

                //printf("Response:\n%s\n", resp);
        } else if(!resp[0] && !strcmp(request.method, "POST")) {
                if(!strcmp(request.requestTarget, "/admin-secret/panel")) {
                        char* username[256] = {0};
                        char* password[256] = {0};


                        char* uname_start = strstr(request.body, "uname=");
                        char* pass_start = strstr(request.body, "&password=");

                        //printf("body: %s\n%p %p\n", request.body, uname_start, pass_start);

                        if(uname_start && pass_start)
                        {
                                uname_start += 6;
                                strncpy(username, uname_start, pass_start - uname_start);
                                username[pass_start - uname_start] = '\0';

                                pass_start += 10;
                                strcpy(password, pass_start);

                                if(strcmp(username, "gabijaba3") || strcmp(password, "cipsas58746"))
                                {
                                        snprintf(resp, sizeof(resp), "HTTP/1.1 403 Forbidden\r\n");
                                } else {
                                        const char *resp_template =     "HTTP/1.1 200 OK\r\n"
                                                                "Server: GabijaServer\r\n"
                                                                "Content-Type: text/html\r\n"
                                                                "Set-Cookie: sessionId=%s\r\n"
                                                                "Content-Length: %lu\r\n"
                                                                "\r\n%s";
                                        char *panel = draw_admin_panel();


                                        //unsigned char sessionId[SHA256_DIGEST_LENGTH*2] = {0};
                                        srand(time(0));
                                        int secret = rand();
                                        char* sessionId = crypto_generate_session_token(inet_ntoa(client_address.sin_addr), username, secret);
                                        session_add_id(sessionId);

                                        snprintf(resp, REQUEST_SIZE, resp_template, sessionId, strlen(panel), panel);
                                }
                        } else {
                                snprintf(resp, sizeof(resp), "HTTP/1.1 400 Bad Request\r\n");
                        }
                } else if(!strcmp(request.requestTarget, "/admin-secret/shutdown")) {
                        char *sessionId = http_get_cookie(&request, "sessionId");
                        printf("!!!! entered !!!!!");
                        if(sessionId)
                        {
                                if(session_is_valid(sessionId))
                                {
                                        const char *resp_template =
                                        "HTTP/1.1 200 OK\r\n"
                                        "Server: GabijaServer\r\n"
                                        "Content-Type: text/plain\r\n"
                                        "Content-Length: %lu\r\n"
                                        "\r\n%s";
                                        char *msg = "Performing server shutdown!";
                                        snprintf(resp, sizeof(resp), resp_template, strlen(msg), msg);

                                        shutdown = true;
                                } else {
                                        const char *resp_template =
                                        "HTTP/1.1 200 OK\r\n"
                                        "Server: GabijaServer\r\n"
                                        "Content-Type: text/html\r\n"
                                        "Content-Length: %lu\r\n"
                                        "\r\n%s";
                                        char *panel = readFile("panel_auth.html");
                                        snprintf(resp, sizeof(resp), resp_template, strlen(panel), panel);
                                }
                        } else {
                                const char *resp_template =
                                "HTTP/1.1 200 OK\r\n"
                                "Server: GabijaServer\r\n"
                                "Content-Type: text/html\r\n"
                                "Content-Length: %lu\r\n"
                                "\r\n%s";
                                char *panel = readFile("panel_auth.html");
                                snprintf(resp, sizeof(resp), resp_template, strlen(panel), panel);

                        }
                } else if(!strcmp(request.requestTarget, "/admin-secret/switch")) {
                        char *sessionId = http_get_cookie(&request, "sessionId");
                        if(sessionId)
                        {
                                if(session_is_valid(sessionId))
                                {
                                        const char *resp_template =
                                        "HTTP/1.1 200 OK\r\n"
                                        "Server: GabijaServer\r\n"
                                        "Refresh: 1; url=/admin-secret/panel\r\n"
                                        "Content-Type: text/plain\r\n"
                                        "Content-Length: %lu\r\n"
                                        "\r\n%s";
                                        char *msg = "Switching server state!";
                                        snprintf(resp, sizeof(resp), resp_template, strlen(msg), msg);

                                        if(timeSinceSwitch)
                                        {
                                                timeSinceSwitch = 0;

                                        } else {
                                                timeSinceSwitch = time(NULL);
                                        }


                                        //if(state) state = 0;
                                        //else state = 1;
                                } else {
                                        const char *resp_template =
                                        "HTTP/1.1 200 OK\r\n"
                                        "Server: GabijaServer\r\n"
                                        "Content-Type: text/html\r\n"
                                        "Content-Length: %lu\r\n"
                                        "\r\n%s";
                                        char *panel = readFile("panel_auth.html");
                                        snprintf(resp, sizeof(resp), resp_template, strlen(panel), panel);
                                }
                        } else {
                                const char *resp_template =
                                        "HTTP/1.1 200 OK\r\n"
                                        "Server: GabijaServer\r\n"
                                        "Content-Type: text/html\r\n"
                                        "Content-Length: %lu\r\n"
                                        "\r\n%s";
                                char *panel = readFile("panel_auth.html");
                                snprintf(resp, sizeof(resp), resp_template, strlen(panel), panel);
                        }
                }
        }


	printf("Response:\n%s\n", resp);
        if(write(client_fd, resp, strlen(resp)) < 0)
        {
                fprintf(stderr, "Error sending HTTP response to client, %s\n", strerror(errno));
        }

        close(client_fd);
        if(shutdown) return true;
        return false;
}

int main(int argc, char **argv)
{
        int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        int conn_fd = 0;
        struct sockaddr_in address;

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(80);

        log_init("clients.txt");

        if(bind(sock_fd, (struct sockaddr*)&address, sizeof(address)))
        {
                perror("Failure to bind");
                fprintf(stderr, "Failure to bind: %s\n", strerror(errno));
                exit(1);
        }

        if(listen(sock_fd, 10))
        {
                fprintf(stderr, "Failure to listen: %s\n", strerror(errno));
                exit(1);
        }

        printf("Server is listening on port %u\n", 80);

        while(1) {
                struct sockaddr_in client_address;
                socklen_t addr_len = sizeof(address);
                conn_fd = accept(sock_fd, (struct sockaddr*)&client_address, &addr_len);
                if(conn_fd < 0)
                {
                        fprintf(stderr, "Failure to accept: %s\n", strerror(errno));
                        continue;
                }

                int flags = fcntl(conn_fd, F_GETFL, 0);
                fcntl(conn_fd, F_SETFL, flags | O_NONBLOCK);

                struct in_addr banned_ip;
                inet_aton("00.000.00.000", &banned_ip);
                if(client_address.sin_addr.s_addr == banned_ip.s_addr)
                {
                        //close(conn_fd);
                        //continue;
                }

                log_client(inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
                printf("Accepted connection from %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
                if(http_handle_request(conn_fd, client_address))
                {
                        break;
                }
        }

        log_shutdown();
        close(sock_fd);



}
