
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "tcpcom.h"

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

typedef struct
{
    SOCKET ConnectSocket;
} tcpcom_ctx;

#define DEFAULT_BUFLEN 2048

static void tcpcom_free(void** ctx)
{
    if (ctx) {
        free(*(tcpcom_ctx**)ctx);
        *ctx = NULL;
    }
}

int tcpcom_init(void** ctx, const char* address, const char* port)
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL,
        * ptr = NULL,
        hints;
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;
    timeval recvtmout;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %x\n", iResult);
        return -1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(address, port, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %x\n", iResult);
        WSACleanup();
        return -1;
    }

#if 0
    printf("AF_INET:%d, AF_INET6:%d, SOCK_STREAM:%d, IPPROTO_TCP:%d, IPPROTO_UDP:%d\n", AF_INET, AF_INET6, SOCK_STREAM, IPPROTO_TCP, IPPROTO_UDP);
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        printf("af:%d type:%d protocol:%d\n", ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
    }
#endif

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %u\n", WSAGetLastError());
            WSACleanup();
            return -1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return -1;
    }

#if 1
    BOOL bOptVal = TRUE;
    int bOptLen = sizeof(BOOL);
    iResult = setsockopt(ConnectSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&bOptVal, bOptLen);
    if (iResult == SOCKET_ERROR) {
        printf("setsockopt for TCP_NODELAY failed with error: %u\n", WSAGetLastError());
    }
#endif

    *ctx = malloc(sizeof(tcpcom_ctx));
    if (*ctx == NULL) return -2;
    ((tcpcom_ctx*)*ctx)->ConnectSocket = ConnectSocket;

    return 0;
}

int tcpcom_request(void **ctx, const char *sendbuf, int senbufsz, uint32_t *timespent)
{
    SOCKET ConnectSocket = INVALID_SOCKET;
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;
    timeval recvtmout;

    if (ctx && *ctx)
        ConnectSocket = ((tcpcom_ctx*)*ctx)->ConnectSocket;

    if (ConnectSocket == INVALID_SOCKET)
        return -1;

    //SENDING
    iResult = send(ConnectSocket, sendbuf, senbufsz, 0);
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %u\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        tcpcom_free(ctx);
        return -1;
    }
    //printf("Bytes Sent: %ld\n", iResult);

#if 0
    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %u\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        tcpcom_free(ctx);
        return -1;
    }
#endif

    LARGE_INTEGER start, end;
    QueryPerformanceFrequency(&start);
    double freq = start.QuadPart/1000;
    QueryPerformanceCounter(&start);

    //RECEIVING
    recvtmout.tv_sec = 5;
    recvtmout.tv_usec = 0;
    int count = 0;
    int first = 1;
    memset(recvbuf, 0, recvbuflen);
    // Receive until the peer closes the connection
    do {
        char byte;
        fd_set fds;
        fds.fd_count = 1;
        fds.fd_array[0] = ConnectSocket;
        iResult = select(fds.fd_count, &fds, NULL, NULL, &recvtmout);
        if (iResult == SOCKET_ERROR)
        {
            printf("select failed with error: %u\n", WSAGetLastError());
            break;
        }
        if (iResult == 0)
        {
            //timelimit expired; we are finished reading the input
            break;
        }

        if (first)
        {
            first = 0;
            QueryPerformanceCounter(&end);
            //now that we started receiving set a lower timeout
            recvtmout.tv_sec = 0;
            recvtmout.tv_usec = 0; // multiply by 1000 for milliseconds
        }

        iResult = recv(ConnectSocket, recvbuf, recvbuflen - 1, 0);
        if (iResult > 0)
        {
            //recvbuf[count++] = byte;
            //if (count >= recvbuflen - 1)
            {
                break;
            }
        }
        else if (iResult == 0)
        {
            printf("Connection closed\n");
            closesocket(ConnectSocket);
            WSACleanup();
            tcpcom_free(ctx);
            return -1;
        }
        else
        {
            printf("recv failed with error: %u\n", WSAGetLastError());
            closesocket(ConnectSocket);
            WSACleanup();
            tcpcom_free(ctx);
            return -1;
        }

    } while (iResult > 0);

    if (first)
    {
        first = 0;
        QueryPerformanceCounter(&end);
        printf("No data received\n");
        return -1;
    }
    uint64_t timediff = (end.QuadPart - start.QuadPart)/freq;
    *timespent = timediff;

    //Sleep(50);

    //printf("%d %d\n", count, (uint32_t)timediff);

    //printf("Received:\n%s\ntimediff:%lld\n", recvbuf, timediff);

    return 0;
}

void tcpcom_close(void** ctx)
{
    SOCKET ConnectSocket = INVALID_SOCKET;

    if (ctx && *ctx)
        ConnectSocket = ((tcpcom_ctx*)*ctx)->ConnectSocket;

    if (ConnectSocket == INVALID_SOCKET)
        return;

    closesocket(ConnectSocket);
    WSACleanup();
    tcpcom_free(ctx);
}

struct serverthread_param
{
    SOCKET socket;
    tcpcom_incoming_message_cb client_cb;
};
DWORD WINAPI ServerThread(LPVOID lpParam);

int tcpcom_server(const char* address, const char* port, tcpcom_incoming_message_cb cb)
{
    int funcret = 0;
    struct addrinfo  hints,
        * results = NULL,
        * addrptr = NULL;
    WSADATA     wsaData;
    SOCKET server_socket = NULL;
    HANDLE server_thread = NULL;
    char        hoststr[NI_MAXHOST],
        servstr[NI_MAXSERV];
    const char* interface = address;
    int         socket_type = SOCK_STREAM,
        address_family = AF_INET;
    int retval;
    struct serverthread_param* tprm = NULL;

    if ((retval = WSAStartup(0x202, &wsaData)) != 0)
    {
        fprintf(stderr, "WSAStartup failed with error %d\n", retval);
        WSACleanup();
        return -1;
    }

    // Make sure the supplied port isn't wildcard
    if (_strnicmp(port, "0", 1) == 0)
    {
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = address_family;
    hints.ai_socktype = socket_type;
    hints.ai_protocol = ((socket_type == SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP);
    // If interface is NULL then request the passive "bind" address
    hints.ai_flags = ((interface == NULL) ? AI_PASSIVE : 0);

    retval = getaddrinfo(interface, port, &hints, &results);
    if (retval != 0)
    {
        fprintf(stderr, "getaddrinfo failed: %d\n", retval);
        goto cleanup;
    }

    // Make sure we got at least one address back
    if (results == NULL)
    {
        fprintf(stderr, "Unable to resolve interface %s\n", interface);
        goto cleanup;
    }

    addrptr = results;

    server_socket = socket(
        addrptr->ai_family,
        addrptr->ai_socktype,
        addrptr->ai_protocol);
    if (server_socket == INVALID_SOCKET)
    {
        fprintf(stderr, "socket failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    // Bind the socket to the address returned
    retval = bind(server_socket,
        addrptr->ai_addr,
        (int)addrptr->ai_addrlen);
    if (retval == SOCKET_ERROR)
    {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    // If a TCP socket, call listen on it
    if (addrptr->ai_socktype == SOCK_STREAM)
    {
        retval = listen(server_socket, 7);
        if (retval == SOCKET_ERROR)
        {
            fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
            goto cleanup;
        }
    }

    // Print the address this socket is bound to
    retval = getnameinfo(
        addrptr->ai_addr,
        (socklen_t)addrptr->ai_addrlen,
        hoststr,
        sizeof(hoststr),
        servstr,
        sizeof(servstr),
        NI_NUMERICHOST | NI_NUMERICSERV);
    if (retval != 0)
    {
        fprintf(stderr, "getnameinfo failed: %d\n", retval);
        goto cleanup;
    }

    fprintf(stdout, "socket 0x%x bound to address %s and port %s\n",
        (int)server_socket, hoststr, servstr);

    tprm = (struct serverthread_param*)malloc(sizeof(struct serverthread_param));
    if (!tprm) goto cleanup;

    tprm->socket = server_socket;
    tprm->client_cb = cb;

    server_thread = CreateThread(
        NULL,
        0,
        ServerThread,
        (LPVOID)tprm,
        0,
        NULL);
    if (server_thread == NULL)
    {
        fprintf(stderr, "CreateThread failed: %d\n", GetLastError());
        goto cleanup;
    }

cleanup:

    if (results != NULL)
    {
        freeaddrinfo(results);
        results = NULL;
    }

    return funcret;
}

const char http_date[] = "DAY__DD_MMM_YYYY_HH_MM_SS";

static DWORD WINAPI ServerThread(LPVOID lpParam)
{
    SOCKET           server_socket,                     // Server socket
        sc = INVALID_SOCKET;   // Client socket (TCP)
    SOCKADDR_STORAGE from;
    char servstr[NI_MAXSERV],
        hoststr[NI_MAXHOST];
    int              socket_type,
        retval,
        fromlen,
        bytecount;
    char datebuf[sizeof(http_date)];

    membuf in = MEMBUF_INITIALISER;
    membuf out = MEMBUF_INITIALISER;
    membuf_adjust_size(&in, DEFAULT_BUFLEN);

    struct serverthread_param* tprm = (struct serverthread_param*)lpParam;
    // Retrieve the socket handle
    server_socket = tprm->socket;

    // Get the socket type back
    fromlen = sizeof(socket_type);
    retval = getsockopt(server_socket, SOL_SOCKET, SO_TYPE, (char*)&socket_type, &fromlen);
    if (retval == INVALID_SOCKET)
    {
        fprintf(stderr, "tcpsrv getsockopt(SO_TYPE) failed: %d\n", WSAGetLastError());
        goto cleanup;
    }

    for (;;)
    {
        fromlen = sizeof(from);

        if (socket_type == SOCK_STREAM)
        {
            if (sc != INVALID_SOCKET)
            {
                //
                // If we have a client connection recv and send until done
                //
                bytecount = recv(sc, (char*)in.data, in.size, 0);
                if ((bytecount == SOCKET_ERROR) || (bytecount == 0))
                {
                    // Client connection was closed
                    retval = shutdown(sc, SD_SEND);
                    if (retval == SOCKET_ERROR)
                    {
                        fprintf(stderr, "tcpsrv shutdown failed: %d\n", WSAGetLastError());
                        //goto cleanup;
                    }

                    closesocket(sc);
                    sc = INVALID_SOCKET;
                }
                else
                {
                    //printf("tcpsrv read %d bytes\n", bytecount);
                    in.used = bytecount;

                    int cbret = tprm->client_cb(&in, &out);

                    char* dtag = strstr((char*)out.data, http_date);
                    if (dtag)
                    {
                        time_t now;
                        struct tm dt;
                        time(&now);
                        gmtime_s(&dt, &now);
                        //DAY__DD_MMM_YYYY_HH_MM_SS
                        size_t sz = strftime(datebuf, sizeof(datebuf), "%a, %d %b %Y %H:%M:%S", &dt);
                        if(sz == strlen(http_date))
                            memcpy(dtag, datebuf, sz);
                    }

                    bytecount = send(sc, (char*)out.data, out.used, 0);
                    if (bytecount == SOCKET_ERROR)
                    {
                        fprintf(stderr, "tcpsrv send failed: %d\n", WSAGetLastError());
                        //client socket will be closed
                        if(cbret == TCPCOM_RETVAL_CONTINUE)
                            cbret = TCPCOM_RETVAL_CLOSE;
                    }
                    else
                    {
                        //printf("wrote %d bytes\n", bytecount);
                    }

                    if (cbret < TCPCOM_RETVAL_CONTINUE)
                    {
                        // Close connection
                        retval = shutdown(sc, SD_SEND);
                        if (retval == SOCKET_ERROR)
                        {
                            fprintf(stderr, "tcpsrv shutdown failed: %d\n", WSAGetLastError());
                            //goto cleanup;
                        }

                        closesocket(sc);
                        sc = INVALID_SOCKET;

                        if (cbret == TCPCOM_RETVAL_FINISHED)
                        {
                            goto cleanup;
                        }
                    }
                }
            }
            else
            {
                //
                // No client connection so wait for one
                //
                sc = accept(server_socket, (SOCKADDR*)&from, &fromlen);
                if (sc == INVALID_SOCKET)
                {
                    fprintf(stderr, "tcpsrv accept failed: %d\n", WSAGetLastError());
                    goto cleanup;
                }

                // Display the client's address
                retval = getnameinfo(
                    (SOCKADDR*)&from,
                    fromlen,
                    hoststr,
                    NI_MAXHOST,
                    servstr,
                    NI_MAXSERV,
                    NI_NUMERICHOST | NI_NUMERICSERV
                );
                if (retval != 0)
                {
                    fprintf(stderr, "tcpsrv getnameinfo failed: %d\n", retval);
                    goto cleanup;
                }

                printf("Accepted connection from host %s and port %s\n",
                    hoststr, servstr);
            }
        }
        else
        {
        fprintf(stderr, "tcpsrv unsupported socket_type %d\n", socket_type);
            break;
        }
    }

cleanup:

    // Close the client connection if present
    if (sc != INVALID_SOCKET)
    {
        closesocket(sc);
        sc = INVALID_SOCKET;
    }

    if (server_socket != INVALID_SOCKET)
    {
        closesocket(server_socket);
        server_socket = INVALID_SOCKET;
    }

    free(tprm);
    membuf_free(&in);
    membuf_free(&out);

    printf("\ntcpsrv thread exiting\n");

    return 0;
}
