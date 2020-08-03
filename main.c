// ===================================================================================  //
//    This program is free software: you can redistribute it and/or modify              //
//    it under the terms of the GNU General Public License as published by              //
//    the Free Software Foundation, either version 3 of the License, or                 //
//    (at your option) any later version.                                               //
//                                                                                      //
//    This program is distributed in the hope that it will be useful,                   //
//    but WITHOUT ANY WARRANTY; without even the implied warranty of                    //
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                     //
//    GNU General Public License for more details.                                      //
//                                                                                      //
//    You should have received a copy of the GNU General Public License                 //
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.            //
//                                                                                      //
//    Copyright: Luiz Gustavo Pfitscher e Feldmann, 2020                                //
// ===================================================================================  //

#include "dns_protocol.h"
#include <winsock2.h>
#include <stdio.h>
#include <conio.h>

SOCKET local_name_server;
SOCKET remote_name_server;

void ReceivedQuery(const char* dgram, int length, struct sockaddr_in query_addr)
{
    char *ip = inet_ntoa(query_addr.sin_addr);
    printf("\nLocal nameserver got query from %s: ", ip);

    // relay query to remote nameserver
    send(remote_name_server, dgram, length, 0);
}

void ReceivedAnswer(const char* dgram, int length)
{
    printf("\n\n\nRemote nameserver provided answer:");

    dns_transaction_t* tra = read_dns_transaction(dgram, length);
    if (tra == NULL)
        return;

    printf("\nDatagram read success!");

    //print_dns_transaction(tra);

    free_dns_transaction(tra);
}

int ConfigSocket(SOCKET* sock, u_long ip, int bConnect)
{
    static const char enableReuse = 1;
    if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(enableReuse)) < 0)
    {
        fprintf(stderr, "\nsetsockopt(SO_REUSEADD) failed");
        return SOCKET_ERROR;
    }

    static u_long nonBlockingMode = 1;
    if (ioctlsocket(*sock, FIONBIO, &nonBlockingMode) != NO_ERROR)
    {
        fprintf(stderr, "\nioctlsocket failed changing (non)blocking mode to %lu", nonBlockingMode);
        return SOCKET_ERROR;
    }

    if (ip != INADDR_NONE)
    {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(53); // dns port is 53
        addr.sin_addr.s_addr = ip;

        if (bConnect)
        {
            if (connect(*sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
            {
                fprintf(stderr, "\nconnect() failed: %d", WSAGetLastError());
                return SOCKET_ERROR;
            }
            else
                printf("\nconnect() is OK!");
        }
        else
        {
            if (bind(*sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
            {
                fprintf(stderr, "\nbind() failed: %d", WSAGetLastError());
                return SOCKET_ERROR;
            }
            else
                printf("\nbind() is OK!");
        }
    }

    return 0;
}

int main(int argc, char** argv)
{
    // init winsock
    WSADATA wsaData;

    if( WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
    {
        fprintf(stderr, "\nWSAStartup failed: %d\n", WSAGetLastError());
        return -1;
    }
    else
        printf("\nWinsock DLL is %s.\n", wsaData.szSystemStatus);

    // create our sockets
    local_name_server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    remote_name_server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // create name server listener socket
    if (ConfigSocket(&local_name_server, ADDR_ANY, 0) == SOCKET_ERROR)
        goto bail;

    // create fallback nameserver socket
    if (ConfigSocket(&remote_name_server, inet_addr("192.168.99.1"), 1) == SOCKET_ERROR)
        goto bail;

    // loop receiving
    static fd_set read_flags;
    static struct timeval waitd = {1, 0}; // check for close every 1 sec

    #define BUFFLEN 1024
    const int buffer_len = BUFFLEN;

    printf("\nListening...");
    while (!kbhit())
    {
        FD_ZERO(&read_flags);
        FD_SET(local_name_server, &read_flags);
        FD_SET(remote_name_server, &read_flags);

        int sel = select(0, &read_flags, NULL, NULL, &waitd);
        if (sel < 0)
        {
            fprintf(stderr, "\nSocket error: %d", WSAGetLastError());
            break;
        }
        else if (sel == 0)
            continue; // timed-out

        if (FD_ISSET(local_name_server, &read_flags)) // check if local server received a query
        {
            char buffer[BUFFLEN];

            // socket ready to read!!!
            struct sockaddr_in query_addr;
            static int addrsize = sizeof(query_addr);

            int recvlen = recvfrom(local_name_server, buffer, buffer_len, 0, (SOCKADDR*)&query_addr, &addrsize);
            if (recvlen == SOCKET_ERROR)
            {
                fprintf(stderr, "\nSocket error on recvfrom: %d", WSAGetLastError());
            }
            else
            {
                ReceivedQuery(buffer, recvlen, query_addr);
            }
        }

        if (FD_ISSET(remote_name_server, &read_flags)) // check if remote server provided a response
        {
            char buffer[BUFFLEN];

            int recvlen = recv(remote_name_server, buffer, buffer_len, 0);
            if (recvlen == SOCKET_ERROR)
            {
                fprintf(stderr, "\nSocket error on recvfrom: %d", WSAGetLastError());
            }
            else
            {
                ReceivedAnswer(buffer, recvlen);
            }
        }
    }

    // cleanup
    bail:
    closesocket(local_name_server);
    closesocket(remote_name_server);
    WSACleanup();
    return 0;
}
