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
#include "zone_file.h"
#include "llist.h" // simple linked list libray - get liblist at https://github.com/mellowcandle/liblist

SOCKET local_name_server;
SOCKET remote_name_server;

dns_answer_t* dns_record_collection = NULL;
unsigned int dns_record_count = 0;


typedef struct delegate_request {
    uint16_t id;
    struct sockaddr_in query_source;
} delegate_request_t;

llist delegate_requests_list;

void ReceivedQuery(const char* dgram, int length, struct sockaddr_in query_addr)
{
    // log the query
    printf("\n\n\nLocal nameserver got query from %s: ", inet_ntoa(query_addr.sin_addr));

    // read the request
    dns_transaction_t* query = read_dns_transaction(dgram, length);

    if (!query)
        return;
    //else
    //    print_dns_transaction(query);

    // look for a match in the records
    dns_transaction_t* reply = build_dns_reply_from_query(query, dns_record_collection, dns_record_count);

    if (!reply)
    {
        // no matches found
        // relay query to remote nameserver

        delegate_request_t* entry = (delegate_request_t*)malloc(sizeof(delegate_request_t)); // keep track of what IP originated this query so we know who to send the reply we'll get later
        *entry = (delegate_request_t){
            .id = query->header.id,
            .query_source = query_addr,
            };


        if (llist_push(delegate_requests_list, entry) == LLIST_SUCCESS)
        {
            if (send(remote_name_server, dgram, length, 0) != SOCKET_ERROR)
                printf("\nNo matches found: relaying request to backup server...");
            else
                fprintf(stderr, "\nError forwarding request: %d", WSAGetLastError());
        }
    }
    else
    {
        // match was found :)
        print_dns_transaction(reply);

        char out_buff[512];
        int len = write_dns_transaction(out_buff, 256, reply);

        //printf("\nbuffer length is %d", len);

        if (sendto(local_name_server, out_buff, len, 0, (SOCKADDR*)&query_addr, sizeof(query_addr)) == SOCKET_ERROR)
            fprintf(stderr, "\nError trying to send reply: %d", WSAGetLastError());
    }

    free(reply);
    free(query);
}

void ReceivedAnswer(const char* dgram, int length)
{
    printf("\n\n\nRemote nameserver provided answer:");

    // get the reply from the server
    dns_transaction_t* remote_reply = read_dns_transaction(dgram, length);
    if (remote_reply == NULL)
        return;
    else
        print_dns_transaction(remote_reply);

    // find which IP Address must receive the reply based on it's ID
    void find_func(llist_node node)
    {
        delegate_request_t* entry = (delegate_request_t*)node;

        if (entry->id != remote_reply->header.id)
            return;

        if (sendto(local_name_server, dgram, length, 0, (SOCKADDR*)&entry->query_source, sizeof(entry->query_source)) != SOCKET_ERROR)
            printf("\nReply forwarded to %s", inet_ntoa(entry->query_source.sin_addr));
        else
            fprintf(stderr, "\nError trying to forward reply (id %u) back to IP %s : error code %d", remote_reply->header.id, inet_ntoa(entry->query_source.sin_addr),  WSAGetLastError());

        llist_delete_node(delegate_requests_list, node, 1, NULL);
    }
    llist_for_each(delegate_requests_list, find_func);

    free_dns_transaction(remote_reply);
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
    // create a list of
    delegate_requests_list = llist_create(NULL, NULL, 0);

    // read our records
    dns_record_count = read_zone_file("config.txt", &dns_record_collection);
    print_records_collection(dns_record_collection, dns_record_count);

    // init winsock
    WSADATA wsaData;

    if( WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
    {
        fprintf(stderr, "\nWSAStartup failed: %d\n", WSAGetLastError());
        goto bail;
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
    free(dns_record_collection);
    llist_destroy(delegate_requests_list, 1, NULL);

    return 0;
}
