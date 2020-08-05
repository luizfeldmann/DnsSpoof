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
#include <string.h>

// UTILITY
// ================================================================
char* read_dns_name(const char* dgram_start, const char* name_start, char* destination)
{
    // sanity check
    if(name_start == NULL || destination == NULL)
        return NULL;

    // clear destination
    strcpy(destination, "");

    char* currPtr = (char*)name_start;
    uint8_t label_len;

    do
    {
        label_len = *((uint8_t*)currPtr);
        currPtr++;

        if (label_len == 0)
            break; // end of string
        else if (label_len >= 0xC0)
        {
            if (dgram_start == NULL) // cannot parse pointer if no reference to beginning of message
                break;

            // pointer
            uint16_t pointer = *((uint8_t*)currPtr) + (label_len & 0b00111111)*255; // pointer is 14 bit long comprised of the "label-length" plus one more byte
            currPtr++;

            char pointer_labels[QNAME_SIZE] = "";
            read_dns_name(dgram_start, (char*)(dgram_start + pointer), pointer_labels);

            strcat(destination, pointer_labels);
            strcat(destination, ".");

            break;
        }
        else
        {
            // text
            char label[64] = "";
            sprintf(label, "%.*s", label_len, currPtr);
            currPtr += label_len;
            strcat(destination, label);
            strcat(destination, ".");
        }
    } while (label_len > 0);

    return currPtr;
}

int domain_plain_to_label(const char* name, char *label_buff)
{
    // sanity check
    if (label_buff == NULL)
        return 0;

    // start clear
    strcpy(label_buff, "");

    // another check
    if (name == NULL)
        return 0;

    // function to append character to string
    void chrcat(char* appendTo, char c)
    {
      size_t len = strlen(appendTo);
      appendTo[len] = c;
      appendTo[len + 1] = '\0';
    }

    uint8_t i;
    uint8_t curr_label_len;
    uint8_t full_name_len = strlen(name);
    char curr_label[64] = "";

    for (i = 0, curr_label_len = 0; i < full_name_len; i++)
    {
        char c = name[i];

        if (c == '.')
        {
            chrcat(label_buff, curr_label_len);
            strcat(label_buff, curr_label);

            // zero the current label
            strcpy(curr_label, "");
            curr_label_len = 0;
        }
        else
        {
            chrcat(curr_label, c);
            curr_label_len++;
        }
    }

    return strlen(label_buff) + 1; // return the length of the label-formated data
}

char* getTypeString(uint16_t _type)
{
    switch (_type)
    {
        case DNS_TYPE_A:     return "A - Host address"; break;
        case DNS_TYPE_NS:    return "NS - Authoritative name server"; break;
        case DNS_TYPE_CNAME: return "CNAME - Canonical name"; break;
        case DNS_TYPE_MX:    return "MX - Mail exchange"; break;
        case DNS_TYPE_TXT:   return "TXT - Text"; break;
        case DNS_TYPE_PTR:   return "PTR - Domain name pointer"; break;
        case DNS_TYPE_AAAA:  return "AAAA - IPv6 record"; break;
    }

    return "Unknown";
}

char* getClassString(uint16_t _class)
{
    switch (_class)
    {
        case DNS_CLASS_IN:  return "Internet"; break;
        case DNS_CLASS_CS:  return "CsNet"; break;
        case DNS_CLASS_CH:  return "Chaos"; break;
        case DNS_CLASS_HS:  return "Hesiod"; break;
        case DNS_CLASS_ANY: return "Any"; break;
    }

    return "Unknown";
}

char* getOPstring(uint16_t op)
{
    switch (op & OP_MASK)
    {
        case OP_QUERY:       return "Query"; break;
        case OP_IQUERY:      return "Inverse Query"; break;
        case OP_STATUS:      return "Status"; break;
        case OP_RESERVED:    return "Reserved"; break;
        case OP_NOTIFY:      return "Notify"; break;
        case OP_UPDATE:      return "Update"; break;
    }

    return "Unknown";
}

char* getRCstring(uint16_t rc)
{
    switch (rc & RC_MASK)
    {
        case RC_NOERROR:        return "No error"; break;
        case RC_FORMATERR:      return "Format error"; break;
        case RC_SERVERFAILURE:  return "Server failure"; break;
        case RC_NAMEERROR:      return "Name error"; break;
        case RC_NOTIMPLEMENTED: return "Not implemented"; break;
        case RC_REFUSED:        return "Refused"; break;
        case RC_YXDOMAIN:       return "YXDOMAIN"; break;
        case RC_YXRRSET:        return "YXRRSET"; break;
        case RC_NXRRSET:        return "NXRRSET"; break;
        case RC_NOTAUTH:        return "Not auth"; break;
        case RC_NOTZONE:        return "Not zone"; break;
    }

    return "Unknown";
}

// HEADER
// ================================================================
void read_dns_header(const char* dgram, dns_header_t* header)
{
    // sanity check
    if (header == NULL || dgram == NULL)
        return;

    // ntohs converts network-endian short to host-endian short
    // ntohs converts network-endian long to host-endian long

    // read struct from buff
    *header = (dns_header_t) {
        .id    =   ntohs( *((u_short*)&dgram[0]) ),
        .flags =   ntohs( *((u_short*)&dgram[2]) ),
        .QDCount = ntohs( *((u_short*)&dgram[4]) ),
        .ANCount = ntohs( *((u_short*)&dgram[6]) ),
        .NSCount = ntohs( *((u_short*)&dgram[8]) ),
        .ARCount = ntohs( *((u_short*)&dgram[10])),
    };
}

char* write_dns_header(char* position, dns_header_t* header)
{
    // sanity check
    if (header == NULL || position == NULL)
        return NULL;

    // htons converts host-endian short network-endian short
    // htonl converts host-endian long network-endian long

    // write struct to buff
    *((u_short*)&position[0]) = htons(header->id);
    *((u_short*)&position[2]) = htons(header->flags);
    *((u_short*)&position[4]) = htons(header->QDCount);
    *((u_short*)&position[6]) = htons(header->ANCount);
    *((u_short*)&position[8]) = htons(header->NSCount);
    *((u_short*)&position[10]) = htons(header->ARCount);

    return position + 12;
}

void print_dns_header(dns_header_t* header)
{
    printf("\nID: %u\nQR: %s\nOP: %s\nFlag: %s%s%s%s\nRC: %s\nQuestions: %u\nAnswers: %u\nAuthority: %u\nAdditional: %u",
            header->id,
            header->flags & QR_RESPONSE ? "Reply" : "Request",
            getOPstring(header->flags),
            header->flags & FLAG_AA ? " AuthAnswer " : "",
            header->flags & FLAG_TC ? " TrunCated " : "",
            header->flags & FLAG_RD ? " RecursionDesired " : "",
            header->flags & FLAG_RA ? " RecursionAvailable " : "",
            getRCstring(header->flags),
            header->QDCount,
            header->ANCount,
            header->NSCount,
            header->ARCount);
}

// QUESTION
// ================================================================
char* read_dns_question(const char* dgram_start, const char* question_start, dns_question_t* question)
{
    if (question == NULL || question_start == NULL || dgram_start == NULL)
    {
        fprintf(stderr, "\nread_dns_question got null pointer!");
        return NULL;
    }

    char* curr = read_dns_name(dgram_start, (char*)question_start, question->qname);

    question->qtype  = ntohs( *((uint16_t*)(curr)) );
    curr += sizeof(question->qtype);

    question->qclass = ntohs( *((uint16_t*)(curr)) );
    curr += sizeof(question->qclass);

    return curr;
}

char* write_dns_question(char* position, dns_question_t* question)
{
    if (question == NULL || position == NULL)
    {
        fprintf(stderr, "\nwrite_dns_question got null pointer!");
        return NULL;
    }

    char *curr = position + domain_plain_to_label(question->qname, position);

    *((uint16_t*)(curr)) = htons(question->qtype);
    curr += sizeof(question->qtype);

    *((uint16_t*)(curr)) = htons(question->qclass);
    curr += sizeof(question->qclass);

    return curr;
}

void print_dns_question(dns_question_t* question)
{
    printf("\nName: %s\nType: %s\nClass: %s",
           question->qname,
           getTypeString(question->qtype),
           getClassString(question->qclass));
}

// ANSWER
// ================================================================

char* read_dns_answer(const char* dgram_start, const char* answer_start, dns_answer_t* answer)
{
    char* curr = read_dns_name(dgram_start, (char*)answer_start, answer->aname);

    answer->atype = ntohs( *((uint16_t*)(curr)) );
    curr += sizeof(answer->atype);

    answer->aclass = ntohs( *((uint16_t*)(curr)) );
    curr += sizeof(answer->aclass);

    answer->ttl = ntohl( *((uint32_t*)(curr)) );
    curr += sizeof(answer->ttl);

    answer->rdlength = ntohs( *((uint16_t*)(curr)) );
    curr += sizeof(answer->rdlength);

    // read the data
    memcpy(answer->rdata, curr, min(answer->rdlength, RDATA_SIZE));
    curr += answer->rdlength;

    return curr;
}

char* write_dns_answer(char* position, dns_answer_t* answer)
{
    char *curr = position + domain_plain_to_label(answer->aname, position);

    *((uint16_t*)(curr)) = htons(answer->atype);
    curr += sizeof(answer->atype);

    *((uint16_t*)(curr)) = htons(answer->aclass);
    curr += sizeof(answer->aclass);

    *((uint32_t*)(curr)) = htonl(answer->ttl);
    curr += sizeof(answer->ttl);

    *((uint16_t*)(curr)) = htons(answer->rdlength);
    curr += sizeof(answer->rdlength);

    // write the data
    memcpy(curr, answer->rdata, min(answer->rdlength, RDATA_SIZE));
    curr += answer->rdlength;

    return curr;
}

void print_dns_answer(dns_answer_t* answer)
{
    printf("\nName: %s\nType: %s\nClass: %s\nTime: %u\nData length: %u",
           answer->aname,
           getTypeString(answer->atype),
           getClassString(answer->aclass),
           answer->ttl,
           answer->rdlength);

    if (answer->atype == DNS_TYPE_A && answer->aclass == DNS_CLASS_IN)
        printf("\nIP: %s", inet_ntoa((struct in_addr) {.S_un.S_addr = *((uint32_t*)answer->rdata) }));
}

// TRANSACTION
// ================================================================
//#define TRANSACTION_PRINT 1
dns_transaction_t* read_dns_transaction(const char* dgram, int length)
{
    if (length < 12)
        return NULL;

    char *currentPosition = (char*)dgram;
    char *maxPosition = (char*)(dgram + length);

    // read the header
    dns_header_t header;
    read_dns_header(dgram, &header);
    currentPosition += 12;

    // alloc the transaction struct
    dns_transaction_t* tra = (dns_transaction_t*)malloc(sizeof(dns_transaction_t));

    tra->header = header;
    tra->questions  = (tra->header.QDCount == 0) ? NULL : (dns_question_t*)calloc(tra->header.QDCount, sizeof(dns_question_t));
    tra->answers_an = (tra->header.ANCount == 0) ? NULL :   (dns_answer_t*)calloc(tra->header.ANCount, sizeof(dns_answer_t));
    tra->answers_ns = (tra->header.NSCount == 0) ? NULL :   (dns_answer_t*)calloc(tra->header.NSCount, sizeof(dns_answer_t));
    tra->answers_ar = (tra->header.ARCount == 0) ? NULL :   (dns_answer_t*)calloc(tra->header.ARCount, sizeof(dns_answer_t));

    #ifdef TRANSACTION_PRINT
    print_dns_header(&tra->header);
    #endif

    int i = 0;
    for (i = 0; (i < header.QDCount) && (currentPosition < maxPosition); i++)
    {
        currentPosition = read_dns_question(dgram, currentPosition, &tra->questions[i]);

        #ifdef TRANSACTION_PRINT
        printf("\n\nQUERY #%d:", i);
        print_dns_question(&tra->questions[i]);
        #endif
    }

    for (i = 0; (i < header.ANCount) && (currentPosition < maxPosition); i++)
    {
        currentPosition = read_dns_answer(dgram, currentPosition, &tra->answers_an[i]);

        #ifdef TRANSACTION_PRINT
        printf("\n\nANSWER RECORD #%d:", i);
        print_dns_answer(&tra->answers_an[i]);
        #endif
    }

    for (i = 0; (i < header.NSCount) && currentPosition < maxPosition; i++)
    {
        currentPosition = read_dns_answer(dgram, currentPosition, &tra->answers_ns[i]);

        #ifdef TRANSACTION_PRINT
        printf("\n\nAUTHORITATIVE NAME SERVER #%d:", i);
        print_dns_answer(&tra->answers_ns[i]);
        #endif
    }

    for (i = 0; (i < header.ARCount) && currentPosition < maxPosition; i++)
    {
        currentPosition = read_dns_answer(dgram, currentPosition, &tra->answers_ar[i]);

        #ifdef TRANSACTION_PRINT
        printf("\n\nADDITIONAL RECORD #%d:", i);
        print_dns_answer(&tra->answers_ar[i]);
        #endif
    }

    return tra;
}

int write_dns_transaction(char* dgram, int buffer_length, dns_transaction_t* tra)
{
    char* position = dgram;

    position = write_dns_header(position, &tra->header);

    int i;

    for (i = 0; (i < tra->header.QDCount) && ((int)(position - dgram) < buffer_length); i++)
        position = write_dns_question(position, &tra->questions[i]);

    for (i = 0; (i < tra->header.ANCount) && ((int)(position - dgram) < buffer_length); i++)
        position = write_dns_answer(position, &tra->answers_an[i]);

    for (i = 0; (i < tra->header.NSCount) && ((int)(position - dgram) < buffer_length); i++)
        position = write_dns_answer(position, &tra->answers_ns[i]);

    for (i = 0; (i < tra->header.ARCount) && ((int)(position - dgram) < buffer_length); i++)
        position = write_dns_answer(position, &tra->answers_ar[i]);

    return (int)(position - dgram);
}

dns_transaction_t* create_dns_reply(dns_transaction_t* query)
{
    dns_transaction_t* reply = (dns_transaction_t*)malloc(sizeof(dns_transaction_t));
    if (reply == NULL)
        return NULL;

    *reply = (dns_transaction_t) {
        .header = (dns_header_t){
            .id = query->header.id,
            .flags = query->header.flags | QR_RESPONSE | FLAG_AA,
            .QDCount = query->header.QDCount,
            .ANCount = 0,
            .NSCount = 0,
            .ARCount = 0,
        },
        .questions = (dns_question_t*)calloc(query->header.QDCount, sizeof(dns_question_t)),
        .answers_an = NULL,
        .answers_ns = NULL,
        .answers_ar = NULL,
    };

    // the reply carries a copy of the queried questions
    memcpy(reply->questions, query->questions, query->header.QDCount*sizeof(dns_question_t));

    return reply;
}

void add_answer_to_dns_reply(dns_transaction_t* reply, dns_answer_t new_answer)
{
    if (reply == NULL)
        return;

    uint16_t* counter = &reply->header.ARCount;
    dns_answer_t **list = &reply->answers_ar;

    if (new_answer.atype == DNS_TYPE_A)
    {
        counter = &reply->header.ANCount;
        list = &reply->answers_an;
    }
    else if (new_answer.atype == DNS_TYPE_NS)
    {
        counter = &reply->header.NSCount;
        list = &reply->answers_ns;
    }

    dns_answer_t *new_list = (dns_answer_t*)realloc((*list), sizeof(dns_answer_t)* ((*counter) + 1));
    if (new_list == NULL)
        return; // reallocation failed
    else
        (*list) = new_list;

    new_list[*counter] = new_answer; // copy the new answer to inside the new element on the list

    (*counter) = (*counter) + 1;
}

void free_dns_transaction(dns_transaction_t* tra)
{
    free(tra->questions);
    free(tra->answers_an);
    free(tra->answers_ns);
    free(tra->answers_ar);
    free(tra);
}

void print_dns_transaction(dns_transaction_t* tra)
{
    print_dns_header(&tra->header);

    if (tra->questions != NULL)
    for (int i = 0; i < tra->header.QDCount; i++)
    {
        printf("\n\nQUERY #%d:", i);
        print_dns_question(&tra->questions[i]);
    }

    if (tra->answers_an) for (int i = 0; i < tra->header.ANCount; i++)
    {
        printf("\n\nANSWER RECORD #%d:", i);
        print_dns_answer(&tra->answers_an[i]);
    }

    if (tra->answers_ns) for (int i = 0; i < tra->header.NSCount; i++)
    {
        printf("\n\nAUTHORITATIVE RECORD #%d:", i);
        print_dns_answer(&tra->answers_ns[i]);
    }

    if (tra->answers_ar) for (int i = 0; i < tra->header.ARCount; i++)
    {
        printf("\n\nADDITIONAL RECORD #%d:", i);
        print_dns_answer(&tra->answers_ar[i]);
    }
}
