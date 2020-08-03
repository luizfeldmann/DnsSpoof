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

// HEADER
// ================================================================
void read_dns_header(const char* dgram, dns_header_t* header)
{
    *header = (dns_header_t) {
        .id    =   ntohs( *((u_short*)&dgram[0]) ),
        .flags =   ntohs( *((u_short*)&dgram[2]) ),
        .QDCount = ntohs( *((u_short*)&dgram[4]) ),
        .ANCount = ntohs( *((u_short*)&dgram[6]) ),
        .NSCount = ntohs( *((u_short*)&dgram[8]) ),
        .ARCount = ntohs( *((u_short*)&dgram[10])),
    };
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

// QUERY
// ================================================================
char* read_dns_name(const char* dgram_start, const char* name_start, char* destination)
{
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

char* read_dns_question(const char* dgram_start, const char* question_start, dns_question_t* question)
{
    char* curr = read_dns_name(dgram_start, (char*)question_start, question->qname);

    question->qtype  = ntohs( *((uint16_t*)(curr)) );
    curr += sizeof(question->qtype);

    question->qclass = ntohs( *((uint16_t*)(curr)) );
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
#define TRANSACTION_PRINT 1
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
        printf("\nQUERY #%d:", i);
        print_dns_question(&tra->questions[i]);
    }

    if (tra->answers_an) for (int i = 0; i < tra->header.ANCount; i++)
    {
        printf("\nANSWER RECORD #%d:", i);
        print_dns_answer(&tra->answers_an[i]);
    }

    if (tra->answers_ns) for (int i = 0; i < tra->header.NSCount; i++)
    {
        printf("\nAUTHORITATIVE RECORD #%d:", i);
        print_dns_answer(&tra->answers_ns[i]);
    }

    if (tra->answers_ar) for (int i = 0; i < tra->header.ARCount; i++)
    {
        printf("\nADDITIONAL RECORD #%d:", i);
        print_dns_answer(&tra->answers_ar[i]);
    }
}
