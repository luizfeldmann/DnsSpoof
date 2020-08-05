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

#ifndef _ZONE_FILE_H_
#define _ZONE_FILE_H_

#include "dns_protocol.h"

void print_records_collection(dns_answer_t* first, int count);
unsigned read_zone_file(const char* filename, dns_answer_t** pointer_to_records);
int find_next_dns_match(const char* domain, dns_answer_t* collection, unsigned int count, int previous);
dns_transaction_t*  build_dns_reply_from_query(dns_transaction_t* query, dns_answer_t *dns_record_collection, unsigned int dns_record_count);

#endif // _ZONE_FILE_H_
