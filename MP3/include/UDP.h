//
//  UDP.hpp
//  
//
//  Created by Hieu Huynh on 10/7/17.
//

#ifndef UDP_hpp
#define UDP_hpp

#include <stdio.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "common.h"
#define TCPPORT "3495" // the port users will be connecting to
#define BACKLOG 10 // how many pending connections queue will hold
#define MAXDATASIZE 100 
using namespace std;

typedef std::chrono::high_resolution_clock clk;
typedef std::chrono::time_point<clk> timepnt;
typedef std::chrono::milliseconds unit_milliseconds;
typedef std::chrono::microseconds unit_microseconds;
typedef std::chrono::nanoseconds unit_nanoseconds;
#define MAX_BUF_SIZE 1024


using namespace std;
class UDP{
private:
    char msg_buf[1024];
    int msg_buf_idx;        
    queue<string> msg_q;    //Message queue
    
public:
    UDP();
    string read_msg_non_block(int time_out);
    string receive_msg();
    void getlines_(int fd);
    vector<string> buf_to_line(char* buf, int buf_size);
    void send_msg(string dest_addr, string msg);    
};

void sigchld_handler(int s);
void *get_in_addr(struct sockaddr *sa);
void tcp_recv();
int tcp_connect(const char * ip);
void tcp_send(int sockfd, const char* ip, const char* msg);
void tcp_close(int sockfd);


#endif /* UDP_hpp */
