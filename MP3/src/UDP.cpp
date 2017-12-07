//
//  UDP.cpp
//  
//
//  Created by Hieu Huynh on 10/7/17.
//

#include "UDP.h"
#include "Protocol.h"


/*This constructor sets the msg_buf_idx to 0
 */
UDP::UDP(){
    msg_buf_idx = 0;
}

/* This function parse buffer and return a vector of lines from buffer
 *Argument:     buf: buffer
 *              buf_size: buffer size
 *Return:       vector of lines from buffer
 */
vector<string> UDP::buf_to_line(char* buf, int buf_size){
    vector<string> lines;
    string s(buf, buf_size);
    string delimiter = "\n";
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        token.push_back('\n');
        lines.push_back(token);
        s.erase(0, pos + delimiter.length());
    }
    return lines;
}

/* This function read from fd and extract data into messages and store in msg queue
 *Argument:     fd: fd to read from
 *Return:       none
 */
void UDP::getlines_(int fd){
    char buf[1024];
    int numbytes;
    if((numbytes = recv(fd, (char*)(msg_buf + msg_buf_idx), 1024 - msg_buf_idx, 0)) == -1){
        perror("UDP_Client: recv error\n");
        exit(1);
    }
    
    int idx ;
    for(idx = msg_buf_idx + numbytes-1; idx >=0 ; idx--){
        if(msg_buf[idx] == '\n')
            break;
    }
    if(idx == 0 && msg_buf[0] != '\n'){
        msg_buf_idx = msg_buf_idx + numbytes;
        return;
    }
    
    memcpy(buf, msg_buf, idx+1);
    memcpy(msg_buf, (char*)(msg_buf + idx+1), numbytes + msg_buf_idx - idx - 1);
    msg_buf_idx =  numbytes + msg_buf_idx - idx - 1;
    vector<string> lines = buf_to_line(buf, idx+1);
    for(int i = 0 ; i < (int)lines.size(); i++){
        msg_q.push(lines[i]);
    }
    return;
}

/*This function read 1 msg from socket and return after a specified time
 *Input:    time_out: wait time (in ms)
 *Return:   Message if exist. Return empty string if timeout and not received any msg.
 */
string UDP::read_msg_non_block(int time_out){
    fd_set r_master, r_fds;
    FD_ZERO(&r_master);
    FD_ZERO(&r_fds);
    
    if(!msg_q.empty()){
        string ret = msg_q.front();
        msg_q.pop();
        return ret;
    }
    
    FD_SET(my_socket_fd, &r_master);
    timepnt begin;
    begin = clk::now();
    
    while(1){
        r_fds = r_master;
        struct timeval t_out;
        t_out.tv_sec = 0;
        t_out.tv_usec = time_out*1000;
        if(select(my_socket_fd+1, &r_fds, NULL, NULL, &t_out) == -1){
            perror("client: select");
            exit(4);
        }
        for(int i = 1 ; i <= my_socket_fd; i++){
            if(FD_ISSET(i, &r_fds)){
                getlines_(i);
                if(!msg_q.empty()){
                    string ret = msg_q.front();
                    msg_q.pop();
                    return ret;
                }
            }
        }
        break;
    }
    string result = "";
    return result;
}

/*This function read 1 msg from msg queue. If msg queue is empty, wait until receive msg
 *Input:    None
 *Return:   Message
 */
string UDP::receive_msg(){
    //If there is msg in msg_q, return the oldest msg
    if(!msg_q.empty()){
        string ret_msg = msg_q.front();
        msg_q.pop();
        return ret_msg;
    }
    while(1){
        if(!msg_q.empty())
            break;
        getlines_(my_socket_fd);
    }
    string ret_msg = msg_q.front();
    msg_q.pop();
    return ret_msg;
}


/*
 *Send msg to destination host name
 *Input:    dest_host_name: host name of destination
 *          msg: message
 *Return:   Number of bytes sent
 */
void UDP::send_msg(string dest_addr, string msg){

    struct addrinfo hints, *servinfo;
    int rv;
    int numbyte = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    
    if ((rv = getaddrinfo(dest_addr.c_str(),PORT, &hints, &servinfo)) != 0) {
        //        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        perror("getaddrinfo: failed \n");
        exit(1);
    }
    int buf_idx = 0;
    int msg_length = (int) msg.size();
    while(msg_length > 0){
        if((numbyte = sendto(my_socket_fd, (char*)(msg.c_str()+buf_idx), msg_length-buf_idx, 0,
                             servinfo->ai_addr, sizeof(*servinfo->ai_addr))) == -1){
            perror("Message: send");
            return ;
        }
        buf_idx += numbyte;
        msg_length -= numbyte;
    }
}

void sigchld_handler(int s)
{
 // waitpid() might overwrite errno, so we save and restore it:
 int saved_errno = errno;
 while(waitpid(-1, NULL, WNOHANG) > 0);
 errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
 if (sa->sa_family == AF_INET) {
 return &(((struct sockaddr_in*)sa)->sin_addr);
 }
 return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void tcp_recv()
{
 int sockfd, new_fd, numbytes; // listen on sock_fd, new connection on new_fd
 struct addrinfo hints, *servinfo, *p;
 char buf[MAXDATASIZE];
 struct sockaddr_storage their_addr; // connector's address information
 socklen_t sin_size;
 struct sigaction sa;
 int yes=1;
 char s[INET6_ADDRSTRLEN];
 int rv;
 memset(&hints, 0, sizeof hints);
 hints.ai_family = AF_UNSPEC;
 hints.ai_socktype = SOCK_STREAM;
 hints.ai_flags = AI_PASSIVE; // use my IP
 if ((rv = getaddrinfo(NULL, TCPPORT, &hints, &servinfo)) != 0) {
 fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
 return;
 }
 // loop through all the results and bind to the first we can
 for(p = servinfo; p != NULL; p = p->ai_next) {
 if ((sockfd = socket(p->ai_family, p->ai_socktype,
 p->ai_protocol)) == -1) {
 perror("server: socket");
 continue;
 }
 if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
 sizeof(int)) == -1) {
 perror("setsockopt");
 exit(1);
 }
 if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
 close(sockfd);
 perror("server: bind");
 continue;
 }
 break;
 }
 freeaddrinfo(servinfo); // all done with this structure
 if (p == NULL) {
 fprintf(stderr, "server: failed to bind\n");
 exit(1);
 }
 if (listen(sockfd, BACKLOG) == -1) {
 perror("listen");
 exit(1);
 }
 sa.sa_handler = sigchld_handler; // reap all dead processes
 sigemptyset(&sa.sa_mask);
 sa.sa_flags = SA_RESTART;
 if (sigaction(SIGCHLD, &sa, NULL) == -1) {
 perror("sigaction");
 exit(1);
 }
 while(1) { // main accept() loop
     printf("server: waiting for connections...\n");
     sin_size = sizeof their_addr;
     new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
     if (new_fd == -1) {
     perror("accept");
     continue;
     }
     inet_ntop(their_addr.ss_family,
     get_in_addr((struct sockaddr *)&their_addr),
     s, sizeof s);
     cout<<"server: got connection from "<<s<<endl;
     //receive initial query
     if ((numbytes = recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1) {
     perror("recv");
     exit(1);
     }
     buf[numbytes] = '\0';
     cout<<"Received "<<buf<<endl;

     //send ack
     if (send(new_fd, "ACK", 3, 0) == -1)
          perror("send");

     //Handler code here
     string msg = buf;
     Protocol local_protocol;
     if(msg[0] == 'P'){
        cout<<"HANDLING P"<<endl;
        local_protocol.handle_P_msg(msg, false, new_fd);
     }
     else if(msg.substr(0,4) == "TASK"){
        cout<<msg<<endl;
        local_protocol.handle_TASK_msg(msg, false, new_fd);
    }
    else if(msg.substr(0,5) == "SHARD"){
        cout<<msg<<endl;
        local_protocol.handle_SHARD_msg(msg, false, new_fd);
    }
     else if(msg.substr(0,3) == "GET"){
        cout<<"HANDLING GET"<<endl;
        local_protocol.handle_GET_msg(msg, false, new_fd);
     }
     else if(msg.substr(0,3) == "GOT"){
        cout<<"HANDLING GOT"<<endl;
        local_protocol.handle_GOT_msg(msg, false, new_fd);
     }
     else if(msg.substr(0,2) == "LS"){
        cout<<"HANDLING LS"<<endl;
        local_protocol.handle_LS_msg(msg, false, new_fd);
     }
     else if(msg.substr(0,3) == "DEL"){
        cout<<"HANDLING DEL"<<endl;
        local_protocol.handle_DEL_msg(msg, false, new_fd);
     }
     else if(msg.substr(0,4) == "FAIL"){
        cout<< "FAILED TO COMPLETE REQUEST"<<endl;
     }
     close(new_fd); // parent doesn't need this
 }
 return ;
}

int tcp_connect(const char * ip){
 int sockfd, numbytes;
 char buf[MAXDATASIZE];
 struct addrinfo hints, *servinfo, *p;
 int rv;
 char s[INET6_ADDRSTRLEN];
 
 memset(&hints, 0, sizeof hints);
 hints.ai_family = AF_UNSPEC;
 hints.ai_socktype = SOCK_STREAM;
 if ((rv = getaddrinfo(ip, TCPPORT, &hints, &servinfo)) != 0) {
 fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
 return -1;
 }
 // loop through all the results and connect to the first we can
 time_t time1, time2;
 time(&time1);
 while(1){
     time(&time2);
     for(p = servinfo; p != NULL; p = p->ai_next) {
     if ((sockfd = socket(p->ai_family, p->ai_socktype,
     p->ai_protocol)) == -1) {
     perror("client: socket");
     cout<<"HELLO";
     continue;
     }
     if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
     close(sockfd);
     perror("client: connect");
     continue;
     }
     break;
     }
     if (p == NULL) {
     // fprintf(stderr, "client: failed to connect\n");
     if(difftime(time2, time1) >= 4)
        return -2;
     continue;
     }
     else
        break;
 }
 inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
 s, sizeof s);
 cout<<"client: connecting to "<<s<<endl;
 freeaddrinfo(servinfo); // all done with this structure

 return sockfd;
}

void tcp_send(int sockfd, const char * ip, const char * msg){
     if (send(sockfd, msg, strlen(msg), 0) == -1)
          perror("send");
}

void tcp_close(int sockfd){
      close(sockfd);
}

