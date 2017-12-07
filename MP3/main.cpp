//
//  main.cpp
//
//
//  Created by Hieu Huynh on 9/27/17.
//

#include "common.h"
#include "Protocol.h"
#include "UDP.h"
#include "logging.h"

membership::Logger my_logger;
membership::Logger::Handle main_log = my_logger.get_handle("Main\t\t\t\t");
membership::Logger::Handle hb_sender_log = my_logger.get_handle("Heartbeat Sender\t");
membership::Logger::Handle hb_checker_log = my_logger.get_handle("Heartbeat Checker\t");
membership::Logger::Handle io_log = my_logger.get_handle("User Input\t\t\t");
membership::Logger::Handle update_hbs_log = my_logger.get_handle("Heartbeat Targets\t");
membership::Logger::Handle protocol_log = my_logger.get_handle("Protocol\t\t\t");

unordered_map<int, VM_info> vm_info_map;
set<int> membership_list;
std::mutex membership_list_lock;
set<int> hb_targets;
std::mutex hb_targets_lock;
std::mutex failure_lock;
std::mutex worker_lock;


//No need lock
int my_socket_fd;
VM_info my_vm_info;
void update_hb_targets(bool haveLock);

UDP* my_listener;
string put_happening;

string vm_hosts[NUM_VMS] =  {
    "fa17-cs425-g38-01.cs.illinois.edu",
    "fa17-cs425-g38-02.cs.illinois.edu",
    "fa17-cs425-g38-03.cs.illinois.edu",
    "fa17-cs425-g38-04.cs.illinois.edu",
    "fa17-cs425-g38-05.cs.illinois.edu",
    "fa17-cs425-g38-06.cs.illinois.edu",
    "fa17-cs425-g38-07.cs.illinois.edu",
    "fa17-cs425-g38-08.cs.illinois.edu",
    "fa17-cs425-g38-09.cs.illinois.edu",
    "fa17-cs425-g38-10.cs.illinois.edu"
};

void heartbeat_checker_handler();
void get_membership_list(bool is_VM0);
void init_machine();
void msg_handler_thread(string msg);
void heartbeat_sender_handler();
void heartbeat_checker_handler();
void update_hb_targets(bool haveLock);
string int_to_string(int num);
int string_to_int(string str);
void print_membership_list();

bool isJoin;
std::mutex isJoin_lock;


/*This function update the HB targets based on the current membershiplist
 *input:    haveLock: indicate if having lock or not
 *return:   Nothing
 */
void update_hb_targets(bool haveLock){
    if(haveLock == false){
        membership_list_lock.lock();
        hb_targets_lock.lock();
    }

    set<int> new_hb_targets;
    //Get new targets

    auto my_it = membership_list.find(my_vm_info.vm_num);
    int count = 0;

    //Get sucessors
    for(auto it = next(my_it); it != membership_list.end() && count < NUM_TARGETS/2; it++){
        new_hb_targets.insert(*it);
        count ++;
    }

    for(auto it = membership_list.begin(); it != my_it && count < NUM_TARGETS/2; it++){
        new_hb_targets.insert(*it);
        count ++;
    }

    //Get predecessors
    if(count == NUM_TARGETS/2){
        count = 0;
        if(my_it != membership_list.begin()){
            for(auto it = prev(my_it); it != membership_list.begin() && count < NUM_TARGETS/2; it--){
                if(new_hb_targets.find(*it) == new_hb_targets.end()){
                    new_hb_targets.insert(*it);
                    count++;
                }
            }
            if(count < (NUM_TARGETS/2)  && new_hb_targets.find(*membership_list.begin()) == new_hb_targets.end()
               && (*membership_list.begin()) != *my_it){
                count++;
                new_hb_targets.insert(*membership_list.begin());
            }
        }
        for(auto it = prev(membership_list.end()); it != my_it && count < NUM_TARGETS/2; it--){
            if(new_hb_targets.find(*it) == new_hb_targets.end()){
                new_hb_targets.insert(*it);
                count++;
            }
        }
    }
    Protocol p ;
    UDP udp;
    //Old targets is not in new targets, set HB to 0
    for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
        if(new_hb_targets.find(*it) == new_hb_targets.end() && membership_list.find(*it) != membership_list.end()){
            vm_info_map[*it].heartbeat = 0;
            string t_msg = p.create_T_msg();
            udp.send_msg(vm_info_map[*it].ip_addr_str, t_msg);
        }
    }

    //Update targets
    hb_targets.erase(hb_targets.begin(), hb_targets.end());
    for(auto it = new_hb_targets.begin(); it != new_hb_targets.end(); it++){
        hb_targets.insert(*it);
    }

    // Log Updates
    update_hbs_log << "New targets ";
    for(auto i : hb_targets) {
        update_hbs_log << i << " ";
    }
    update_hbs_log <<= "";

    if(haveLock == false){
        hb_targets_lock.unlock();
        membership_list_lock.unlock();
    }
    return;
}

/*This function convert the num from 0-99 to a string with 2 char
 *input:    num: number
 *return:   string of that number
 */
string int_to_string(int num){
    string ret("");
    int first_digit = num/10;
    int sec_digit = num%10;
    ret.push_back((char)(first_digit + '0'));
    ret.push_back((char)(sec_digit + '0'));
    return ret;
}

/*This function convert the string of number to int
 *input:    str: string
 *return:    number
 */
int string_to_int(string str){
    int ret = 0;
    for(int i = 0; i < (int)str.size(); i++){
        ret = ret*10 + (str[i] - '0');
    }
    return ret;
}

/*This function print out the membershiplist
 *input:    none
 *return:    none
 */
void print_membership_list(){
    cout <<"Current membership list: \n";
    for(auto it = membership_list.begin(); it != membership_list.end(); it++){
        cout << "id: " << vm_info_map[*it].vm_num << " --- ip address: " << vm_info_map[*it].ip_addr_str
        << " --- time stamp: "<<vm_info_map[*it].time_stamp << "\n";
    }
}


/*This function send request to VM0 to get membershiplist, and set the membership list based on response
 *Input:    bool:
 *Return:   None
 */
void get_membership_list(bool is_vm0){
    UDP local_udp;
    Protocol local_proc;
    string request_msg = local_proc.create_J_msg();
    if(is_vm0 == false){    //If this is not VM0, send request to VM0 until get the response
        cout << "Requesting membership list from VM0...\n";
        while(1){
            local_udp.send_msg(vm_hosts[0], request_msg);
            string i_msg = local_udp.read_msg_non_block(200);
            if((i_msg.size() == 0) || (i_msg[0] != 'I') ){
                continue;
            }
            int num_node = string_to_int(i_msg.substr(3,2));        //Initialize the membership list based on VM0 response
            if((int)i_msg.size() == num_node*16 + 6){
                local_proc.handle_I_msg(i_msg);
                break;
            }
        }
    }
    else{           //If this is VM0, send msg to all other VMs to to check if they are still alive or not
        bool got_msg = false;
        cout << "Checking if there is any VM still alive...\n";
        for(int i = 1; i < NUM_VMS; i++){
            local_udp.send_msg(vm_hosts[i], request_msg);
            string i_msg = local_udp.read_msg_non_block(200);
            if((i_msg.size() == 0) || (i_msg[0] != 'I') ){
                continue;
            }
            int num_node = string_to_int(i_msg.substr(3,2));        //Set membership list based on the response
            if((int)i_msg.size() == num_node*16 + 6){
                got_msg = true;
                local_proc.handle_I_msg(i_msg);
                break;
            }
        }
        if(got_msg == false){
            string i_msg = local_udp.read_msg_non_block(200);
            if((i_msg.size() > 0) || (i_msg[0] == 'I') ){
                int num_node = string_to_int(i_msg.substr(3,2));
                if((int)i_msg.size() == num_node*16 + 6){
                    got_msg = true;
                    local_proc.handle_I_msg(i_msg);
                }
            }
        }
        if(got_msg == false){
            membership_list.insert(0);
            vm_info_map[0] = my_vm_info;
        }
    }
}

/*This function return ip of this VM
 *Input:    bool:
 *Return:   None
 */
void get_my_ip(){
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    char my_addr[512];
    gethostname(my_addr,512);

    if ((status = getaddrinfo(my_addr, NULL, &hints, &res)) != 0) {
        perror("Cannot get my addrinfo\n");
        exit(1);
    }

    for(p = res;p != NULL; p = p->ai_next) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        void * addr = &(ipv4->sin_addr);
        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        break;
    }
    freeaddrinfo(res); // free the linked list

    //Get Bytes from ip address
    unsigned short a, b, c, d;
    sscanf(ipstr, "%hu.%hu.%hu.%hu", &a, &b, &c, &d);
    my_vm_info.ip_addr[0] = (unsigned char) a;
    my_vm_info.ip_addr[1] = (unsigned char) b;
    my_vm_info.ip_addr[2] = (unsigned char) c;
    my_vm_info.ip_addr[3] = (unsigned char) d;

    for (int i = 0 ; i < 4; i++) {
        my_vm_info.ip_addr_str.append(to_string((unsigned int) my_vm_info.ip_addr[i]));
        if(i != 3)
            my_vm_info.ip_addr_str.push_back('.');
    }

    return;
}

/*This function initilize the vm. It sets my_id, my_id_str, my_logger, my_listener, membership list
 *Input:    None
 *Return:   None
 */
void init_machine(){
    //Init my_id and my_id_str
    get_my_ip();
    bool is_VM0 = false;
    char my_addr[512];
    gethostname(my_addr,512);
    if(strncmp(my_addr, vm_hosts[0].c_str(), vm_hosts[0].size()) == 0){
        is_VM0 = true;
    }

    ///Initialize my_socket_fd
    struct addrinfo hints, *servinfo, *p;
    int rv;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(my_addr,PORT, &hints, &servinfo)) != 0) {
        perror("getaddrinfo: failed \n");
        exit(1);
    }

    // loop through all the results and make a socket
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((my_socket_fd = socket(p->ai_family, p->ai_socktype,
                                   p->ai_protocol)) == -1) {
            perror("server: socket fail");
            continue;
        }
        bind(my_socket_fd, p->ai_addr, p->ai_addrlen);
        break;
    }
    if(p == NULL){
        perror("server: socket fail to bind");
        exit(1);
    }
    freeaddrinfo(servinfo);

    //Initialize UDP listener
    my_listener = new UDP();

    //Get time_stamp
    time_t seconds;
    seconds = time (NULL);
    my_vm_info.time_stamp = to_string(seconds);

    //Get membership_list
    if(is_VM0 == false){
        get_membership_list(false);
    }
    else{
        my_vm_info.vm_num = 0;
        my_vm_info.make_id_str();
        my_vm_info.heartbeat = 0;
        get_membership_list(true);
        membership_list_lock.lock();
        if(membership_list.size() > 1){
            auto it = membership_list.end();
            it--;
            my_vm_info.master_ip = vm_info_map[*it].master_ip;
        }
        membership_list_lock.unlock();

    }
}

/* This function handles msg based on msg types
 *Input:    msg: message
 *Return:   None
 */
 void handle_P_msg(Protocol local_protocol, string msg, bool haveLock, int my_socket_fd){
    local_protocol.handle_P_msg(msg, false, my_socket_fd);
 }

/* This function handles msg based on msg types
 *Input:    msg: message
 *Return:   None
 */
void msg_handler_thread(string msg){
    Protocol local_protocol;
    if(msg[0] == 'H'){
        if(msg.size() != H_MESSAGE_LENGTH)
            return;
        local_protocol.handle_H_msg(msg);
    }
    else if(msg[0] == 'N'){
        if(msg.size() != N_MESSAGE_LENGTH)
            return;
        local_protocol.handle_N_msg(msg, false);
    }
    else if(msg[0] == 'L'){
        if(msg.size() != L_MESSAGE_LENGTH)
            return;
        local_protocol.handle_L_msg(msg, false);
    }
    else if(msg[0] == 'J'){
        if(msg.size() != J_MESSAGE_LENGTH)
            return;
        local_protocol.handle_J_msg(msg);
    } else if(msg[0] == 'G') {
        local_protocol.handle_G_msg(msg, false);
    }
    else if(msg[0] == 'T'){
        local_protocol.handle_T_msg(msg, false);
    }
    else if(msg[0] == 'Q'){
        local_protocol.handle_Q_msg(msg, false);
    }
    else if(msg.substr(0,9) == "PUTNOTIFY"){
        local_protocol.handle_PUTNOTIFY_msg(msg);
    }
    else if(msg.substr(0,6) == "DELETE"){
        local_protocol.handle_DELETE_msg(msg);
    }
    else if(msg.substr(0,3) == "VMF"){
        cout<<"FD"<<endl;
        local_protocol.handle_VMF_msg(msg);
    }
    else if(msg.substr(0,8) == "MASTERFD"){
        cout<<"MASTERFD"<<endl;
        local_protocol.handle_MASTERFD_msg(msg);
    }
    else if(msg.substr(0,3) == "MAP"){
        cout<<"MAP"<<endl;
        local_protocol.handle_MAP_msg(msg);
    }
    else if(msg.substr(0,3) == "inV"){
        cout<<"inV"<<endl;
        local_protocol.handle_inV_msg(msg);
    }
    else if(msg.substr(0,4) == "NODE"){
        // cout<<"inV"<<endl;
        // local_protocol.handle_inV_msg(msg);
        std::istringstream iss;
        vector<std::string> result;
        iss.str(msg);
        for (string s; iss>>s; )
        result.push_back(s);

        my_vm_info.num_vertices = stol(result[1]);
        cout<<"NODES received "<<my_vm_info.num_vertices<<endl;
    }
    else if(msg.substr(0,3) == "inM"){
        cout<<"inV"<<endl;
        local_protocol.handle_inM_msg(msg);
    }
    else if(msg.substr(0,7) == "ELECTED"){
        cout<<msg<<endl;
        local_protocol.handle_ELECTED_msg(msg);
    }
    else if(msg.substr(0,7) == "SAVAReg"){
        cout<<msg<<endl;
        local_protocol.handle_SAVAReg_msg(msg, false);
    }
    else if(msg.substr(0,5) == "ALIVE"){
        cout<<msg<<endl;
        local_protocol.handle_ALIVE_msg(msg);
    }
    else if(msg.substr(0,4) == "PART"){
        cout<<msg<<endl;
        local_protocol.handle_PART_msg(msg, false);
    }
    else if(msg.substr(0,7) == "ENQUEUE"){
        // cout<<msg<<endl;
        local_protocol.handle_ENQUEUE_msg(msg, false);
    }
    else if(msg.substr(0,5) == "START"){
        cout<<msg<<endl;
        local_protocol.handle_START_msg(msg, false);
    }
    else if(msg.substr(0,2) == "SS"){
        cout<<msg<<endl;
        local_protocol.handle_SS_msg(msg, false);
    }
    else if(msg.substr(0,3) == "APP"){
        // cout<<msg<<endl;
        local_protocol.handle_APP_msg(msg, false);
    }
    else if(msg.substr(0,4) == "DONE"){
        cout<<msg<<endl;
        local_protocol.handle_DONE_msg(msg, false);
    }

}

/* This is thread handler to read and handle msg
 *Input:    None
 *Return:   None
 */
void listener_thread_handler(){
    vector<std::thread> thread_vector;
    while(1){
        isJoin_lock.lock();
        if(isJoin == false){
            isJoin_lock.unlock();
            return;
        }
        isJoin_lock.unlock();
        string msg = my_listener->read_msg_non_block(500);
        if(msg.size() == 0){
            continue;
        }

        msg_handler_thread(msg);
    }
}

/* This is thread handler to send heartbeats to pre/successors
 *Input:    None
 *Return:   None
 */
void heartbeat_sender_handler(){
    Protocol local_protocol;
    string h_msg = local_protocol.create_H_msg();
    while(1){
        isJoin_lock.lock();
        if(isJoin == false){
            isJoin_lock.unlock();
            return;
        }

        isJoin_lock.unlock();
        UDP local_udp;
        membership_list_lock.lock();
        hb_targets_lock.lock();

        //Send HB to all HB targets
        for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
            if(vm_info_map.find(*it) != vm_info_map.end()){
                local_udp.send_msg(vm_info_map[*it].ip_addr_str, h_msg);
            }
        }

        hb_targets_lock.unlock();
        membership_list_lock.unlock();
        //Sleep for HB_TIME
        std::this_thread::sleep_for(std::chrono::milliseconds(HB_TIME));
    }
}

/* This is failure handler to make changes to the maps and remove dead_ip's data and braodcast those updates
 *Input:    dead_ip
 *Return:   None
 */
void handle_failure(string dead_ip, bool haveLock){
    if(!haveLock)
        failure_lock.lock();
    vector<string> present = my_vm_info.VM_to_files_map[dead_ip];
    Protocol local_protocol;
    my_vm_info.VM_to_files_map.erase(dead_ip);
    vector<string> dummy;
    string message_1 = local_protocol.create_VMF_msg(dead_ip, dummy);

    string alive1, alive2;
    int local = 0;

    for(unsigned int i = 0; i< present.size(); i++){
        cout<<"present file is "<<present[i]<<endl;

        string del_file = present[i];
        if(my_vm_info.master_file_directory[del_file][0] == dead_ip){
            alive1 = my_vm_info.master_file_directory[del_file][1];
            alive2 = my_vm_info.master_file_directory[del_file][2];
        }
        else if(my_vm_info.master_file_directory[del_file][1] == dead_ip){
            alive1 = my_vm_info.master_file_directory[del_file][0];
            alive2 = my_vm_info.master_file_directory[del_file][2];
        }
        else{
            alive1 = my_vm_info.master_file_directory[del_file][0];
            alive2 = my_vm_info.master_file_directory[del_file][1];
        }
        cout<<"alive1-"<<alive1<<" | alive2-"<<alive2<<endl;
        //find iterator to dead_ip in the vector of locations for del_file and remove it
        auto it = find(my_vm_info.master_file_directory[del_file].begin(), my_vm_info.master_file_directory[del_file].end(), dead_ip);
        if(it != my_vm_info.master_file_directory[del_file].end()){
            cout<<"erasing "<<endl;//<<my_vm_info.master_file_directory[del_file][*it]<<endl;
            my_vm_info.master_file_directory[del_file].erase(it);
        }
        //Rereplication
        int off = 0;
        while(1){

            string hash = md5(dead_ip + to_string(off));
            std::istringstream converter(hash.substr(27));
            unsigned int value, size;
            converter >> std::hex >> value;

            if(!haveLock)
                membership_list_lock.lock();

            size = (unsigned int) membership_list.size();
            auto itr = membership_list.begin();
            if(!haveLock)
                membership_list_lock.unlock();

            int assign = (int)(value%size);
            while(assign){
                ++itr;
                assign--;
            }
            VM_info location1 = vm_info_map[*itr];
            cout<<"location1 :"<<location1.ip_addr_str<<endl;
            if(location1.ip_addr_str == my_vm_info.master_ip){
                off++;
                continue;
            }
            auto file_it = find(my_vm_info.VM_to_files_map[location1.ip_addr_str].begin(), my_vm_info.VM_to_files_map[location1.ip_addr_str].end(), del_file);
            //if replica already in location found
            if(file_it != my_vm_info.VM_to_files_map[location1.ip_addr_str].end()){
                cout<<"location contains replica"<<endl;
                off++;
                continue;
            }
            else{

                if(my_vm_info.sdfs_files.find(del_file) != my_vm_info.sdfs_files.end());
                else{
                    //get file as local copy
                    // Make connection to the IP to receive
                    cout<<"getting a local copy"<<endl;
                    local = 1;
                    if(!haveLock)
                        membership_list_lock.lock();
                    for(itr = membership_list.begin(); itr != membership_list.end(); itr++){

                        if(vm_info_map[*itr].ip_addr_str == alive1 || vm_info_map[*itr].ip_addr_str == alive2){
                            string selectedLoc = vm_info_map[*itr].ip_addr_str;
                            if(!haveLock)
                                membership_list_lock.unlock();
                            int sockfd = tcp_connect(selectedLoc.c_str());
                            if(sockfd == -2){
                                if(selectedLoc == alive1)
                                    selectedLoc = alive2;
                                else
                                    selectedLoc = alive1;
                                sockfd = tcp_connect(selectedLoc.c_str());
                            }
                            //Get request to that IP
                            string send_to_master = local_protocol.create_GOT_msg(del_file, my_vm_info.ip_addr_str, del_file);
                            const char * msg2 = send_to_master.c_str();
                            tcp_send(sockfd, selectedLoc.c_str(), msg2);
                            char buff[3];
                            //wait for ack from master
                            int rcv;
                            if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
                                perror("recv");
                            cout<<"received ack after connecting to IP"<<endl;

                            //recv file size
                             unsigned long fileSize;
                             char buf[MAXDATASIZE];
                             int numbytes;
                             if ((numbytes = recv(sockfd, buf, MAXDATASIZE, 0)) == -1) {
                             perror("recv");
                             exit(0);
                             }
                             fileSize = atoi(buf);
                             printf("FileSize %lu\n", fileSize);
                            //receive the output file
                            FILE *fp = fopen(del_file.c_str(), "w");
                            if(fp == NULL){
                                printf("File open error\n");
                                exit(0);
                            }
                            char *received_buff = new char[fileSize];
                            unsigned long bytesRead = 0;
                            while(bytesRead != fileSize)
                            {
                                 int readNow;
                                 readNow = read(sockfd, received_buff + bytesRead, (fileSize - bytesRead));
                                 //printf(" %d\n",  i++);
                                 if(readNow == -1)
                                 {
                                      perror("read");
                                      printf("Error sending file\n");
                                      exit(0);
                                 }
                                 bytesRead += readNow;
                            }
                            fwrite(received_buff,1, fileSize,fp);
                            fclose(fp);
                            //free(received_buff);
                            //close sockfd
                            tcp_close(sockfd);
                            break;
                        }
                    }
                }
                //send file through TCP
                cout<<"sending the file"<<endl;
                if(location1.ip_addr_str == my_vm_info.master_ip){
                    my_vm_info.sdfs_files.insert(del_file);
                    continue;
                }
                //SEND contents of the file and wait to get ACK from Master
                FILE *p_file = fopen(del_file.c_str(),"rb");
                string IP = location1.ip_addr_str;
                string requester_IP = my_vm_info.ip_addr_str;
                UDP local_udp;
                Protocol p;

                // First: Send the file size
                fseek(p_file,0,SEEK_END);
                unsigned long numbytes = ftell(p_file);
                fclose(p_file);
                string send_to_master = p.create_P_msg(numbytes, del_file, requester_IP);
                const char * ip = IP.c_str();
                const char * msg = send_to_master.c_str();
                int sockfd = tcp_connect(ip);
                if(sockfd == -1){
                    cout<<"FAILED: TRY AGAIN"<<endl;
                    continue;
                }
                tcp_send(sockfd, ip, msg);

                //wait for ack from master
                char buff[3];
                int rcv;
                if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
                    perror("recv");
                cout<<"received ack"<<endl;

                // Second: Send the file contents
                FILE *fp = fopen(del_file.c_str(), "r");
                if(fp == NULL){
                    printf("File open error\n");
                    exit(0);
                }
                while(1){
                    char buff[256] = {0};
                    int bytesToWrite = fread(buff,1,256,fp);
                    if(bytesToWrite > 0){
                        int bytesWritten = 0;
                        while(bytesWritten != bytesToWrite){
                            int sent;
                            sent = write(sockfd, buff + bytesWritten, (bytesToWrite - bytesWritten));
                            if(sent == -1){
                                printf("Error sending file\n");
                                exit(0);
                            }
                            bytesWritten += sent;
                        }
                    }
                    // error checking
                    if(bytesToWrite < 256){
                        if(feof(fp))
                            printf("End of file\n");
                        if(ferror(fp))
                            printf("Error in reading of file\n");
                        break;
                    }
                }
                tcp_close(sockfd);
                //push back into MFD, VMF
                my_vm_info.master_file_directory[del_file].push_back(location1.ip_addr_str);
                my_vm_info.VM_to_files_map[location1.ip_addr_str].push_back(del_file);
                string message_3 = local_protocol.create_MASTERFD_msg(del_file, my_vm_info.master_file_directory[del_file]);
                string message_4 = local_protocol.create_VMF_msg(location1.ip_addr_str,my_vm_info.VM_to_files_map[location1.ip_addr_str]);
                if(!haveLock)
                    membership_list_lock.lock();
                for(itr = membership_list.begin(); itr != membership_list.end(); itr++){
                    string destination_ip = vm_info_map[*itr].ip_addr_str;
                    local_udp.send_msg(destination_ip, message_3);
                    local_udp.send_msg(destination_ip, message_4);
                }
                if(!haveLock)
                    membership_list_lock.unlock();
                //delete file
                if(local == 1)
                    system(("rm " + del_file).c_str());
                break;
            }
        }
    }
    if(!haveLock)
        membership_list_lock.lock();
    UDP local_udp;
    for(auto it = membership_list.begin(); it != membership_list.end(); it++){
        string destination_ip = vm_info_map[*it].ip_addr_str;
        local_udp.send_msg(destination_ip, message_1);
    }
    if(!haveLock)
        membership_list_lock.unlock();
    cout<<"fin"<<endl;
    if(!haveLock)
        failure_lock.unlock();

}

/* This is thread handler to check heartbeats of pre/successors. If timeout, set that node to DEAD, and send msg
 *Input:    None
 *Return:   None
 */
void heartbeat_checker_handler(){
    while(1){
        isJoin_lock.lock();
        if(isJoin == false){
            isJoin_lock.unlock();
            return;
        }

        int flag = 0;
        VM_info dead_vm;
        isJoin_lock.unlock();
        membership_list_lock.lock();
        hb_targets_lock.lock();
        time_t cur_time;
        cur_time = time (NULL);

        for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
            std::unordered_map<int,VM_info>::iterator dead_vm_it;
            if((dead_vm_it = vm_info_map.find(*it)) != vm_info_map.end()){
                //If current time - last hearbeat > HB_TIMEOUT, mark the VM as dead and send gossip to other VM
                if(cur_time - vm_info_map[*it].heartbeat > HB_TIMEOUT && vm_info_map[*it].heartbeat != 0){
                    dead_vm = vm_info_map[*it];
                    vm_info_map.erase(dead_vm_it);
                    membership_list.erase(*it);
                    cout << "Failure Detected: VM id: " << dead_vm.vm_num << " --- ip: "<< dead_vm.ip_addr_str << " --- ts: "<<dead_vm.time_stamp
                    << " --- Last HB: " << dead_vm.heartbeat << "--- cur_time:  " << cur_time << "\n";
                    cout<<"flag setting"<<endl;
                    flag = 1;
                    hb_checker_log << "Failure Detected: VM id: " << dead_vm.vm_num << " --- ip: "<< dead_vm.ip_addr_str << " --- ts: "<<dead_vm.time_stamp
                    << " --- Last HB: " << dead_vm.heartbeat << "--- cur_time:  " <<= cur_time;
                    print_membership_list();
                    update_hb_targets(true);
                    if(membership_list.size() > 1){
                    Protocol p;
                    p.gossip_msg(p.create_L_msg(dead_vm.vm_num), true);
                    }
                }
            }
        }
        hb_targets_lock.unlock();
        membership_list_lock.unlock();
        if(flag == 1){
            cout<<"in flag ==1"<<endl;
            //handle failures
            if(dead_vm.ip_addr_str == my_vm_info.master_ip){
                    membership_list_lock.lock();
                my_vm_info.master_ip = vm_info_map[*membership_list.begin()].ip_addr_str;
                    membership_list_lock.unlock();
                cout<<"ELECTED: "<<my_vm_info.master_ip<<endl;

                // master_election_notification(false);
            }
            if(my_vm_info.ip_addr_str == my_vm_info.master_ip){
                cout<<"calling failure handler"<<endl;
                std::thread failure_handler_thread = std::thread(handle_failure, dead_vm.ip_addr_str, false);
                failure_handler_thread.detach();
            }
        }
    }
}

/*This function send request to VM0 to get membershiplist, and set the membership list based on response
 *Input:    bool:
 *Return:   None
 */
void get_maps(bool is_vm0){
    UDP local_udp;
    Protocol local_proc;
    string request_msg("MAP ");
    request_msg.append(my_vm_info.ip_addr_str);
    request_msg.append("\n");
    if(is_vm0 == false){    //If this is not VM0, send request to VM0
        cout << "Requesting VMF and MFD from VM0...\n";
        local_udp.send_msg(vm_hosts[0], request_msg);
    }
    else{           //If this is VM0, send msg to all other VMs to to check if they are still alive or not
        cout << "Requesting VMF and MFD from current master\n";
        local_udp.send_msg(my_vm_info.master_ip, request_msg);
    }
}

int main(){
    system("rm sdfs_*");
    system("rm 172*");

    isJoin = false;

    std::thread listener_thread;
    std::thread heartbeat_sender_thread;
    std::thread heartbeat_checker_thread;
    std::thread tcp_listener_thread;
    cout << "Type JOIN to join the system!\n";
    cout << "Type QUIT to stop the system!\n";
    cout << "Type ML to print membership list\n";
    cout << "Type MyVM to print this VM's information\n";
    cout << "Type put localfilename sdfsfilename to insert or update a file\n";
    cout << "Type get sdfsfilename localfilename to fetch a file\n";
    cout << "Type delete sdfsfilename to delete a file\n";
    cout << "Type ls sdfsfilename to list all machines where the file is present\n";
    cout << "Type store to list all files currently being stored at the machine\n";
    cout << "Type ph to list put_happening\n";
    cout << "Type M to list master\n";
    cout << "Type V to list loaded graph\n";
    cout << "Type X to list vertex values\n";
    cout << "-----------------------------\n";

    //Main while Loop
    while(1){
        cout<<"Enter command:"<<endl;
        string input;
        getline(cin, input);
        if(strncmp(input.c_str(), "JOIN", 4) == 0){ //Join the system
            isJoin_lock.lock();
            //If user want to join the system
            if(isJoin == true){
                cout << "VM is running!!!\n";
                isJoin_lock.unlock();
                continue;
            }
            isJoin = true;
            isJoin_lock.unlock();

            //Initialize the VM
            init_machine();
            cout <<"-----------Successfully Initialize-----------\n";
            cout << "My VM info: id: " << my_vm_info.vm_num << " --- ip: "<< my_vm_info.ip_addr_str << " --- ts: "<<my_vm_info.time_stamp<<"\n";
            print_membership_list();
            //Start all threads
            listener_thread = std::thread(listener_thread_handler);
            heartbeat_sender_thread = std::thread(heartbeat_sender_handler);
            heartbeat_checker_thread = std::thread(heartbeat_checker_handler);
            tcp_listener_thread = std::thread(tcp_recv);
            if(my_vm_info.ip_addr_str == "172.22.147.116")
                get_maps(true);
            else{
                if(my_vm_info.ip_addr_str != my_vm_info.master_ip)
                    get_maps(false);
                else
                    cout<< "Failed to get VMF and MFD"<<endl;
            }

            /* SAVA Initialization */
            if(my_vm_info.ip_addr_str == "172.22.147.116"){
                cout << "I am the SAVA Client" <<endl;
                // wait for master to notify if alive???
            }
            else if(my_vm_info.ip_addr_str == "172.22.147.117"){
              cout << "I am Master" <<endl;
            }
            else if(my_vm_info.ip_addr_str == "172.22.147.118"){
              cout << "I am Standby Master" <<endl;
            }
            else{
              cout << "I am a worker" <<endl;
              // Register with the Master
              Protocol p;
              UDP udp;
              string registration = p.create_SAVAReg_msg(my_vm_info.ip_addr_str);
              udp.send_msg(my_vm_info.SAVA_Master, registration);
            }
       }
        else if(strncmp(input.c_str(), "QUIT", 4) == 0){    //Quit program
            isJoin_lock.lock();
            if(isJoin == false){
                cout << "VM is NOT running!!!\n";
                isJoin_lock.unlock();
                continue;
            }
            //Set flag to false to stop all threads
            isJoin = false;

            cout <<"Quitting the Program..\n";
            isJoin_lock.unlock();

            Protocol p;
            UDP udp;
            membership_list_lock.lock();
            hb_targets_lock.lock();

            //Send msg to notify other VM before quitting
            string t_msg = p.create_T_msg();
            for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
                udp.send_msg(vm_info_map[*it].ip_addr_str, t_msg);
            }
            p.gossip_msg(p.create_Q_msg(), true);
            hb_targets_lock.unlock();
            membership_list_lock.unlock();
            break;
        }
        else if(strncmp(input.c_str(), "ML", 2) == 0){  //Print membershiplist
            isJoin_lock.lock();
            if(isJoin == false){
                cout << "VM is NOT running!!!\n";
                isJoin_lock.unlock();
                continue;
            }

            isJoin_lock.unlock();
            membership_list_lock.lock();
            print_membership_list();
            membership_list_lock.unlock();
        }
        else if(strncmp(input.c_str(), "put", 3) == 0){
            // FORMAT: put localfilename sdfsfilename
            std::istringstream iss;
            string strvalues = input;
            vector<std::string> result;
            iss.str (strvalues);

            for (string s; iss>>s; )
                result.push_back(s);

            if(result.size() < 3){
                cout<< "ENTER IN THE FORMAT: put localfilename sdfsfilename  "<<endl;
                continue;
            }
            char reply;
            string localfilename = result[1];
            string sdfsfilename = result[2];
            FILE *p_file = fopen(localfilename.c_str(),"rb");
            if(p_file == NULL){
                cout<<localfilename<<" does not exist."<<endl;
                continue;
            }
            if(put_happening == ("sdfs_" + sdfsfilename)){
                cout<<"CONFIRM PUT?\n"<<"Y/N"<<endl;
                time_t time1, time2;
                time(&time1);
                cin>>reply;
                time(&time2);
                if(difftime(time2, time1) > 30){
                    cout<<"Timeout: Ignoring command"<<endl;
                    continue;
                }
                if(reply == 'N')
                    continue;
            }

            isJoin_lock.lock();
            if(isJoin == false){
                cout << "VM is NOT running!!!\n";
                isJoin_lock.unlock();
                continue;
            }
            isJoin_lock.unlock();

            //SEND contents of the file and wait to get ACK from Master
            string IP = my_vm_info.master_ip;
            string requester_IP = my_vm_info.ip_addr_str;
            UDP local_udp;
            Protocol p;

            // First: Send the file size
            fseek(p_file,0,SEEK_END);
            unsigned long numbytes = ftell(p_file);
            fclose(p_file);
            string send_to_master = p.create_P_msg(numbytes, sdfsfilename, requester_IP);
            const char * ip = IP.c_str();
            const char * msg = send_to_master.c_str();
            int sockfd = tcp_connect(ip);
            if(sockfd == -1){
                cout<<"FAILED: TRY AGAIN"<<endl;
                continue;
            }
            tcp_send(sockfd, ip, msg);

            //wait for ack from master
            char buff[3];
            int rcv;
            if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
                perror("recv");
            cout<<"received ack"<<endl;

            // Second: Send the file contents
            FILE *fp = fopen(localfilename.c_str(), "r");
            if(fp == NULL){
                printf("File open error\n");
                exit(0);
            }
            while(1){
                char buff[256] = {0};
                int bytesToWrite = fread(buff,1,256,fp);
                if(bytesToWrite > 0){
                    int bytesWritten = 0;
                    while(bytesWritten != bytesToWrite){
                        int sent;
                        sent = write(sockfd, buff + bytesWritten, (bytesToWrite - bytesWritten));
                        if(sent == -1){
                            printf("Error sending file\n");
                            exit(0);
                        }
                        bytesWritten += sent;
                    }
                }
                // error checking
                if(bytesToWrite < 256){
                    if(feof(fp))
                        printf("End of file\n");
                    if(ferror(fp))
                        printf("Error in reading of file\n");
                    break;
                }
            }
            tcp_close(sockfd);
        }
        else if(strncmp(input.c_str(), "get", 3) == 0){
            // FORMAT: get sdfsfilename localfilename
            std::istringstream iss;
            string strvalues = input;
            vector<std::string> result;
            iss.str (strvalues);
            for (string s; iss>>s; )
                result.push_back(s);

            if(result.size() < 3){
                cout<< "ENTER IN THE FORMAT: get sdfsfilename localfilename"<<endl;
                continue;
            }

            string localfilename = result[2];
            string sdfsfilename = "sdfs_" + result[1];
            cout<<"IN GET: input is"<<input<<endl;
            cout<<"IN GET: result 1 is sdfsfilename: "<<result[1]<<endl;
            cout<<"IN GET: result 2 is localfilename: "<<result[2]<<endl;

            isJoin_lock.lock();
            if(isJoin == false){
                cout << "VM is NOT running!!!\n";
                isJoin_lock.unlock();
                continue;
            }
            isJoin_lock.unlock();

            string IP = my_vm_info.master_ip;
            string requester_IP = my_vm_info.ip_addr_str;
            UDP local_udp;
            Protocol p;
            string send_to_master = p.create_GET_msg(sdfsfilename, requester_IP, localfilename);
            const char * ip = IP.c_str();
            const char * msg = send_to_master.c_str();
            // cout<< "IN PUT: MESSAGE SENT TO MASTER: " <<send_to_master<<endl;
            int sockfd = tcp_connect(ip);
            if(sockfd == -1){
                cout<<"FAILED: TRY AGAIN"<<endl;
                continue;
            }
            tcp_send(sockfd, ip, msg);
            //wait for ack from master
            char buff[3];
            int rcv;
            if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
                perror("recv");
            cout<<"received ack"<<endl;

            // Receive alive machine's IP
            int rcvIP;
            char buff2[MAXDATASIZE];
            if ((rcvIP = recv(sockfd, buff2, MAXDATASIZE, 0)) == -1)
                perror("recv");
            if(buff2[0] == 'F'){
                cout<<"No such file exists"<<endl;
                tcp_close(sockfd);
                continue;
            }
            else
                cout<<"IP received: "<<buff2;
            tcp_close(sockfd);

            // Make connection to the IP to receive
            sockfd = tcp_connect(buff2);
            //Get request to that IP
            send_to_master = p.create_GOT_msg(sdfsfilename, requester_IP, localfilename);
            const char * msg2 = send_to_master.c_str();
            tcp_send(sockfd, buff2, msg2);
            //wait for ack from master
            if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
                perror("recv");
            cout<<"received ack after connecting to IP"<<endl;

            //recv file size

             unsigned long fileSize;
             char buf[MAXDATASIZE];
             int numbytes;
             if ((numbytes = recv(sockfd, buf, MAXDATASIZE, 0)) == -1) {
             perror("recv");
             exit(0);

            }
             fileSize = atoi(buf);
             printf("FileSize %lu\n", fileSize);
            //receive the output file
            FILE *fp = fopen(localfilename.c_str(), "w");
            if(fp == NULL){
                printf("File open error\n");
                exit(0);
            }
            char *received_buff = new char[fileSize];
            unsigned long bytesRead = 0;
            while(bytesRead != fileSize)
            {
                 int readNow;
                 readNow = read(sockfd, received_buff + bytesRead, (fileSize- bytesRead));
                 //printf(" %d\n",  i++);
                 if(readNow == -1)
                 {
                      perror("read");
                      printf("Error sending file\n");
                      exit(0);
                 }
                 bytesRead += readNow;
            }
            fwrite(received_buff,1, fileSize,fp);
            fclose(fp);
            //free(received_buff);


            //close sockfd
            tcp_close(sockfd);

        }
        else if(strncmp(input.c_str(), "delete", 6) == 0){
            // FORMAT: delete sdfsfilename
            std::istringstream iss;
            string strvalues = input;
            vector<std::string> result;
            iss.str (strvalues);

            for (string s; iss>>s; )
                result.push_back(s);

            if(result.size() < 2){
                cout<< "ENTER IN THE FORMAT: delete sdfsfilename"<<endl;
                continue;
            }

            string sdfsfilename = result[1];

            isJoin_lock.lock();
            if(isJoin == false){
                cout << "VM is NOT running!!!\n";
                isJoin_lock.unlock();
                continue;
            }
            isJoin_lock.unlock();

            string IP = my_vm_info.master_ip;
            UDP local_udp;
            Protocol p;
            string send_to_master = p.create_DEL_msg(sdfsfilename);
            const char * ip = IP.c_str();
            const char * msg = send_to_master.c_str();
            int sockfd = tcp_connect(ip);
            if(sockfd == -1){
                cout<<"FAILED: TRY AGAIN"<<endl;
                continue;
            }
            tcp_send(sockfd, ip, msg);
            char buffer[3];
            int rcv1;
            if ((rcv1 = recv(sockfd, buffer, 3, 0)) == -1)
                perror("recv");
            int rcv;
            char buff[MAXDATASIZE];
            if ((rcv = recv(sockfd, buff, MAXDATASIZE, 0)) == -1)
                perror("recv");
            cout<<buff<<endl;
            tcp_close(sockfd);

        }
        else if(strncmp(input.c_str(), "ls", 2) == 0){
            // FORMAT: ls sdfsfilename
            std::istringstream iss;
            string strvalues = input;
            vector<std::string> result;
            iss.str (strvalues);

            isJoin_lock.lock();
            if(isJoin == false){
                cout << "VM is NOT running!!!\n";
                isJoin_lock.unlock();
                continue;
            }
            isJoin_lock.unlock();

            for (string s; iss>>s; )
                result.push_back(s);

            if(result.size() < 2){
                cout<< "ENTER IN THE FORMAT: ls sdfsfilename"<<endl;
                continue;
            }

            string sdfsfilename = result[1];

            UDP local_udp;
            Protocol p;
            string IP = my_vm_info.master_ip;
            string requester_IP = my_vm_info.ip_addr_str;
            const char * ip = IP.c_str();
            string send_to_master = p.create_LS_msg(sdfsfilename, requester_IP);
            const char * msg = send_to_master.c_str();

            int sockfd = tcp_connect(ip);
            if(sockfd == -1){
                cout<<"FAILED: TRY AGAIN"<<endl;
                continue;
            }
            tcp_send(sockfd, ip, msg);
            char buffer[3];
            int rcv1;
            if ((rcv1 = recv(sockfd, buffer, 3, 0)) == -1)
                perror("recv");
            int rcv;
            char buff[MAXDATASIZE];
            if ((rcv = recv(sockfd, buff, MAXDATASIZE, 0)) == -1)
                perror("recv");
            cout<<buff<<endl;
            tcp_close(sockfd);
        }
        else if(strncmp(input.c_str(), "store", 5) == 0){
            cout<<"SDFS files stored:"<<endl;
            for(auto it = my_vm_info.sdfs_files.begin(); it!= my_vm_info.sdfs_files.end(); it++){
                cout<<(*it).substr(5)<<endl;
            }
        }
        else if(strncmp(input.c_str(), "MyVM", 4) == 0){   //Print VM info
            isJoin_lock.lock();
            if(isJoin == false){
                cout << "VM is NOT running!!!\n";
                isJoin_lock.unlock();
                continue;
            }
            cout << "My VM info: id: " << my_vm_info.vm_num << " --- ip: "<< my_vm_info.ip_addr_str << " --- ts: "<<my_vm_info.time_stamp<<"\n";
            isJoin_lock.unlock();
        }
        else if(strncmp(input.c_str(), "ph", 2) == 0){
            if(put_happening.empty())
                cout<<"put_happening is empty"<<endl;
            else
                cout<<"put_happening is "<<put_happening<<endl;
        }
        else if(strncmp(input.c_str(), "VMF", 3) == 0){
            cout<<"VM_to_files map: "<<endl;
            for(auto it = my_vm_info.VM_to_files_map.begin(); it != my_vm_info.VM_to_files_map.end(); it++){
                vector<string> v = it->second;
                cout << it->first << "has : "<< endl;
                for(unsigned int i = 0; i < v.size(); i++)
                    cout << v[i] << endl;
            }
        }
        else if(strncmp(input.c_str(), "MFD", 3) == 0){
            cout<<"master_file_directory: "<<endl;
            for(auto it = my_vm_info.master_file_directory.begin(); it != my_vm_info.master_file_directory.end(); it++){
                vector<string> v = it->second;
                cout << it->first << " is @ : "<< endl;
                for(unsigned int i = 0; i < v.size(); i++)
                    cout << v[i] << endl;
            }
        }
        else if(strncmp(input.c_str(), "M", 1) == 0){
            cout<<"master: "<<my_vm_info.master_ip<<endl;
        }
        else if(strncmp(input.c_str(), "V", 1) == 0){
            auto x = my_vm_info.partitions.begin();
            for(int i = 0; i < NUM_PARTITIONS; i++){
                cout<<"Partition "<<*(x++)<<" has:"<<endl;
                for(auto vertex = my_vm_info.vertex_state[i].begin(); vertex != my_vm_info.vertex_state[i].end(); vertex++){
                    cout<<"Vertex :"<<vertex->first<<endl;
                    cout<<"Edges :";
                    for(auto edge = vertex->second.outgoing_edges.begin(); edge != vertex->second.outgoing_edges.end(); edge++){
                        cout<<*(edge)<<" ";
                    }
                    cout<<endl;
                }
            }
        }
        else if(strncmp(input.c_str(), "X", 1) == 0){
            auto x = my_vm_info.partitions.begin();
            for(int i = 0; i < NUM_PARTITIONS; i++){
                cout<<"Partition "<<*(x++)<<" has:"<<endl;
                for(auto vertex = my_vm_info.vertex_state[i].begin(); vertex != my_vm_info.vertex_state[i].end(); vertex++){
                    cout<<"Vertex :"<<vertex->first<<" has value :"<<vertex->second.current_value;
                    cout<<endl;
                }
            }
        }
        else if(strncmp(input.c_str(), "Z", 1) == 0){
            cout<<my_vm_info.num_vertices<<endl;
        }
        else if(strncmp(input.c_str(), "TASK", 4) == 0){
            cout<<"Requesting Task To Master: "<<my_vm_info.master_ip<<endl;
            if(my_vm_info.ip_addr_str == my_vm_info.SAVA_Client){
            cout<<"Enter graph file name"<<endl;
            string sdfsfilename;
            cin>>sdfsfilename;
            cout<<"Enter application file name"<<endl;
            string app;
            cin>>app;
            cout<<"Sending graph and application to Sava. Please be patient"<<endl;

            //SEND contents of the file and wait to get ACK from Master
            string IP = my_vm_info.SAVA_Master;
            string requester_IP = my_vm_info.ip_addr_str;
            UDP local_udp;
            Protocol p;

            FILE *p_file = fopen(sdfsfilename.c_str(), "r");
            // First: Send the file size
            fseek(p_file,0,SEEK_END);
            unsigned long numbytes = ftell(p_file);
            fclose(p_file);
            string send_to_master = p.create_TASK_msg(numbytes, sdfsfilename, requester_IP);
            const char * ip = IP.c_str();
            const char * msg = send_to_master.c_str();
            int sockfd = tcp_connect(ip);
            if(sockfd == -1){
                cout<<"FAILED: TRY AGAIN"<<endl;
                continue;
            }
            tcp_send(sockfd, ip, msg);

            //wait for ack from master
            char buff[3];
            int rcv;
            if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
                perror("recv");
            cout<<"received ack"<<endl;

            // Second: Send the file contents
            FILE *fp = fopen(sdfsfilename.c_str(), "r");
            if(fp == NULL){
                printf("File open error\n");
                exit(0);
            }
            while(1){
                char buff[256] = {0};
                int bytesToWrite = fread(buff,1,256,fp);
                if(bytesToWrite > 0){
                    int bytesWritten = 0;
                    while(bytesWritten != bytesToWrite){
                        int sent;
                        sent = write(sockfd, buff + bytesWritten, (bytesToWrite - bytesWritten));
                        if(sent == -1){
                            printf("Error sending file\n");
                            exit(0);
                        }
                        bytesWritten += sent;
                    }
                }
                // error checking
                if(bytesToWrite < 256){
                    if(feof(fp))
                        printf("End of file\n");
                    if(ferror(fp))
                        printf("Error in reading of file\n");
                    break;
                }
            }
            fclose(fp);
            //wait for second ack from master
            if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
                perror("recv");
            cout<<"received ack for prep to appl send"<<endl;

            //send application file
            p_file = fopen(app.c_str(), "r");
            // First: Send the file size
            fseek(p_file,0,SEEK_END);
            numbytes = ftell(p_file);
            fclose(p_file);
            send_to_master = to_string(numbytes);
            msg = send_to_master.c_str();
            tcp_send(sockfd, ip, msg);

            //wait for ack from master
            if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
                perror("recv");
            cout<<"received ack for prep to appl file send"<<endl;

            // Second: Send the file contents
            fp = fopen(app.c_str(), "r");
            if(fp == NULL){
                printf("File open error\n");
                exit(0);
            }
            while(1){
                char buff[256] = {0};
                int bytesToWrite = fread(buff,1,256,fp);
                if(bytesToWrite > 0){
                    int bytesWritten = 0;
                    while(bytesWritten != bytesToWrite){
                        int sent;
                        sent = write(sockfd, buff + bytesWritten, (bytesToWrite - bytesWritten));
                        if(sent == -1){
                            printf("Error sending file\n");
                            exit(0);
                        }
                        bytesWritten += sent;
                    }
                }
                // error checking
                if(bytesToWrite < 256){
                    if(feof(fp))
                        printf("End of file\n");
                    if(ferror(fp))
                        printf("Error in reading of file\n");
                    break;
                }
            }


            tcp_close(sockfd);
            }
            else
                cout<<"Not client"<<endl;
        }
    }

     cout << "Quit Successfully\n";

    //Wait for all other threads to stop
     listener_thread.join();
     heartbeat_sender_thread.join();
     heartbeat_checker_thread.join();

    my_logger.write_to_file("vm_log");


    return 0;
}
