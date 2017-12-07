//
//  Message.cpp
//
//
//  Created by Hieu Huynh on 9/27/17.
//

#include <stdio.h>
#include "Protocol.h"

#include <sstream>
#include <random>
#include <thread>
#include <algorithm>    // for min
#include <fstream>
#include <dlfcn.h>

#include "logging.h"
#include "common.h"
#include "md5.h"
#include "UDP.h"

extern membership::Logger::Handle protocol_log;

void send_gossip_helper(vector<string> msg, bool haveLock);

int cur_partition = 0;
int done_counter = 0;
void * dlhandler;
/*This function create the H_msg with format: | H | VM_num | \n |
 *Input:    None
 *Output:   HB msg
 */
string Protocol::create_H_msg(){
    string msg("H");
    msg.append(int_to_string(my_vm_info.vm_num));
    msg.append("\n");
    return msg;
}

/*This function create the J_msg with format: | J | ip_address | timestamp | \n|
 *Input:    None
 *Output:   J msg
 */
string Protocol::create_J_msg(){
    string msg("J");
    for(int i = 0 ; i < IP_LEN; i++){
        msg.push_back((unsigned char) my_vm_info.ip_addr[i]);
    }
    msg.append(my_vm_info.time_stamp);
    msg.append("\n");
    return msg;
}


/*This function create the N_msg with format: | N | VM_id | \n |
 *Input:    None
 *Output:   N msg
 */
string Protocol::create_N_msg(string id_str) {
    string msg = "N" + id_str + "\n";
    return msg;
}

/*This function create the L_msg with format: | L | VM_num | \n |
 *Input:    None
 *Output:   HB msg
 */
string Protocol::create_L_msg(int vm_num) {
    string msg("L");
    msg.append(int_to_string(vm_num));
    msg.append("\n");
    return msg;
}

/*This function create the I_msg with format: | I | vm_num | size of membership list (i) | VM0 | VM1 | ... |VMi| \n |
 *Input:    None
 *Output:   I msg
 */
string Protocol::create_I_msg(vector<string> vm_list, int vm_num_){
    string msg("I");
    msg.append(int_to_string(vm_num_));
    msg.append(int_to_string((int)vm_list.size()));

    for(int i = 0 ; i < (int)vm_list.size(); i++){
        msg.append(vm_list[i]);
    }

    msg.append("\n");
    return msg;
}

/*This function create the G_msg with format: | G | rtt | msg | \n |
 *Input:    None
 *Output:   G msg
 */
string Protocol::create_G_msg(string msg, int num_retransmits) {
    ostringstream ss;
    ss << "G" << num_retransmits << msg;
    return ss.str();
}

/*This function create the T_msg with format: | G | vm_num | \n |
 *Input:    None
 *Output:   T msg
 */
string Protocol::create_T_msg(){
    string msg("T");
    msg.append(int_to_string(my_vm_info.vm_num));
    msg.push_back('\n');
    return msg;
}


/*This function create the Q_msg with format: | Q | vm_num | \n |
 *Input:    None
 *Output:   Q msg
 */
string Protocol::create_Q_msg(){
    string msg("Q");
    msg.append(int_to_string(my_vm_info.vm_num));
    msg.append("\n");
    return msg;
}

/*This function create the P_msg with format: | P | numbytes | filename | \n |
 *Input:    None
 *Output:   P msg
 */
string Protocol::create_P_msg(unsigned long numbytes, string sdfsfilename, string requester_IP){
    string msg("P ");
    msg.append(to_string(numbytes));
    msg.append(" ");
    msg.append(sdfsfilename);
    msg.append(" ");
    msg.append(requester_IP);
    msg.append("\n");
    return msg;
}

/*This function create the SHARD_msg with format: | P | numbytes | filename | \n |
 *Input:    None
 *Output:   P msg
 */
string Protocol::create_SHARD_msg(unsigned long numbytes, string sdfsfilename, string requester_IP){
    string msg("SHARD ");
    msg.append(to_string(numbytes));
    msg.append(" ");
    msg.append(sdfsfilename);
    msg.append(" ");
    msg.append(requester_IP);
    msg.append("\n");
    return msg;
}

/*This function create the GET_msg with format: | GET | sdfsfilename | requester'sIP | \n |
 *Input:    None
 *Output:   P msg
 */
string Protocol::create_GET_msg(string sdfsfilename, string requester_IP, string localfilename){
    string msg("GET ");
    msg.append(sdfsfilename);
    msg.append(" ");
    msg.append(requester_IP);
    msg.append(" ");
    msg.append(localfilename);
    msg.append("\n");
    return msg;
}

/*This function create the GOT_msg with format: | GOT | sdfsfilename | requester'sIP | \n |
 *Input:    None
 *Output:   GOT msg
 */
string Protocol::create_GOT_msg(string sdfsfilename, string requester_IP, string localfilename){
    string msg("GOT ");
    msg.append(sdfsfilename);
    msg.append(" ");
    msg.append(requester_IP);
    msg.append(" ");
    msg.append(localfilename);
    msg.append("\n");
    return msg;
}

/*This function create the ls_msg with format: | LS | sdfsfilename | \n |
 *Input:    sdfsfilename requester_IP
 *Output:   ls msg
 */
string Protocol::create_LS_msg(string sdfsfilename, string requester_IP){
    string msg("LS ");
    msg.append(sdfsfilename);
    msg.append(" ");
    msg.append(requester_IP);
    msg.append("\n");
    return msg;
}

/*This function create the ls_msg with format: | LS | sdfsfilename | \n |
 *Input:    sdfsfilename requester_IP
 *Output:   ls msg
 */
string Protocol::create_START_msg(string worker_ip){
    string msg("START ");
    msg.append(worker_ip);
    msg.append("\n");
    return msg;
}

/*This function create the ss_msg with format: | SS | number | \n |
*/
string Protocol::create_SS_msg(int superstep){
    string msg("SS ");
    msg.append(int_to_string(superstep));
    msg.append("\n");
    return msg;
}

/*This function create the ss_msg with format: | SS | number | \n |
*/
string Protocol::create_DONE_msg(bool active_flag, string worker){
    string msg("DONE ");
    if(active_flag)
      msg.append("true");
    else
      msg.append("false");
    msg.append(" ");
    msg.append(worker);
    msg.append("\n");
    return msg;
}

/*This function create the DEL_msg with format: | DEL | sdfsfilename | \n |
 *Input:    sdfsfilename
 *Output:   del msg
 */
string Protocol::create_DEL_msg(string sdfsfilename){
    string msg("DEL ");
    msg.append(sdfsfilename);
    msg.append("\n");
    return msg;
}

/*This function create the DELETE_msg with format: | DEL | sdfsfilename | \n |
 *Input:    sdfsfilename
 *Output:   del msg
 */
string Protocol::create_DELETE_msg(string sdfsfilename){
    string msg("DELETE ");
    msg.append(sdfsfilename);
    msg.append("\n");
    return msg;
}

/*This function create the SAVAReg with format: | SAVAReg | worker_ip | \n |
 *Input:    worker_ip
 *Output:   register message
 */
string Protocol::create_SAVAReg_msg(string worker_ip){
    string msg("SAVAReg ");
    msg.append(worker_ip);
    msg.append("\n");
    return msg;
}

/*This function create the task with format: | SAVAReg | worker_ip | \n |
 *Input:    worker_ip
 *Output:   register message
 */
string Protocol::create_TASK_msg(unsigned long numbytes, string sdfsfilename, string requester_IP){
    string msg("TASK ");
    msg.append(to_string(numbytes));
    msg.append(" ");
    msg.append(sdfsfilename);
    msg.append(" ");
    msg.append(requester_IP);
    msg.append("\n");
    return msg;
}

/*This function create the task with format: | APP | destination_vertex | partition_number | message \n |
 *Input:    worker_ip
 *Output:   register message
 */
string Protocol::create_APP_msg(string destination_vertex, long double message, int partition_number){
    string msg("APP ");
    msg.append(destination_vertex);
    msg.append(" ");
    msg.append(int_to_string(partition_number));
    msg.append(" ");
    msg.append(to_string(message));
    msg.append("\n");
    return msg;
}



/*This function create the ls_msg with format: | ALIVE | alive_workers | \n |
 *Input:    sdfsfilename requester_IP
 *Output:   ls msg
 */
string Protocol::create_ALIVE_msg(set<string> alive_workers){
    string msg("ALIVE ");
    for(auto it = alive_workers.begin(); it != alive_workers.end(); it++){
      msg.append(" ");
      msg.append(*it);
    }
    msg.append("\n");
    return msg;
}

string Protocol::create_PART_msg(unordered_map<int, string> partitions_to_VMs){
  string msg("PART ");
  for(auto it = partitions_to_VMs.begin(); it != partitions_to_VMs.end(); it++){
    msg.append(" ");
    msg.append(int_to_string(it->first));
    msg.append(" ");
    msg.append(it->second);
  }
  msg.append("\n");
  return msg;
}

/*This function create the FD_msg with format: | FD | IP | filenames | \n |
 *Input:    None
 *Output:   FD msg
 */
string Protocol::create_VMF_msg(string IP, vector<string> filenames){
    string msg("VMF ");
    msg.append(IP);
    if(filenames.empty()){
        msg.append("\n");
        return msg;
    }
    for(unsigned int i = 0; i < filenames.size(); i++){
        msg.append(" ");
        msg.append(filenames[i]);
    }
    msg.append("\n");
    cout << "FD MESSAGE CREATED: " <<msg<<endl;
    return msg;
}

/*This function create the MasterFD_msg with format: | MASTERFD | sdfsfilename | ips | \n |
 *Input:    None
 *Output:   FD msg
 */
string Protocol::create_MASTERFD_msg(string sdfsfilename, vector<string> ip){
    string msg("MASTERFD ");
    msg.append(sdfsfilename);
    for(unsigned int i = 0; i < ip.size(); i++){
        msg.append(" ");
        msg.append(ip[i]);
    }
    msg.append("\n");
    cout << "MASTERFD MESSAGE CREATED: " <<msg<<endl;
    return msg;
}


/* This function handle H_msg and update HB of HB targets
 *input:    msg: H_msg
 *output:   NONE
 */
void Protocol::handle_H_msg(string msg){
    membership_list_lock.lock();
    hb_targets_lock.lock();

    string sender_id_str = msg.substr(1,2);
    int sender_id = string_to_int(sender_id_str);
    time_t cur_time;
    cur_time = time (NULL);
    //Update the H_msg of the HB
    if(hb_targets.find(sender_id) != hb_targets.end() && vm_info_map.find(sender_id) != vm_info_map.end()){
        vm_info_map[sender_id].heartbeat = (long) cur_time;
    }

    hb_targets_lock.unlock();
    membership_list_lock.unlock();
    return;
}

/* This function handle J_msg and update membershiplist, send gossip and response with I msg
 *input:    msg: J_msg
 *output:   NONE
 */
void Protocol::handle_J_msg(string msg){
    membership_list_lock.lock();
    unsigned char sender_ip[4];
    string sender_time_stamp;


    //Get data from msg
    for(int i= 0 ; i < IP_LEN; i++){
        sender_ip[i] = msg[1+i];
    }
    string sender_ip_str("");
    for(int i = 0 ; i < IP_LEN; i++){
        sender_ip_str.append(to_string((unsigned int) sender_ip[i]));
        if(i != IP_LEN -1){
            sender_ip_str.push_back('.');
        }
    }
    sender_time_stamp = msg.substr(5, 10);
    bool is_in_ML = false;

    //Determined if this is a duplicate request
    int sender_id =-1;
    for(auto it = vm_info_map.begin(); it != vm_info_map.end(); it++){
        if(strcmp(it->second.time_stamp.c_str(), sender_time_stamp.c_str()) == 0
           && strcmp(it->second.ip_addr_str.c_str(), sender_ip_str.c_str()) == 0 ){
            is_in_ML = true;
        sender_id = it->second.vm_num;
        }
    }


    //Update membershiplist
    if(is_in_ML == false){
        for(int i = 0 ; i < (int)membership_list.size() +1; i++){
            if(membership_list.find(i) != membership_list.end()){
                continue;
            }
            sender_id = i;
            break;
        }
        membership_list.insert(sender_id);
        VM_info new_vm(sender_id, sender_ip, sender_time_stamp);
        vm_info_map[sender_id] = new_vm;
        cout <<"VM with id: " << new_vm.vm_num << " JOIN.";
        protocol_log << "VM with id: " << new_vm.vm_num <<= " JOIN.";
        print_membership_list();

        //Gossip the msg
        Protocol p;
        p.gossip_msg(p.create_N_msg(new_vm.id_str), true);
    }

    vector<string> vm_list;

    //Create I msg to reponse to new VM
    for(auto it = vm_info_map.begin(); it != vm_info_map.end(); it++){
        vm_list.push_back(it->second.id_str);
    }
    string i_msg = create_I_msg(vm_list, sender_id);

    //Send I msg to new VM
    UDP local_udp;
    string ip_addr_str("");
    for(int i = 0; i < IP_LEN; i++){
        int num = (int) sender_ip[i];
        ip_addr_str.append(to_string(num));
        if(i != IP_LEN-1)
            ip_addr_str.push_back('.');
    }
    local_udp.send_msg(ip_addr_str, i_msg);

    //Update HB targets
    if(is_in_ML == false){
        hb_targets_lock.lock();
        update_hb_targets(true);

        hb_targets_lock.unlock();
    }
    membership_list_lock.unlock();

    return;
}


/* This function handle N_msg and update membershiplist
 *input:    msg: N_msg
 *output:   NONE
 */
void Protocol::handle_N_msg(string msg, bool haveLock){
    //Get data from msg
    string new_node_id_str = msg.substr(1,16);
    VM_info new_vm(new_node_id_str);
    string new_node_num_str = msg.substr(1,2);

    int new_node_num = string_to_int(new_node_num_str);

    //Update membership list
    if(haveLock == false)
        membership_list_lock.lock();
    set<int>::iterator it = membership_list.find(new_node_num);
    if(it == membership_list.end()) {
        membership_list.insert(new_node_num);
        vm_info_map[new_node_num] = new_vm;

        //update hb_targets
        hb_targets_lock.lock();
        update_hb_targets(true);
        hb_targets_lock.unlock();
    }
    cout << "VM with id: " << new_node_num << " JOIN.";
    protocol_log << "VM with id: " << new_node_num <<= " JOIN.";
    print_membership_list();

    if(haveLock == false)
        membership_list_lock.unlock();

    return;
}

/* This function handle L_msg and update membershiplist
 *input:    msg: L_msg
 *output:   NONE
 */
void Protocol::handle_L_msg(string msg, bool haveLock){
    //Get data from msg
    string new_node_num_str = msg.substr(1,2);
    int new_node_num = string_to_int(new_node_num_str);

    //Update membership list
    if(haveLock == false)
        membership_list_lock.lock();
    string dead_ip = vm_info_map[new_node_num].ip_addr_str;
    membership_list.erase(new_node_num);
    vm_info_map.erase(new_node_num);

    //update hb_targets
    hb_targets_lock.lock();
    update_hb_targets(true);
    hb_targets_lock.unlock();

    cout << "VM with id: " << new_node_num << " FAIL.";
    protocol_log << "VM with id: " << new_node_num <<= " FAIL.";
    print_membership_list();

    if(haveLock == false)
        membership_list_lock.unlock();

    if(dead_ip == my_vm_info.master_ip){
        if(haveLock == false)
            membership_list_lock.lock();
        my_vm_info.master_ip = vm_info_map[*membership_list.begin()].ip_addr_str;
        if(haveLock == false)
            membership_list_lock.unlock();
        cout<<"ELECTED: "<<my_vm_info.master_ip<<endl;
    }
    if(my_vm_info.ip_addr_str == my_vm_info.master_ip){
        cout<<"calling failure handler"<<endl;
        std::thread failure_handler_thread = std::thread(handle_fail, dead_ip, false);
        failure_handler_thread.detach();
    }

}

/* This function handle I_msg and update membershiplist
 *input:    msg: I_msg
 *output:   NONE
 */
void Protocol::handle_I_msg(string msg){

     //Extract membership list data from msg
    my_vm_info.vm_num = string_to_int( msg.substr(1,2));

    string num_node_str = msg.substr(3,2);
    int num_node = string_to_int(num_node_str);
    vector<string> nodes;
    vector<int> nodes_num;

    for(int i = 0 ; i < num_node; i++){
        nodes.push_back( msg.substr(5+ i*ID_LEN, ID_LEN));
        nodes_num.push_back(string_to_int(msg.substr(5 + i*ID_LEN,2)));
    }

    membership_list_lock.lock();

     //Add VMs from I_msg to membershiplist
    for(int i = 0 ; i < (int)nodes.size(); i++){
        membership_list.insert(nodes_num[i]);
        VM_info new_node(nodes[i]);
        vm_info_map[nodes_num[i]] = new_node;
    }

    hb_targets_lock.lock();
    update_hb_targets(true);

    hb_targets_lock.unlock();
    membership_list_lock.unlock();
}

/* This function handle G_msg and call corresponsding handler
 *input:    msg: G_msg
 *output:   NONE
 */
void Protocol::handle_G_msg(string msg, bool haveLock) {
    if(haveLock == false)
        membership_list_lock.lock();

    int rem_retransmits = string_to_int(msg.substr(1,1));
    string str = msg.substr(2);
    int target_id = string_to_int(str.substr(1,2));


    //If msg is N_msg, call N_msg handler
    if(str[0] == 'N'){
        if(membership_list.find(target_id) == membership_list.end()){
            handle_N_msg(str, true);
        }
        else{
            if(haveLock == false)
                membership_list_lock.unlock();
            return;
        }
    }
    else if(str[0] == 'L') {    //If msg is L_msg, call L_msg handler
        if(membership_list.find(target_id) != membership_list.end()){
            handle_L_msg(str, true);
        }
        else{
            if(haveLock == false)
                membership_list_lock.unlock();
            return;
        }
    }
    else if(str[0] == 'Q'){     //If msg is Q_msg, call Q_msg handler
        if(membership_list.find(target_id) != membership_list.end()){
            handle_Q_msg(str, true);
        }
        else{
            if(haveLock == false)
                membership_list_lock.unlock();
            return;
        }
    }

    //Gossip the message
    vector<string> msg_v;
    while(rem_retransmits > 0){
        rem_retransmits--;
        msg[1] = rem_retransmits +'0';
        msg_v.push_back(msg);
    }
    send_gossip_helper(msg_v, true);

    if(haveLock == false)
        membership_list_lock.unlock();

    return;
}

/* This function handle T_msg and update hearbeat targets
 *input:    msg: T_msg
 *output:   NONE
 */
void Protocol::handle_T_msg(string msg, bool haveLock){
    if(haveLock == false){
        membership_list_lock.lock();
        hb_targets_lock.lock();
    }
    //Get data from msg
    int sender_id = string_to_int(msg.substr(1,2));

    //Update HB targets
    if(hb_targets.find(sender_id) != hb_targets.end()){
        vm_info_map[sender_id].heartbeat = 0;
        hb_targets.erase(sender_id);
    }

    if(haveLock == false){
        membership_list_lock.unlock();
        hb_targets_lock.unlock();
    }
    return;
}

/* This function handle Q_msg and update membershiplist
 *input:    msg: Q_msg
 *output:   NONE
 */
void Protocol::handle_Q_msg(string msg, bool haveLock){
    string new_node_num_str = msg.substr(1,2);
    int new_node_num = string_to_int(new_node_num_str);

    //Update membership list
    if(haveLock == false)
        membership_list_lock.lock();
    string dead_ip = vm_info_map[new_node_num].ip_addr_str;
    membership_list.erase(new_node_num);
    vm_info_map.erase(new_node_num);

    //update hb_targets
    hb_targets_lock.lock();
    update_hb_targets(true);
    hb_targets_lock.unlock();

    cout <<"VM with id: " << new_node_num << " VOLUNTARILY LEAVE.";
    protocol_log << "VM with id: " << new_node_num <<= " VOLUNTARILY LEAVE.";
    print_membership_list();

    if(haveLock == false)
        membership_list_lock.unlock();

     if(dead_ip == my_vm_info.master_ip){
        if(haveLock == false)
            membership_list_lock.lock();
        my_vm_info.master_ip = vm_info_map[*membership_list.begin()].ip_addr_str;
        if(haveLock == false)
            membership_list_lock.unlock();
        cout<<"ELECTED: "<<my_vm_info.master_ip<<endl;
    }
    if(my_vm_info.ip_addr_str == my_vm_info.master_ip){
        cout<<"calling failure handler"<<endl;
        std::thread failure_handler_thread = std::thread(handle_fail, dead_ip, false);
        failure_handler_thread.detach();
    }
}

/* This function handle start msg and starts graph processing
 *input:    msg: N_msg
 *output:   NONE
 */
void Protocol::handle_START_msg(string msg, bool haveLock){
  UDP local_udp;
  Protocol p;
  std::istringstream iss;
  vector<std::string> result;
  iss.str(msg);
  for (string s; iss>>s; )
      result.push_back(s);

  string worker_ip = result[1];
  cout << "In handle_START_msg: worker_ip: " << worker_ip << endl;
  my_vm_info.bitmap[worker_ip] = true;
  // can start task is all active workers are true
  int counter = 0;
  int num_workers;
  if(!haveLock)
    worker_lock.lock();
  for(auto it = my_vm_info.alive_workers.begin(); it != my_vm_info.alive_workers.end(); it++){
    cout << "*it here: " << *it << endl;
    if(my_vm_info.bitmap.find(*it) != my_vm_info.bitmap.end()){
      if(my_vm_info.bitmap[*it] == true)
        counter++;
    }
  }
  num_workers = my_vm_info.alive_workers.size();
  if(!haveLock)
    worker_lock.unlock();
  cout << "num workers: " << num_workers << endl;
  cout << "counter: " << counter << endl;
  if(counter == num_workers){
    counter = 0;
    cout << "All have acknowledged; Can start the TASK; " << endl;
  }
  cout << "Superstep was: " << my_vm_info.superstep << endl;
  my_vm_info.superstep = 1;
  string start_ss = p.create_SS_msg(my_vm_info.superstep);
  cout << "start ss message is: " << start_ss << endl;
  string dest;
  if(!haveLock)
    worker_lock.lock();
  for(auto it = my_vm_info.alive_workers.begin(); it != my_vm_info.alive_workers.end(); it++){
    dest = *it;
    cout << "destination is: " << *it << endl;
    local_udp.send_msg(dest, start_ss);
    if(!haveLock)
        worker_lock.unlock();
    if(!haveLock)
        worker_lock.lock();
  }
  if(!haveLock)
    worker_lock.unlock();
}


/* This function handle P_msg_helper
 *input:    msg: P_msg
 *output:   NONE
*/
void handle_P_helper(unsigned long numbytes, string IP, string sdfsfilename, string requester_IP){
    UDP local_udp;
    Protocol p;
    string buffer;
    char buf[1024];
    int sentbytes = 0;
    int count;

    string send_to_master = p.create_P_msg(numbytes, sdfsfilename, requester_IP);
    const char * ip = IP.c_str();
    const char * msg = send_to_master.c_str();
    int sockfd = tcp_connect(ip);
    if(sockfd == -1){
        cout<<"FAILED"<<endl;
        return;
    }
    tcp_send(sockfd, ip, msg);
    //wait for ack from master
    char buff[3];
    int rcv;
    if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
        perror("recv");
    cout<<"RECEIVED ACK"<<endl;
    cout<<"numbytes are "<<numbytes<<"and sdfsfilename is "<<sdfsfilename<<endl;
    //send file
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
    tcp_close(sockfd);
}

/* This function handle P_msg
 *input:    msg: P_msg
 *output:   NONE
*/
void Protocol::handle_P_msg(string msg, bool haveLock, int my_file_socket_fd){
    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string receiveBytes = result[1];
    string sdfsfilename = result[2];
    string requester_IP = result[3];

    if(my_vm_info.ip_addr_str == my_vm_info.master_ip){
        sdfsfilename = "sdfs_" + sdfsfilename;
        //send PUTNOTIFY to all machines
        string notification = "PUTNOTIFY " + sdfsfilename + "\n";
        if(!haveLock)
            membership_list_lock.lock();
        for(auto it = membership_list.begin(); it!= membership_list.end(); it++){
            local_udp.send_msg(vm_info_map[*it].ip_addr_str, notification);
        }
        if(!haveLock)
            membership_list_lock.unlock();
    }

    unsigned long numbytes = stoul(receiveBytes);

    FILE *fp = fopen(sdfsfilename.c_str(), "w");
    if(fp == NULL){
         printf("File open error\n");
         exit(0);
    }
    char *buff = new char[numbytes];
    unsigned long bytesRead = 0;
    while(bytesRead != numbytes){
        if(!haveLock)
            membership_list_lock.lock();
        auto it = membership_list.begin();
        while(it != membership_list.end()){
            if(vm_info_map[*it].ip_addr_str == requester_IP)
                break;
            it++;
        }
        if(it == membership_list.end()){
            if(!haveLock)
                membership_list_lock.unlock();
            cout<<"Failed while PUT - Abort"<<endl;
            system(("rm " + sdfsfilename).c_str());
            return;
        }
        if(!haveLock)
            membership_list_lock.unlock();
        int readNow;
        readNow = read(my_file_socket_fd, buff + bytesRead, (numbytes- bytesRead));
        if(readNow == -1){
              perror("read");
              printf("Error sending file\n");
              exit(0);
        }
        bytesRead += readNow;
    }
    fwrite(buff,1, numbytes,fp);
    fclose(fp);
    free(buff);

    // If MASTER, Hash and send it out;
    // Else add to set and exit as already stored
    if(my_vm_info.ip_addr_str == my_vm_info.master_ip){
        cout<<"In handle_P_msg: in master code"<<endl;

        // If file is already present in SDFS
        if(my_vm_info.master_file_directory.find(sdfsfilename) != my_vm_info.master_file_directory.end()){

            string dest_1_IP = my_vm_info.master_file_directory[sdfsfilename][0];
            string dest_2_IP = my_vm_info.master_file_directory[sdfsfilename][1];
            string dest_3_IP = my_vm_info.master_file_directory[sdfsfilename][2];

            if(dest_1_IP == my_vm_info.master_ip)
                my_vm_info.sdfs_files.insert(sdfsfilename);
            else{
                handle_P_helper(numbytes, dest_1_IP, sdfsfilename, requester_IP);
            }
            if(dest_2_IP == my_vm_info.master_ip)
                my_vm_info.sdfs_files.insert(sdfsfilename);
            else{
                handle_P_helper(numbytes, dest_2_IP, sdfsfilename, requester_IP);
            }
            if(dest_3_IP == my_vm_info.master_ip)
                my_vm_info.sdfs_files.insert(sdfsfilename);
            else{
                handle_P_helper(numbytes, dest_3_IP, sdfsfilename, requester_IP);
            }
            cout<<"After sending to all destinations"<<endl;
            if(dest_1_IP != my_vm_info.master_ip && dest_2_IP != my_vm_info.master_ip && dest_3_IP != my_vm_info.master_ip)
                system(("rm " + sdfsfilename).c_str());
            return;
        }

        //new file addition - find locations
        string hash = md5(sdfsfilename);
        std::istringstream converter(hash.substr(27));
        unsigned int value, size;
        converter >> std::hex >> value;

        if(!haveLock)
            membership_list_lock.lock();

        size = (unsigned int) membership_list.size();
        auto it = membership_list.begin();
        int assign = (int)(value%size);
        while(assign){
            ++it;
            assign--;
        }
        VM_info location1 = vm_info_map[*it];
        VM_info location2;
        VM_info location3;
        cout<<"LOCATION 1: "<<location1.ip_addr_str<<endl;

        for(it = membership_list.begin(); it != membership_list.end(); it++){
            auto curr = it;
            curr++;
            if(curr == membership_list.end() && vm_info_map[*it].vm_num == location1.vm_num){
                auto loc2 = it;
                auto loc3 = it;
                location2 = vm_info_map[*(--(--loc2))];
                location3 = vm_info_map[*(--loc3)];
                cout << "Last element: "<<endl;
                cout << "LOCATION1 VM_NUM: " <<location1.vm_num <<endl;
                cout << "LOCATION2 VM_NUM: " <<location2.vm_num <<endl;
                cout << "LOCATION3 VM_NUM: " <<location3.vm_num <<endl;
                break;
            }
            if(it == membership_list.begin() && vm_info_map[*it].vm_num == location1.vm_num){
                auto loc2 = it;
                auto loc3 = it;
                location2 = vm_info_map[*(++loc2)];
                location3 = vm_info_map[*(++(++loc3))];
                cout << "first element: "<<endl;
                cout << "LOCATION1 VM_NUM: " <<location1.vm_num <<endl;
                cout << "LOCATION2 VM_NUM: " <<location2.vm_num <<endl;
                cout << "LOCATION3 VM_NUM: " <<location3.vm_num <<endl;
                break;
            }
            if(vm_info_map[*it].vm_num == location1.vm_num){
                auto loc2 = it;
                auto loc3 = it;
                location2 = vm_info_map[*(++loc2)];
                location3 = vm_info_map[*(--loc3)];
                cout << "mid element: "<<endl;
                cout << "LOCATION1 VM_NUM: " <<location1.vm_num <<endl;
                cout << "LOCATION2 VM_NUM: " <<location2.vm_num <<endl;
                cout << "LOCATION3 VM_NUM: " <<location3.vm_num <<endl;
                break;
            }
            cout<<"FAILED TO ALLOCATE LOCATIONS"<<endl;
        }
        if(!haveLock)
            membership_list_lock.unlock();

        cout << "location1" << location1.vm_num << endl;
        cout << "location2" << location2.vm_num << endl;
        cout << "location3" << location3.vm_num << endl;

        string dest_1_IP = location1.ip_addr_str;
        string dest_2_IP = location2.ip_addr_str;
        string dest_3_IP = location3.ip_addr_str;

        // Add to the VM to files map - put for all new files
        my_vm_info.VM_to_files_map[dest_1_IP].push_back(sdfsfilename);
        string message_1 = create_VMF_msg(dest_1_IP, my_vm_info.VM_to_files_map[dest_1_IP]);
        my_vm_info.VM_to_files_map[dest_2_IP].push_back(sdfsfilename);
        string message_2 = create_VMF_msg(dest_2_IP, my_vm_info.VM_to_files_map[dest_2_IP]);
        my_vm_info.VM_to_files_map[dest_3_IP].push_back(sdfsfilename);
        string message_3 = create_VMF_msg(dest_3_IP, my_vm_info.VM_to_files_map[dest_3_IP]);

        vector<string> collection;
        collection.push_back(dest_1_IP);
        collection.push_back(dest_2_IP);
        collection.push_back(dest_3_IP);

        my_vm_info.master_file_directory[sdfsfilename] = collection;
        string message_4 = create_MASTERFD_msg(sdfsfilename, collection);

        if(!haveLock)
            membership_list_lock.lock();
        for(it = membership_list.begin(); it != membership_list.end(); it++){
            string destination_ip = vm_info_map[*it].ip_addr_str;
            local_udp.send_msg(destination_ip, message_1);
            local_udp.send_msg(destination_ip, message_2);
            local_udp.send_msg(destination_ip, message_3);
            local_udp.send_msg(destination_ip, message_4);
        }
        if(!haveLock)
            membership_list_lock.unlock();

        if(dest_1_IP == my_vm_info.master_ip)
                my_vm_info.sdfs_files.insert(sdfsfilename);
        else{
            handle_P_helper(numbytes, dest_1_IP, sdfsfilename, requester_IP);
        }
        if(dest_2_IP == my_vm_info.master_ip)
            my_vm_info.sdfs_files.insert(sdfsfilename);
        else{
            handle_P_helper(numbytes, dest_2_IP, sdfsfilename, requester_IP);
        }
        if(dest_3_IP == my_vm_info.master_ip)
            my_vm_info.sdfs_files.insert(sdfsfilename);
        else{
            handle_P_helper(numbytes, dest_3_IP, sdfsfilename, requester_IP);
        }
        if(dest_1_IP != my_vm_info.master_ip && dest_2_IP != my_vm_info.master_ip && dest_3_IP != my_vm_info.master_ip)
            system(("rm " + sdfsfilename).c_str());
    }
    //received file to add to my sdfs
    else{
        my_vm_info.sdfs_files.insert(sdfsfilename);
    }
}

/* This function handle GET_msg and update membershiplist
 *input:    msg: GET_msg
 *output:   NONE
 */
void Protocol::handle_GET_msg(string msg, bool haveLock, int my_file_socket_fd){
    UDP local_udp;
    Protocol p;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string sdfsfilename = result[1];
    string requester_IP = result[2];
    string localfilename = result[3];
    cout<<sdfsfilename<<" "<<requester_IP<<" "<<localfilename<<endl;
    //check if requestor still alive
   if(!haveLock)
            membership_list_lock.lock();
    auto it = membership_list.begin();
    while(it != membership_list.end()){
        if(vm_info_map[*it].ip_addr_str == requester_IP)
            break;
        it++;
    }
    if(it == membership_list.end()){
        if(!haveLock)
            membership_list_lock.unlock();
        cout<<"Failed while GET1 - Abort"<<endl;
        return;
    }
    if(!haveLock)
        membership_list_lock.unlock();
    // If another node, send the file to requester
    // If master , list the nodes from data structure
    if(my_vm_info.ip_addr_str == my_vm_info.master_ip){
        cout<<"I am master"<<endl;
        if(my_vm_info.master_file_directory.find(sdfsfilename) != my_vm_info.master_file_directory.end()){
            cout<<"File found"<<endl;
            string location1 = my_vm_info.master_file_directory[sdfsfilename][0];
            string location2 = my_vm_info.master_file_directory[sdfsfilename][1];
            string location3 = my_vm_info.master_file_directory[sdfsfilename][2];
            cout<<"Locations: "<<location1<<" "<<location2<<" "<<location3<<endl;
            string alive_destination;

            if(!haveLock)
                membership_list_lock.lock();

            for(auto it = membership_list.begin(); it != membership_list.end(); it++){
                if(vm_info_map[*it].ip_addr_str == location1){
                    alive_destination = location1;
                    break;
                }
                else if(vm_info_map[*it].ip_addr_str == location2){
                    alive_destination = location2;
                    break;
                }
                else if(vm_info_map[*it].ip_addr_str == location3){
                    alive_destination = location3;
                    break;
                }
            }
            if(it == membership_list.end()){
                cout<<"FAILED TO FIND ALIVE LOCATIONS"<<endl;
                string msg = "FAIL\n";
                if (send(my_file_socket_fd, msg.c_str(), MAXDATASIZE, 0) == -1)
                     perror("send");
                return;
            }
            if(!haveLock)
                membership_list_lock.unlock();
            cout<<"alive loc"<<alive_destination<<endl;
            string msg = alive_destination + '\n';
            if (send(my_file_socket_fd, msg.c_str(), MAXDATASIZE, 0) == -1)
                 perror("send");
            return;
        }
        else{
            cout << "NO SUCH SDFS FILE EXISTS" << endl;
            string msg = "FAIL\n";
            if (send(my_file_socket_fd, msg.c_str(), MAXDATASIZE, 0) == -1)
                 perror("send");
            return;
        }
    }

}

/* This function handle GOT msg
 *input:    msg: J_msg
 *output:   NONE
 */
void Protocol::handle_GOT_msg(string msg, bool haveLock, int my_file_socket_fd){
    UDP local_udp;
    Protocol p;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string sdfsfilename = result[1];
    string requester_IP = result[2];
    string localfilename = result[3];
    cout<<sdfsfilename<<" "<<requester_IP<<" "<<localfilename<<endl;
    //check if requestor still alive
    if(!haveLock)
            membership_list_lock.lock();
    auto it = membership_list.begin();
    while(it != membership_list.end()){
        if(vm_info_map[*it].ip_addr_str == requester_IP)
            break;
        it++;
    }
    if(it == membership_list.end()){
        if(!haveLock)
            membership_list_lock.unlock();
        cout<<"Failed while GET1 - Abort"<<endl;
        return;
    }
    if(!haveLock)
        membership_list_lock.unlock();

    //send the output file
    FILE *fp = fopen(sdfsfilename.c_str(), "r");

    if(fp == NULL){
        printf("File open error\n");
        exit(0);
    }
        //get size of file
    fseek(fp, 0L, SEEK_END);
    int fileS = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    char fileSize[MAXDATASIZE];

    sprintf(fileSize, "%d", fileS);


    // Send the file size so the buffer knows what to expect
    if (send(my_file_socket_fd, fileSize, MAXDATASIZE, 0) == -1)
         perror("send");

    // File transfer over the socket back to the client

    while(1)
    {
        if(!haveLock)
            membership_list_lock.lock();
        auto it = membership_list.begin();
        while(it != membership_list.end()){
            if(vm_info_map[*it].ip_addr_str == requester_IP)
                break;
            it++;
        }
        if(it == membership_list.end()){
            if(!haveLock)
                membership_list_lock.unlock();
            cout<<"Failed while GET2 - Abort"<<endl;
            return;
        }
        if(!haveLock)
            membership_list_lock.unlock();
        char buff[256] = {0};
        int bytesToWrite = fread(buff,1,256,fp);

        if(bytesToWrite > 0)
        {

            int bytesWritten = 0;

            while(bytesWritten != bytesToWrite)
            {
                int sent;
                sent = write(my_file_socket_fd, buff + bytesWritten, (bytesToWrite - bytesWritten));
                //printf("%s %d\n", buff + bytesWritten, sent);

                if(sent == -1)
                {
                    printf("Error sending file\n");
                    exit(0);
                }

                bytesWritten += sent;
            }
        }

      // error checking
        if(bytesToWrite < 256)
        {
            if(feof(fp))
                printf("End of file\n");
            if(ferror(fp))
                printf("Error in reading of file\n");
            break;

        }
    }
     printf("File sent successfully\n");
     close(my_file_socket_fd); // parent doesn't need this
}

/* This function handle LS_msg and sends all locations that contain sdfsfilename
 *input:    msg: LS_msg
 *output:   NONE
 */
void Protocol::handle_LS_msg(string msg, bool haveLock, int my_file_socket_fd){
    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    // if(my_vm_info.ip_addr_str == my_vm_info.master_ip){
    string sdfsfilename = "sdfs_" + result[1];
    string ip = result[2];
    cout << "result_0: " << result[0];
    cout << "result_1: " << result[1];
    cout << "result_2: " << result[2];

    string message;
    if(my_vm_info.master_file_directory.find(sdfsfilename) != my_vm_info.master_file_directory.end()){
        message =  sdfsfilename.substr(5) + ": ";
        //        my_vm_info.master_file_directory[sdfsfilename][0] + " " +
        //        my_vm_info.master_file_directory[sdfsfilename][1] + " " +
        //        my_vm_info.master_file_directory[sdfsfilename][2] + '\n';
        if(!haveLock)
                membership_list_lock.lock();
        for(auto it = membership_list.begin(); it != membership_list.end(); it++){
            if(vm_info_map[*it].ip_addr_str == my_vm_info.master_file_directory[sdfsfilename][0]){
                message = message + my_vm_info.master_file_directory[sdfsfilename][0] + " ";
                continue;
            }
            else if(vm_info_map[*it].ip_addr_str == my_vm_info.master_file_directory[sdfsfilename][1]){
                message = message + my_vm_info.master_file_directory[sdfsfilename][1] + " ";
                continue;
            }
            else if(vm_info_map[*it].ip_addr_str == my_vm_info.master_file_directory[sdfsfilename][2]){
                message = message + my_vm_info.master_file_directory[sdfsfilename][2] + " ";
                continue;
            }
        }
        if(!haveLock)
            membership_list_lock.unlock();
        message = message + '\n';

        if (send(my_file_socket_fd, message.c_str(), MAXDATASIZE, 0) == -1)
          perror("send");
    }
    else{
        message = "The file: " + result[1] + " does not exist in the SDFS\n";
        if (send(my_file_socket_fd, message.c_str(), MAXDATASIZE, 0) == -1)
          perror("send");
    }
}

/* This function handle DEL_msg and sends deletes sdfsfile from all locations
 *input:    msg: DEL_msg
 *output:   NONE
 */
void Protocol::handle_DEL_msg(string msg, bool haveLock, int my_file_socket_fd){
    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string sdfsfilename = "sdfs_" + result[1];
    cout << "result_0: " << result[0];
    cout << "result_1: " << result[1];

    // If the sdfsfile exists, find locations
    // Send Delete sdfsfilename to all locations
    string send_to_all = create_DELETE_msg(sdfsfilename);
    cout << "DELETE MESSAGE: " << send_to_all<<endl;
    if(my_vm_info.ip_addr_str == my_vm_info.master_ip){
        cout<<"I am master"<<endl;
        if(my_vm_info.master_file_directory.find(sdfsfilename) != my_vm_info.master_file_directory.end()){
            cout<<"File found"<<endl;
            string location1 = my_vm_info.master_file_directory[sdfsfilename][0];
            string location2 = my_vm_info.master_file_directory[sdfsfilename][1];
            string location3 = my_vm_info.master_file_directory[sdfsfilename][2];
            cout<<"Locations: "<<location1<<" "<<location2<<" "<<location3<<endl;

            if(!haveLock)
                membership_list_lock.lock();
            int done = 0;
            auto it = membership_list.begin();
            while(it != membership_list.end() && done != 3){
                if(vm_info_map[*it].ip_addr_str == location1){
                    local_udp.send_msg(location1, send_to_all);
                    cout << "SENT TO location1"<<endl;
                    done += 1;
                }
                else if(vm_info_map[*it].ip_addr_str == location2){
                    local_udp.send_msg(location2, send_to_all);
                    cout << "SENT TO location2"<<endl;
                    done += 1;
                }
                else if(vm_info_map[*it].ip_addr_str == location3){
                    local_udp.send_msg(location3, send_to_all);
                    cout << "SENT TO location3"<<endl;
                    done += 1;
                }
                it++;
            }
            if(!haveLock)
                membership_list_lock.unlock();

            string dest_1_IP = location1;
            string dest_2_IP = location2;
            string dest_3_IP = location3;

            auto it_VMtoFile = my_vm_info.VM_to_files_map[dest_1_IP].begin();
            while(*it_VMtoFile != sdfsfilename)
                it_VMtoFile++;
            my_vm_info.VM_to_files_map[dest_1_IP].erase(it_VMtoFile);
            string message_1 = create_VMF_msg(dest_1_IP, my_vm_info.VM_to_files_map[dest_1_IP]);
            it_VMtoFile = my_vm_info.VM_to_files_map[dest_2_IP].begin();
            while(*it_VMtoFile != sdfsfilename)
                it_VMtoFile++;
            my_vm_info.VM_to_files_map[dest_2_IP].erase(it_VMtoFile);
            string message_2 = create_VMF_msg(dest_2_IP, my_vm_info.VM_to_files_map[dest_2_IP]);
            it_VMtoFile = my_vm_info.VM_to_files_map[dest_3_IP].begin();
            while(*it_VMtoFile != sdfsfilename)
                it_VMtoFile++;
            my_vm_info.VM_to_files_map[dest_3_IP].erase(it_VMtoFile);
            string message_3 = create_VMF_msg(dest_3_IP, my_vm_info.VM_to_files_map[dest_3_IP]);

            vector <string> collection;
            string message_4 = create_MASTERFD_msg(sdfsfilename, collection);


            if(!haveLock)
                membership_list_lock.lock();
            for(it = membership_list.begin(); it != membership_list.end(); it++){
                string destination_ip = vm_info_map[*it].ip_addr_str;
                local_udp.send_msg(destination_ip, message_1);
                local_udp.send_msg(destination_ip, message_2);
                local_udp.send_msg(destination_ip, message_3);
                local_udp.send_msg(destination_ip, message_4);
            }
            if(!haveLock)
                membership_list_lock.unlock();

            cout << "SENT DELETE MESSAGE TO ALL OR SOME LOCATIONS" << endl;
            string msg = "ACK\n";
            my_vm_info.master_file_directory.erase(sdfsfilename);
            if (send(my_file_socket_fd, msg.c_str(), MAXDATASIZE, 0) == -1)
                 perror("send");
            return;
        }
        else{
            cout << "NO SUCH SDFS FILE EXISTS" << endl;
            string msg = "The file: " + result[1] + " does not exist in the SDFS\n";
            if (send(my_file_socket_fd, msg.c_str(), MAXDATASIZE, 0) == -1)
                 perror("send");
            return;
        }
    }
}

/* This function handle DELETE_msg and sends deletes sdfsfile from all locations
 *input:    msg: DELETE_msg
 *output:   NONE
 */
void Protocol::handle_DELETE_msg(string msg){

    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string sdfsfilename = result[1];
    cout << "result_0: " << result[0];
    cout << "result_1: " << result[1];

    my_vm_info.sdfs_files.erase(sdfsfilename);
    cout << "AFTER DELETE FROM SET"<<endl;
    system(("rm " + sdfsfilename).c_str());
    cout << "AFTER SYSCALL"<<endl;
}

/* This function handle DELETE_msg and sends deletes sdfsfile from all locations
 *input:    msg: DELETE_msg
 *output:   NONE
 */
void Protocol::handle_APP_msg(string msg, bool haveLock){

    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string destination_vertex = result[1];
    int partition_number = string_to_int(result[2]) % NUM_PARTITIONS;
    long double message = stod(result[3]);

    my_vm_info.vertex_state[partition_number][destination_vertex].incoming_msg_S_1.push_back(message);
    my_vm_info.vertex_state[partition_number][destination_vertex].flag_next = true;
    my_vm_info.bitmap[my_vm_info.ip_addr_str] = true;
    my_vm_info.active_flag = true;
}

void computeSS(int i, create_t *creat ){//, destroy_t *destroy){
    for(auto it = my_vm_info.vertex_state[i].begin(); it != my_vm_info.vertex_state[i].end(); it++){
        Vertex * tst = creat(it->first, it->second);
        tst->Compute();
        tst->CopyToWorker();
        // cout<<"Copied to worker after compute 1471"<<endl;
        // destroy(tst);
    }
}

void performSS(){
    //start of superstep
    my_vm_info.active_flag = false;
    create_t* creat=(create_t*)dlsym(dlhandler,"create");
    // destroy_t* destroy=(destroy_t*)dlsym(dlhandler,"destroy");
    if (!creat)
    {
           cout<<"The error is %s"<<dlerror();
    }
    // if (!destroy)
    // {
    //        cout<<"The error is %s"<<dlerror();
    // }
    //threads for each partition - iterate through all vertices
    std::thread partition_threads[NUM_PARTITIONS];
    for(int i = 0; i<NUM_PARTITIONS; i++){
        partition_threads[i] = std::thread(computeSS, i, creat);//, destroy);
    }

    for(int i = 0; i<NUM_PARTITIONS; i++){
        partition_threads[i].join();
    }
    //all NUM_PARTITION threads are done with current superstep
    terminate_superstep();
}
/* This function handle DELETE_msg and sends deletes sdfsfile from all locations
 *input:    msg: DELETE_msg
 *output:   NONE
 */
void Protocol::handle_SS_msg(string msg, bool haveLock){

    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string ss_num = result[1];
    my_vm_info.superstep = string_to_int(ss_num);
    cout << "Current Superstep is: " << my_vm_info.superstep << endl;
    if(my_vm_info.superstep >= 1){
      cout << "Starting superstep: " << my_vm_info.superstep << endl;
      // call the function from here for the next superstep
      performSS();
    }
}

void handle_PUTNOTIFY_helper(string msg){
    std::istringstream iss;
    string strvalues = msg;
    vector<std::string> result;
    iss.str (strvalues);
    //cout<<"in handle_PUTNOTIFY_helper with msg: "<<msg<<endl;
    for (string s; iss>>s; )
        result.push_back(s);
    put_happening = result[1];
    sleep(60);
    // cout<<"sleeping thread awake"<<endl;
    if(put_happening == result[1])
        put_happening.clear();
}

void Protocol::handle_PUTNOTIFY_msg(string msg){
    //cout<<"in handlePUTNOTIFYmsg"<<endl;
    std::thread put_notify_thread = std::thread(handle_PUTNOTIFY_helper, msg);
    put_notify_thread.detach();
}

/*
* Sending to all is handled through the sdfs function handlers for:
* put, delete, failure/quit
* use local_udp.send_msg() to forward to all.
* This is the handler function of the FD msg
*/
void Protocol::handle_VMF_msg(string msg){
    // Every VM just updates its own
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);
    cout << "IN HANDLE FD: " <<endl;
    string VM_ip = result[1];
    if(result.size() == 2){
        my_vm_info.VM_to_files_map.erase(VM_ip);
        return;
    }
    cout << "VM_ip: "<< VM_ip <<endl;
    vector<string> filenames;
    result.erase(result.begin(), result.begin()+2);
    filenames = result;
    for(unsigned int i = 0; i < filenames.size(); i++)
        cout << "filenames at " << i << " : "<< filenames[i] << endl;
    my_vm_info.VM_to_files_map[VM_ip] = filenames;
    cout << "inserted" << endl;
}

/*
* Sending to all is handled through the sdfs function handlers for:
* put, delete, failure/quit
* use local_udp.send_msg() to forward to all.
* This is the handler function of the FD msg
*/
void Protocol::handle_MASTERFD_msg(string msg){
    // Every VM just updates its own
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    cout << "IN HANDLE MasterFD: " <<endl;
    string sdfsfilename = result[1];
    //if file was deleted
    if(result.size() == 2){
        my_vm_info.master_file_directory.erase(sdfsfilename);
        return;
    }
    cout << "sdfsfilename: "<< sdfsfilename <<endl;
    vector<string> IPs;
    result.erase(result.begin(), result.begin()+2);
    IPs = result;
    for(unsigned int i = 0; i < IPs.size(); i++)
        cout << "IPs at " << i << " : "<< IPs[i] << endl;
    my_vm_info.master_file_directory[sdfsfilename] = IPs;
    cout << "inserted" << endl;
}

// handled when parsing the message received in the udp listener
void Protocol::handle_ELECTED_msg(string msg){
    // Every VM just updates its own
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string new_master = result[1];

    my_vm_info.master_ip = new_master;
}

/* This function handle DELETE_msg and sends deletes sdfsfile from all locations
 *input:    msg: DELETE_msg
 *output:   NONE
 */
void Protocol::handle_SAVAReg_msg(string msg, bool haveLock){

    UDP local_udp;
    Protocol p;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string worker_ip = result[1];
    cout << "result[0] is: " << result[0];
    cout << "worker getting added: " << result[1];
    // add to the data structure of alive_workers
    my_vm_info.alive_workers.insert(worker_ip);
    my_vm_info.bitmap[worker_ip] = false;
    // acquire lock and send to all
    string tosend = p.create_ALIVE_msg(my_vm_info.alive_workers);

    // assign partitions in the partitions_to_VMs data structure
    // Tell the worker about it
    // tell all alive workers about it
    for(int i =0 ; i < NUM_PARTITIONS; i++){
      my_vm_info.partitions_to_VMs[cur_partition + i] = worker_ip;
    }
    cur_partition+= NUM_PARTITIONS;

    string partition_message = p.create_PART_msg(my_vm_info.partitions_to_VMs);

    if(!haveLock)
        membership_list_lock.lock();

    for(auto it = membership_list.begin(); it != membership_list.end(); it++){
      string destination = vm_info_map[*it].ip_addr_str;
      local_udp.send_msg(destination, tosend);
      local_udp.send_msg(destination, partition_message);
    }

    if(haveLock == false)
        membership_list_lock.unlock();
}

void load_thread(string filename){
  cout<<"in handle_LOAD_msg"<<endl;
  std::ifstream infile(filename);
  string line;
  UDP local_udp;
  Protocol p;
  while (std::getline(infile, line)) // or the end of file
  {
      std::istringstream iss(line);
      string partition, start_node, end_node;
      if (!(iss >> partition >> start_node >> end_node)) { break; } // error
      int x = string_to_int(partition)%NUM_PARTITIONS;
      if(my_vm_info.vertex_state[x].find(start_node) == my_vm_info.vertex_state[x].end())
        my_vm_info.vertex_state[x][start_node] = state(0, stod(end_node), 1);
      else{
        my_vm_info.vertex_state[x][start_node].outgoing_edges.push_back(stod(end_node));
      }
  }
  cout << "Done Loading on worker; notifying master" << endl;
   cout<<"Received application"<<endl;
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
  string ack = p.create_START_msg(my_vm_info.ip_addr_str);
  local_udp.send_msg(my_vm_info.SAVA_Master, ack);
}


/*
* Sending to all is handled through the sdfs function handlers for:
* put, delete, failure/quit
* use local_udp.send_msg() to forward to all.
* This is the handler function of the FD msg
*/
void handle_LOAD_msg(){
    // open the sharded file
    // launch num partition number of threads
    // each thread reads from the file from an offset
    // load the unordered_map<string, state> vertex_state[NUM_PARTITIONS]; // vertex_id -> state
    // if vertex belongs to either of the partitions, keep
    // else add to string specific to the vms
    // when reached threshold, send it out

    load_thread(my_vm_info.ip_addr_str);

}

/* This function handle Shard msg
 *input:    msg , socketFD
 *output:   NONE
 */
void Protocol::handle_SHARD_msg(string msg, bool haveLock, int my_file_socket_fd){

    int numbytes2;
     char bufer [MAXDATASIZE];

    if ((numbytes2 = recv(my_file_socket_fd, bufer, MAXDATASIZE-1, 0)) == -1) {
     perror("recv");
     exit(1);
     }
    my_vm_info.num_vertices = atol(bufer);

    if (send(my_file_socket_fd, "ACK", 3, 0) == -1)
          perror("send");
    

    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string receiveBytes = result[1];
    string sdfsfilename = result[2];
    string requester_IP = result[3];

    unsigned long numbytes = stoul(receiveBytes);

    FILE *fp = fopen(sdfsfilename.c_str(), "w");
    if(fp == NULL){
         printf("File open error\n");
         exit(0);
    }
    char *buff = new char[numbytes];
    unsigned long bytesRead = 0;
    while(bytesRead != numbytes){
        if(!haveLock)
            membership_list_lock.lock();
        auto it = membership_list.begin();
        while(it != membership_list.end()){
            if(vm_info_map[*it].ip_addr_str == requester_IP)
                break;
            it++;
        }
        if(it == membership_list.end()){
            if(!haveLock)
                membership_list_lock.unlock();
            cout<<"Failed while PUT - Abort"<<endl;
            system(("rm " + sdfsfilename).c_str());
            return;
        }
        if(!haveLock)
            membership_list_lock.unlock();
        int readNow;
        cout<<"waiting for file"<<endl;
        readNow = read(my_file_socket_fd, buff + bytesRead, (numbytes- bytesRead));
        if(readNow == -1){
              perror("read");
              printf("Error sending file\n");
              exit(0);
        }
        bytesRead += readNow;
    }
    cout<<"got file"<<endl;

    fwrite(buff,1, numbytes,fp);
    fclose(fp);
    free(buff);

    //send ack
     if (send(my_file_socket_fd, "ACK", 3, 0) == -1)
          perror("send");

    char buf[MAXDATASIZE];
    long numbytes_app;
    //Receive file size of application
    if ((numbytes_app = recv(my_file_socket_fd, buf, MAXDATASIZE-1, 0)) == -1) {
         perror("recv");
         exit(1);
    }
     buf[numbytes_app] = '\0';
     string buf_app = buf;
     // cout<<"Buf_app-"<<buf_app<<" numbytes_app-"<<numbytes_app<<" buf- "<<buf<<endl;
     numbytes_app = stol(buf_app);
     cout<<"Received "<<buf_app<<endl;
     receiveBytes = buf_app;
     // cout<<"HERE2"<<endl;

     //send ack
    if (send(my_file_socket_fd, "ACK", 3, 0) == -1)
          perror("send");

    //recieve application file
    fp = fopen("application.so", "w");
    if(fp == NULL){
         printf("File open error\n");
         exit(0);
    }
    buff = new char[numbytes_app];
    long bytesRead_app = 0;
    while(bytesRead_app != numbytes_app){
        if(!haveLock)
            membership_list_lock.lock();
        auto it = membership_list.begin();
        while(it != membership_list.end()){
            if(vm_info_map[*it].ip_addr_str == requester_IP)
                break;
            it++;
        }
        if(it == membership_list.end()){
            if(!haveLock)
                membership_list_lock.unlock();
            cout<<"Failed while PUT - Abort"<<endl;
            system(("rm application.so"));
            return;
        }
        if(!haveLock)
            membership_list_lock.unlock();
        int readNow;
        readNow = read(my_file_socket_fd, buff + bytesRead_app, (numbytes_app- bytesRead_app));
        if(readNow == -1){
              perror("read");
              printf("Error sending file\n");
              exit(0);
        }
        bytesRead_app += readNow;
    }
    fwrite(buff,1, numbytes_app,fp);
    fclose(fp);
    free(buff);

    dlhandler = dlopen("./application.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!dlhandler)
    {
           printf("dlopen: The error is %s", dlerror());
    }
    handle_LOAD_msg();
}

/* This function handle ALIVE_msg
 *input:    msg: Alive
 *output:   NONE
 */
void Protocol::handle_ALIVE_msg(string msg){

    UDP local_udp;
    Protocol p;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    cout << "result[0] is: " << result[0];
    cout << "worker getting added: " << result[1];
    // add to the data structure of alive_workers
    vector<string> workers;
    result.erase(result.begin(), result.begin()+1);
    workers = result;
    my_vm_info.alive_workers.clear();
    for(unsigned int i = 0; i < workers.size(); i++){
      my_vm_info.alive_workers.insert(workers[i]);
      cout << "alive_workers: " << i << " : " << workers[i] << endl;
    }
}

void shard(bool haveLock){
  FILE *fp;
  std::ifstream infile("graph.txt");
  string line;
  UDP local_udp;
  long int lines_count = 0;
  std::getline(infile, line);
  std::getline(infile, line);
  std::getline(infile, line);
   
    std::istringstream iss;
    vector<std::string> result;
    iss.str(line);
    for (string s; iss>>s; )
    result.push_back(s);

    string nodes = result[2];
    // string msg = "NODE " + nodes + "\n";
    my_vm_info.num_vertices = stol(nodes);
    // cout<<msg<<" ||||"<<my_vm_info.num_vertices<<endl;
    // worker_lock.lock();
    // for(auto it = my_vm_info.alive_workers.begin(); it!= my_vm_info.alive_workers.end(); it++){
    //     cout<<"Sending to "<<*it<<endl;
    //     local_udp.send_msg(*it, msg);
    // }
    // worker_lock.unlock();

  std::getline(infile, line);
  unsigned int num_workers;
  if(!haveLock)
    worker_lock.lock();
  num_workers = my_vm_info.alive_workers.size();
  if(!haveLock)
    worker_lock.unlock();
  while (std::getline(infile, line)) // or the end of file
  {
      std::istringstream iss(line);
      string start_node, end_node;
      if (!(iss >> start_node >> end_node)) { break; } // error
      // cout << "start_node: " << start_node <<endl;
      // cout << "end_node: " << end_node << endl;

      string hash = md5(start_node);
      std::istringstream converter(hash.substr(27));
      unsigned int value;
      converter >> std::hex >> value;
      // cout<<"Value for vertex "<<start_node<<" is "<<value<<endl;
      int index_partition = value % (num_workers*NUM_PARTITIONS);
      // cout<<"partition_number- "<<index_partition<<endl;
      fp = fopen(my_vm_info.partitions_to_VMs[index_partition].c_str(), "a");
      string entry = int_to_string(index_partition) + " " + start_node + " " + end_node + "\n";
      fwrite(entry.c_str(), strlen(entry.c_str()), 1, fp);
      fclose(fp);

      hash = md5(end_node);
      std::istringstream converter2(hash.substr(27));
      converter2 >> std::hex >> value;
      index_partition = value % (num_workers*NUM_PARTITIONS);
      // cout<<"partition_number- "<<index_partition<<endl;
      fp = fopen(my_vm_info.partitions_to_VMs[index_partition].c_str(), "a");
      entry = int_to_string(index_partition) + " " + end_node + " " + start_node + "\n";
      fwrite(entry.c_str(), strlen(entry.c_str()), 1, fp);
      fclose(fp);
  }

  worker_lock.lock();
  for(auto it = my_vm_info.alive_workers.begin(); it != my_vm_info.alive_workers.end(); it++){

      if(my_vm_info.alive_workers.size() != num_workers){
        // worker_lock.unlock();
        break;
      }
      if((fp = fopen((*it).c_str(), "r")) == NULL){
        continue;
      }
      //SEND contents of the file and wait to get ACK from Master
      string IP = *it;
      string requester_IP = my_vm_info.ip_addr_str;
      UDP local_udp;
      Protocol p;

      // First: Send the file size
      fseek(fp,0,SEEK_END);
      unsigned long numbytes = ftell(fp);
      fclose(fp);
      string send_to_master = p.create_SHARD_msg(numbytes, *it, requester_IP);
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

      //send nodes
      tcp_send(sockfd, ip, (to_string(my_vm_info.num_vertices)).c_str());
      //wait for ack
      if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
          perror("recv");

      // Second: Send the file contents
      fp = fopen((*it).c_str(), "r");
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
      //wait for second ack from master
      if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
          perror("recv");
      cout<<"received ack for prep to appl send"<<endl;

      //send application file
      fp = fopen("application.so", "r");
      // First: Send the file size
      fseek(fp,0,SEEK_END);
      numbytes = ftell(fp);
      fclose(fp);
      send_to_master = to_string(numbytes);
      msg = send_to_master.c_str();
      tcp_send(sockfd, ip, msg);

      //wait for ack from master
      if ((rcv = recv(sockfd, buff, 3, 0)) == -1)
          perror("recv");
      cout<<"received ack for prep to appl file send"<<endl;

      // Second: Send the file contents
      fp = fopen("application.so", "r");
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
      // Sending superstep 0
      string ss = p.create_SS_msg(my_vm_info.superstep);
      my_vm_info.previously_active = num_workers;
      local_udp.send_msg(IP, ss);

      worker_lock.unlock();
      worker_lock.lock();
  }
  worker_lock.unlock();
}
/* This function handle TASK_msg
 *input:    msg: TASK _ partition
 *output:   NONE
 */
void Protocol::handle_TASK_msg(string msg, bool haveLock, int my_file_socket_fd){
    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string receiveBytes = result[1];
    string sdfsfilename = result[2];
    string requester_IP = result[3];

    unsigned long numbytes = stoul(receiveBytes);

    FILE *fp = fopen("graph.txt", "w");
    if(fp == NULL){
         printf("File open error\n");
         exit(0);
    }
    char *buff = new char[numbytes];
    unsigned long bytesRead = 0;
    while(bytesRead != numbytes){
        if(!haveLock)
            membership_list_lock.lock();
        auto it = membership_list.begin();
        while(it != membership_list.end()){
            if(vm_info_map[*it].ip_addr_str == requester_IP)
                break;
            it++;
        }
        if(it == membership_list.end()){
            if(!haveLock)
                membership_list_lock.unlock();
            cout<<"Failed while PUT - Abort"<<endl;
            system(("rm graph.txt"));
            return;
        }
        if(!haveLock)
            membership_list_lock.unlock();
        int readNow;
        readNow = read(my_file_socket_fd, buff + bytesRead, (numbytes- bytesRead));
        if(readNow == -1){
              perror("read");
              printf("Error sending file\n");
              exit(0);
        }
        bytesRead += readNow;
    }
    fwrite(buff,1, numbytes,fp);
    fclose(fp);
    free(buff);

    //send ack
     if (send(my_file_socket_fd, "ACK", 3, 0) == -1)
          perror("send");

    char buf[MAXDATASIZE];
    long numbytes_app;
    //Receive file size of application
    if ((numbytes_app = recv(my_file_socket_fd, buf, MAXDATASIZE-1, 0)) == -1) {
         perror("recv");
         exit(1);
    }
     buf[numbytes_app] = '\0';
     string buf_app = buf;
     // cout<<"Buf_app-"<<buf_app<<" numbytes_app-"<<numbytes_app<<" buf- "<<buf<<endl;
     numbytes_app = stol(buf_app);
     cout<<"Received "<<buf_app<<endl;
     receiveBytes = buf_app;
     // cout<<"HERE2"<<endl;

     //send ack
    if (send(my_file_socket_fd, "ACK", 3, 0) == -1)
          perror("send");

    //recieve application file
    fp = fopen("application.so", "w");
    if(fp == NULL){
         printf("File open error\n");
         exit(0);
    }
    buff = new char[numbytes_app];
    long bytesRead_app = 0;
    while(bytesRead_app != numbytes_app){
        if(!haveLock)
            membership_list_lock.lock();
        auto it = membership_list.begin();
        while(it != membership_list.end()){
            if(vm_info_map[*it].ip_addr_str == requester_IP)
                break;
            it++;
        }
        if(it == membership_list.end()){
            if(!haveLock)
                membership_list_lock.unlock();
            cout<<"Failed while PUT - Abort"<<endl;
            system(("rm application.so"));
            return;
        }
        if(!haveLock)
            membership_list_lock.unlock();
        int readNow;
        readNow = read(my_file_socket_fd, buff + bytesRead_app, (numbytes_app- bytesRead_app));
        if(readNow == -1){
              perror("read");
              printf("Error sending file\n");
              exit(0);
        }
        bytesRead_app += readNow;
    }
    fwrite(buff,1, numbytes_app,fp);
    fclose(fp);
    free(buff);

    cout<<"Received application"<<endl;
    cout<<"Loading partitions to workers. This may take a few minutes..."<<endl;
    // Send sharded file to each worker
    shard(false);

}


/* This function gossips the message
 *input:    msg: vector of messages that will be gossiped
 *          haveLock: indicate is have lock or not
 *output:   NONE
 */
void Protocol::gossip_msg(string msg, bool haveLock){
    //Create G_msg based on the input msg
    string g_msg = create_G_msg(msg,G_MESSAGE_NRTS);

    if(!haveLock)
        membership_list_lock.lock();
    int rtt = G_MESSAGE_NRTS - 1;
    vector<string> msg_v;

    //Gossip messgaes
    while(rtt >= 0){
        g_msg[1] = rtt +'0';
        msg_v.push_back(g_msg);
        rtt--;
    }
    send_gossip_helper(msg_v, true);

    if(!haveLock)
        membership_list_lock.unlock();
}

/* This function is a helper function to gossip message
 *input:    msg: vector of messages that will send
 *          haveLock: indicate is have lock or not
 *output:   NONE
 */
void send_gossip_helper(vector<string> msg, bool haveLock){
    vector<int> alive_id_array;
    if(haveLock == false)
        membership_list_lock.lock();

    if(membership_list.size() == 1){
        if(haveLock == false)
            membership_list_lock.unlock();
        return;
    }
    int rtt = msg.size();

    //Get random Alive VMs from membership list
    std::default_random_engine generator;
    std::uniform_int_distribution<int> distribution(0,membership_list.size()-1);

    vector<int> mem_list_v;
    int my_idx = 0;
    int count =0 ;

    //Get idx of this vm to prevent sending msg to itself
    for(auto it = membership_list.begin(); it != membership_list.end(); it++){
        mem_list_v.push_back(*it);
        if(*it == my_vm_info.vm_num){
            my_idx = count;
        }
        count++;
    }

    set<int> receivers;
    vector<int> receivers_v;

    while((int)receivers_v.size() < rtt*GOSSIP_B){
        while((receivers_v.size() < membership_list.size() -1) && ((int)receivers_v.size() < rtt*GOSSIP_B)){
            int temp = distribution(generator);
            if(receivers.find(temp) == receivers.end() && temp != my_idx){
                receivers.insert(temp);
                receivers_v.push_back(temp);
            }
        }
           while((int)receivers_v.size() < rtt*GOSSIP_B){
                  int temp = distribution(generator);
                  if(temp != my_idx){
                      receivers.insert(temp);
                      receivers_v.push_back(temp);
                  }
              }
      }

    //Send msg
    UDP local_udp;
    auto it = receivers_v.begin();
    for(int i = 0 ; i < (int) msg.size(); i++){
       for(int j = 0 ; j < GOSSIP_B; j++){
           local_udp.send_msg(vm_info_map[mem_list_v[*it]].ip_addr_str, msg[i]);
            protocol_log << "Send Gossip to id " << *it << "--- ip: " << vm_info_map[mem_list_v[*it]].ip_addr_str <<= msg[i];
           it++;
        }
    }
    if(haveLock == false)
        membership_list_lock.unlock();
}

/* This is failure handler to make changes to the maps and remove dead_ip's data and braodcast those updates
 *Input:    dead_ip
 *Return:   None
 */
void handle_fail(string dead_ip, bool haveLock){
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
                            free(received_buff);
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

/* This function handle MAP_msg and sends deletes sdfsfile from all locations
 *input:    msg: MAP_msg
 *output:   NONE
 */
void Protocol::handle_MAP_msg(string msg){
    cout << "In handle MAP msg\n";
    UDP local_udp;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    string requester = result[1];
    cout << "result_0: " << result[0];
    cout << "result_1: " << result[1];

    for(auto it = my_vm_info.VM_to_files_map.begin(); it != my_vm_info.VM_to_files_map.end(); it++){
        vector<string> v = it->second;
        string VM_ip = it->first;
        string to_send("inV ");
        to_send.append(create_VMF_msg(VM_ip, v));
        local_udp.send_msg(requester, to_send);
    }

    for(auto it = my_vm_info.master_file_directory.begin(); it != my_vm_info.master_file_directory.end(); it++){
        vector<string> vms = it->second;
        string sdfsfile = it->first;
        string to_send("inM ");
        to_send.append(create_MASTERFD_msg(sdfsfile, vms));
        local_udp.send_msg(requester, to_send);
    }
}

/* This function handle MAP_msg and sends deletes sdfsfile from all locations
 *input:    msg: MAP_msg
 *output:   NONE
 */
void Protocol::handle_inV_msg(string msg){
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);
    cout << "IN HANDLE inV: " <<endl;
    string VM_ip = result[2];

    cout << "VM_ip: "<< VM_ip <<endl;
    vector<string> filenames;
    result.erase(result.begin(), result.begin()+3);
    filenames = result;
    for(unsigned int i = 0; i < filenames.size(); i++)
        cout << "filenames at " << i << " : "<< filenames[i] << endl;
    my_vm_info.VM_to_files_map[VM_ip] = filenames;
    cout << "inserted" << endl;

}

/* This function handle MAP_msg and sends deletes sdfsfile from all locations
 *input:    msg: MAP_msg
 *output:   NONE
 */
void Protocol::handle_inM_msg(string msg){
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    cout << "IN HANDLE inM: " <<endl;
    string sdfsfilename = result[2];

    cout << "sdfsfilename: "<< sdfsfilename <<endl;
    vector<string> IPs;
    result.erase(result.begin(), result.begin()+3);
    IPs = result;
    for(unsigned int i = 0; i < IPs.size(); i++)
        cout << "IPs at " << i << " : "<< IPs[i] << endl;
    my_vm_info.master_file_directory[sdfsfilename] = IPs;
    cout << "inserted" << endl;
}

/* This function handle MAP_msg and sends deletes sdfsfile from all locations
 *input:    msg: MAP_msg
 *output:   NONE
 */
void Protocol::handle_DONE_msg(string msg, bool haveLock){
    UDP local_udp;
    Protocol p;
    done_counter++;
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);
    string active_flag = result[1];
    string active_worker = result[2];
    if(active_flag.substr(0,4) == "true")
      my_vm_info.bitmap[active_worker] = true;
    else
      my_vm_info.bitmap[active_worker] = false;

    // cout << "Current Superstep done is: " << my_vm_info.superstep << endl;
    // cout << "Sending ping to active workers for next superstep" << endl;
    int active_s_1 = 0;
    if(done_counter == my_vm_info.previously_active){
      string ss = p.create_SS_msg(++my_vm_info.superstep);
      for(auto it = my_vm_info.bitmap.begin(); it != my_vm_info.bitmap.end(); it++){
        if(it->second == true){
          active_s_1++;
          string dest = it->first;
          local_udp.send_msg(dest, ss);
        }
      }
    }
    my_vm_info.previously_active = active_s_1;
    // cout << "workers active for superstep: " << my_vm_info.superstep << "are" << my_vm_info.previously_active << endl;
    done_counter = 0;
    if(active_s_1 == 0){
      // Can halt:
       cout << "Job complete" << endl;
      //OUTPUT function
    }

}

/* This function handle MAP_msg and sends deletes sdfsfile from all locations
 *input:    msg: MAP_msg
 *output:   NONE
 */
void Protocol::handle_PART_msg(string msg, bool haveLock){
    std::istringstream iss;
    vector<std::string> result;
    iss.str(msg);
    for (string s; iss>>s; )
        result.push_back(s);

    cout << "IN HANDLE PART Message: " <<endl;
    result.erase(result.begin(), result.begin()+1);
    my_vm_info.partitions_to_VMs.clear();
    my_vm_info.partitions.clear();
    for(unsigned int i = 0; i < result.size(); ){
      if(i%2 == 0){
        int partition_number = string_to_int(result[i]);
        my_vm_info.partitions_to_VMs[partition_number] = result[i+1];
        if(result[i+1] == my_vm_info.ip_addr_str)
          my_vm_info.partitions.insert(partition_number);
        i = i+2;
      }
    }

    // For debugging:
    for(auto it = my_vm_info.partitions_to_VMs.begin(); it != my_vm_info.partitions_to_VMs.end(); it++){
      cout << "Partition number is: " << it->first <<endl;
      cout << my_vm_info.partitions_to_VMs[it->first] << endl;
    }

    for(auto it = my_vm_info.partitions.begin(); it != my_vm_info.partitions.end(); it++){
      cout << "Partitions in the set are: " << *it << endl;
    }

}


/*
* Sending to all is handled through the sdfs function handlers for:
* put, delete, failure/quit
* use local_udp.send_msg() to forward to all.
* This is the handler function of the FD msg
*/
void Protocol::handle_ENQUEUE_msg(string msg, bool haveLock){

    cout<<msg<<endl;
    // UDP local_udp;
    // Protocol p;
    // std::istringstream iss;
    // vector<std::string> result;
    // iss.str(msg);
    // for (string s; iss>>s; )
    //     result.push_back(s);

    // result.erase(result.begin(), result.begin() + 1);
    // for(unsigned int i = 0; i < result.size(); ){
    //   if(i%2 == 0){
    //     string start_node = result[i];
    //     string end_node = result[i+1];
    //     i = i+2;
    //     my_vm_info.vertex_edges[start_node].push_back(end_node);
    //     state curr_vertex(0, my_vm_info.vertex_edges[start_node], true);
    //     // Look into this for the map below :
    //     my_vm_info.vertex_state[partition_number][start_node] = curr_vertex;
    //   }
    // }
}

// This is for Master Re-election on failure detection
// at any given time
// Called when master failure is notified
void master_election_notification(bool haveLock){
    UDP local_udp;
    string vote("ELECTED ");
    if(!haveLock)
        membership_list_lock.lock();
    string master = vm_info_map[*membership_list.begin()].ip_addr_str;
    vote.append(master);
    vote.append("\n");

    for(auto it = membership_list.begin(); it != membership_list.end(); it++){
        local_udp.send_msg(vm_info_map[*it].ip_addr_str, vote);
    }
    if(!haveLock)
        membership_list_lock.unlock();
}

void terminate_superstep(){
  UDP local_udp;
  Protocol p;
  // if even one vertex has an active flag -> make it true ; else make it false
  // my_vm_info.active_flag = false;
  // for(int i = 0; i < NUM_PARTITIONS; i ++){
  //   for(auto it = my_vm_info.vertex_state[i].begin(); it != my_vm_info.vertex_state[i].end(); it++){
  //     if((it->second).flag_next == true){
  //       my_vm_info.active_flag = true;
  //       break;
  //     }
  //   }
  // }
cout<<"in terminate_superstep"<<endl;
  // Switch S and S+1 queues
  for(int i = 0; i < NUM_PARTITIONS; i ++){
    for(auto it = my_vm_info.vertex_state[i].begin(); it != my_vm_info.vertex_state[i].end(); it++){
        // cout<<"vertex: "<<it->first<<" has incoming msgs:"<<endl;
        // for(auto itt = it->second.incoming_msg_S_1.begin(); itt != it->second.incoming_msg_S_1.end(); itt++)
        //     cout<<*itt<<endl;
        // cout<<"switching S and S_1"<<endl;
      (it->second).incoming_msg_S.swap((it->second).incoming_msg_S_1);
      (it->second).incoming_msg_S_1.clear();
    }
  }

  // Send back active_flag to SAVA_Master
  // cout<<"worker flag is "<<my_vm_info.active_flag<<endl;
  string worker = my_vm_info.ip_addr_str;
  string done_ss = p.create_DONE_msg(my_vm_info.active_flag, worker);
  local_udp.send_msg(my_vm_info.SAVA_Master, done_ss);

}
