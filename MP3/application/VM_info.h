//
//  VM_info.hpp
//
//
//  Created by Hieu Huynh on 10/7/17.
//

#ifndef VM_info_h
#define VM_info_h

using namespace std;
#include <stdio.h>
#include <string>
#include <set>
#include <vector>
#include <unordered_map>
#include <queue>

#define NUM_PARTITIONS 3

class state{
public:
    long double current_value;
    vector<long double> outgoing_edges;
    bool flag;
    // flag 1 is active and 0 is inactive
    vector<long double> incoming_msg_S;
    vector<long double> incoming_msg_S_1;
    bool flag_next;

    state();
    state(long double curr_val, long double edge, bool Aflag);
};

class VM_info{
public:
    int vm_num;             //id number given by VM0 when join the system
    unsigned char ip_addr[4];
    string ip_addr_str; //string of ip address
    string time_stamp;  //Time stamp of the VM
    string id_str;  //This includes id, ip, timestamp
    long heartbeat;
    set<string> sdfs_files; //set of files in my machine
    string master_ip = "172.22.147.116";
    string SAVA_Master = "172.22.147.117";
    string SAVA_StandBy = "172.22.147.118";
    string SAVA_Client = "172.22.147.116";
    unordered_map<string, vector<string>> master_file_directory;
    unordered_map<string, vector<string>> VM_to_files_map; // Maps the IP to the sdfsfiles present

    // SAVA Data Structures:
    set<int> partitions; // set of partitions on this machine
    long num_vertices = 0;
    unordered_map<string , bool> bitmap;
    unordered_map<int, string> partitions_to_VMs;
    unordered_map<string, state> vertex_state[NUM_PARTITIONS]; // vertex_id -> state
    set<string> alive_workers;
    int superstep = 0;
    bool active_flag = false;
    int previously_active = 0;

    VM_info();
    VM_info(int id_, unsigned char* ip_addr_, string time_stamp_);
    VM_info(string id_str_);
    void make_id_str();  // Make id_str from vm_num,ip_addr, and time_stamp

};

#endif /* VM_info_hpp */
