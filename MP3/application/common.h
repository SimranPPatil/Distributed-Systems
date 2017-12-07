//
//  common.h
//
//
//  Created by Hieu Huynh on 9/27/17.
//

#ifndef common_h
#define common_h

#define PORT "4392"             //PORT number
#define J_MESSAGE_LENGTH 16     //This is the Length of the J msg
#define H_MESSAGE_LENGTH 4      //This is the Length of the H msg
#define N_MESSAGE_LENGTH 18     //This is the Length of the N msg
#define L_MESSAGE_LENGTH 4      //This is the Length of the L msg

#define GOSSIP_B		3       //This is the parameters B of the gossip algorithm
#define GOSSIP_C		2
#define G_MESSAGE_NRTS	3       //This is the number of rounds to gossiping the msg

#define IP_LEN 4                //LENGTH of IP
#define NUM_TARGETS 4           //NUMBERS OF TARGETS
#define ID_LEN 16               //Length of id of VM

#define VM_AND_TIMESTAMP_SIZE 12
#define ALIVE 1
#define DEAD 0
#define HB_TIME 500     //Send  HB msg every 500ms
#define HB_TIMEOUT 4    // Detect failure if not receive HB after 2 seconds
#define NUM_VMS 10      //NUmber of VMs
#define NUM_PARTITIONS 3 // This is per machine
#define ERROR_LENGTH		4096

#include <stdio.h>
#include <iostream>
#include <vector>
#include <queue>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctime>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "limits.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/time.h>
#include <chrono>
#include <thread>
#include <mutex>
#include <algorithm>
#include <queue>
#include "VM_info.h"
#include "md5.h"
#include <set>
#include <unordered_map>
#include <sstream>      // std::istringstream
#include <iomanip>
#include <fcntl.h>

using namespace std;

extern unordered_map<int, VM_info> vm_info_map;
extern set<int> membership_list;
extern std::mutex membership_list_lock;

extern set<int> hb_targets;
extern std::mutex hb_targets_lock;
extern std::mutex failure_lock;
extern std::mutex worker_lock;

//No need lock
extern long num_vertices;
extern string time_stamp;
extern string vm_hosts[NUM_VMS];
extern int my_socket_fd;
extern VM_info my_vm_info;
extern void update_hb_targets(bool haveLock);
extern string int_to_string(int num);
extern int string_to_int(string str);
extern void print_membership_list();
extern string put_happening;
extern int cur_partition;

extern bool ismeasuring;
extern std::mutex measure_lock;
extern int msg_num;

typedef std::chrono::high_resolution_clock clk;
typedef std::chrono::time_point<clk> timepnt;
typedef std::chrono::milliseconds unit_milliseconds;
typedef std::chrono::microseconds unit_microseconds;
typedef std::chrono::nanoseconds unit_nanoseconds;


#endif /* common_h */
