//
//  Message.h
//
//
//  Created by Hieu Huynh on 9/27/17.
//

#ifndef Protocol_h
#define Protocol_h
#define MAX_BUF_SIZE 1024
#include "common.h"
#include "UDP.h"
#include "vertex.h"

typedef Vertex * create_t(string, state);
typedef void destroy_t(Vertex *);

class Protocol{
private:
    //string sender;

public:
    //This is the Heart beat msg
    string create_H_msg();

    //This is the Join msg, which is the request to get the membership list
    string create_J_msg();

    //This is the New msg, to notify that there is a new node join the system
    string create_N_msg(string id_str);

    //This is the Leave msg, to notify that there is a  node fail
    string create_L_msg(int vm_num);

    //This is the Initialize msg, this contains the membership list info that VM0 send to the new node
    string create_I_msg(vector<string> vm_list, int vm_num_);

    //This is the Gossip msg, this contain either Q_msg, L_msg, or N_msg
	string create_G_msg(string msg, int num_retransmits);

    //This is a Target update msg, this msg tells the targets to update it hb targets
    string create_T_msg();

    //This is the Quit message, this message tells other VM that this VM is leaving
    string create_Q_msg();

    //This is the Put message, this message tells other VM that file needs to be added
    string create_P_msg(unsigned long numbytes, string sdfsfilename, string requester_IP);

    //This is the Shard message, this message tells worker to receive shard of graph file
    string create_SHARD_msg(unsigned long numbytes, string sdfsfilename, string requester_IP);

    //This is the Get message, this message tells other VM that file needs to be fetched
    string create_GET_msg(string sdfsfilename, string requester_IP, string localfilename);

    //This is the Got message, this message tells other VM that file is ready to be saved
    string create_GOT_msg(string sdfsfilename, string requester_IP, string localfilename);

    //This is the LS message, this message tells other VM to execute ls command
    string create_LS_msg(string sdfsfilename, string requester_IP);

    //This is the DEL message, this message tells other VM to delete the sdfs file
    string create_DEL_msg(string sdfsfilename);

    //This is the DEL message, this message tells other VM to delete the sdfs file
    string create_DELETE_msg(string sdfsfilename);

    //This is the FD message, this message tells other VM to delete the sdfs file
    string create_VMF_msg(string IP, vector<string> filenames);

    //This is the MASTERFD_message, this message tells other VM to delete the sdfs file
    string create_MASTERFD_msg(string sdfsfilename, vector<string> ip);

    //This is the SAVA Register message, this message tells other Master to register a generic worker
    string create_SAVAReg_msg(string worker_ip);

    //This is the active worker_ip Register message, this message tells other Master to register a generic worker
    string create_ALIVE_msg(set<string> alive_workers);

    //This is the TASK message, this message tells other Master to init task
    string create_TASK_msg(unsigned long numbytes, string sdfsfilename, string requester_IP);

    //This is the PARTITION message, this message tells other Master to init task
    string create_PART_msg(unordered_map<int, string> partitions_to_VMs);

    //This is the START message, this message tells other Master to init task
    string create_START_msg(string worker_ip);

    //This is the SUPERSTEP message, this message tells other Master to init task
    string create_SS_msg(int superstep);

    //This is the DONE message, this message tells other Master to init task
    string create_DONE_msg(bool active_flag, string worker);

    //This is the APP message, this message tells other Master to init task
    string create_APP_msg(string destination_vertex, long double message, int partition_number);

    //This is the handler function of the H msg
    void handle_H_msg(string msg);

    //This is the handler function of the J msg
    void handle_J_msg(string msg);

    //This is the handler function of the N msg
    void handle_N_msg(string msg, bool haveLock);

    //This is the handler function of the L msg
    void handle_L_msg(string msg, bool haveLock);

    //This is the handler function of the I msg
    void handle_I_msg(string msg);

    //This is the handler function of the G msg
	  void handle_G_msg(string msg, bool haveLock);

    //This is the handler function of the T msg
    void handle_T_msg(string msg, bool haveLock);

    //This is the handler function of the Q msg
    void handle_Q_msg(string msg, bool haveLock);

    //This is the handler function of the P msg
    void handle_P_msg(string msg, bool haveLock, int my_socket_fd);

    //This is the handler function of the SHARD msg
    void handle_SHARD_msg(string msg, bool haveLock, int my_socket_fd);

    //This is the handler function of the GET msg
    void handle_GET_msg(string msg, bool haveLock, int my_socket_fd);

    //This is the handler function of the GOT msg
    void handle_GOT_msg(string msg, bool haveLock, int my_socket_fd);

    //This is the handler function of the LS msg
    void handle_LS_msg(string msg, bool haveLock, int my_socket_fd);

    //This is the handler function of the DEL msg
    void handle_DEL_msg(string msg, bool haveLock, int my_socket_fd);

    //This is the handler function of the DEL msg
    void handle_DELETE_msg(string msg);

    //This is the handler function of the PUTNOTIFY msg
    void handle_PUTNOTIFY_msg(string msg);

    //This is the handler function of the FD msg
    void handle_VMF_msg(string msg);

    // handled when parsing the message received in the udp listener
    void handle_ELECTED_msg(string msg);

    //This is the handler function of the FD msg
    void handle_MASTERFD_msg(string msg);

    //This is the MAP msg handler function
    void handle_MAP_msg(string msg);

    //This is the inM msg handler function
    void handle_inM_msg(string msg);

    //This is the inV msg handler function
    void handle_inV_msg(string msg);

    //This is the inV msg handler function
    void handle_SAVAReg_msg(string msg, bool haveLock);

    //This is the inV msg handler function
    void handle_ALIVE_msg(string msg);

    //This is the inV msg handler function
    void handle_TASK_msg(string msg, bool haveLock, int fd);

    //This is the inV msg handler function
    void handle_PART_msg(string msg, bool haveLock);

    // This is the LOAD msg handler function
    void handle_START_msg(string msg, bool haveLock);

    // This is the APP msg handler function
    void handle_APP_msg(string msg, bool haveLock);

    //This is the ENQUEUE msg handler function
    void handle_ENQUEUE_msg(string msg, bool haveLock);

    //This is the SS msg handler function
    void handle_SS_msg(string msg, bool haveLock);

    //This is the DONE msg handler function
    void handle_DONE_msg(string msg, bool haveLock);

    //This funcion is used to spread the gossip
    void gossip_msg(string msg, bool haveLock);
};

void handle_fail(string ip, bool haveLock);

void master_election_notification(bool haveLock);

void terminate_superstep();

#endif /* Message_h */
