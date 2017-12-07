//
//  main.cpp
//
//
//  Created by Hieu Huynh on 9/27/17.
//

#include "common.h"
#include "Protocol.h"
#include "logging.h"
#include "UDP.h"

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

//No need lock
int my_socket_fd;
VM_info my_vm_info;
void update_hb_targets(bool haveLock);

UDP* my_listener;

string vm_hosts[NUM_VMS] =  {
    "fa17-cs425-g13-01.cs.illinois.edu",
    "fa17-cs425-g13-02.cs.illinois.edu",
    "fa17-cs425-g13-03.cs.illinois.edu",
    "fa17-cs425-g13-04.cs.illinois.edu",
    "fa17-cs425-g13-05.cs.illinois.edu",
    "fa17-cs425-g13-06.cs.illinois.edu",
    "fa17-cs425-g13-07.cs.illinois.edu",
    "fa17-cs425-g13-08.cs.illinois.edu",
    "fa17-cs425-g13-09.cs.illinois.edu",
    "fa17-cs425-g13-10.cs.illinois.edu"
};

void heartbeat_checker_handler();
void get_membership_list(bool is_VM0);
void init_machine();
void msg_handler_thread(string msg);
void heartbeat_sender_handler();
void update_hb_targets(bool haveLock);
string int_to_string(int num);
int string_to_int(string str);
void print_membership_list();



void update_hb_targets(bool haveLock){
    update_hbs_log <<= "-----------------------------Updating HB Targets...";
    if(haveLock == false){
        membership_list_lock.lock();
        hb_targets_lock.lock();
    }
    
    set<int> new_hb_targets;
    //    print_membership_list();
    //Get new targets
    auto my_it = membership_list.find(my_vm_info.vm_num);
    update_hbs_log << "     My vm_num: " << *my_it<<"\n";
    
    update_hbs_log << "   Membership list: ";
    for(auto it = membership_list.begin(); it!= membership_list.end(); it++){
        update_hbs_log << *it << " ";
    }
    update_hbs_log <<"\n";
    
    int count = 0;
    for(auto it = next(my_it); it != membership_list.end() && count < NUM_TARGETS/2; it++){
        update_hbs_log << "     Here1: " << *it <<"\n";
        new_hb_targets.insert(*it);
        count ++;
    }
    
    for(auto it = membership_list.begin(); it != my_it && count < NUM_TARGETS/2; it++){
        update_hbs_log << "     Here2: " << *it<<"\n";
        
        new_hb_targets.insert(*it);
        count ++;
    }
    update_hbs_log << "Count = " << count <<"\n";
    if(count == NUM_TARGETS/2){
        update_hbs_log << "Here3a:  " << *prev(my_it)<<"\n";
        count = 0;
        if(my_it != membership_list.begin()){
            for(auto it = prev(my_it); it != membership_list.begin() && count < NUM_TARGETS/2; it--){
                if(new_hb_targets.find(*it) == new_hb_targets.end()){
                    update_hbs_log << "     Here3: " << *it<<"\n";
                    new_hb_targets.insert(*it);
                    count++;
                }
            }
            if(count < (NUM_TARGETS/2)  && new_hb_targets.find(*membership_list.begin()) == new_hb_targets.end()
               && (*membership_list.begin()) != *my_it){
                update_hbs_log << "     Here4: " << *membership_list.begin()<<"\n";
                count++;
                new_hb_targets.insert(*membership_list.begin());
            }
        }

        for(auto it = prev(membership_list.end()); it != my_it && count < NUM_TARGETS/2; it--){
            if(new_hb_targets.find(*it) == new_hb_targets.end()){
                update_hbs_log << "     Here5: " << *it<<"\n";
                new_hb_targets.insert(*it);
                count++;
            }
        }
    }
    
        update_hbs_log << "New hb_targets: ";
        for(auto it = new_hb_targets.begin(); it != new_hb_targets.end(); it++){
            update_hbs_log << *it<< " ";
        }
        update_hbs_log <<"\n";
    
    Protocol p ;
    UDP udp;
    //Old targets is not in new targets, set HB to 0
    for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
        if(new_hb_targets.find(*it) == new_hb_targets.end() && membership_list.find(*it) != membership_list.end()){
            update_hbs_log << "Set HB of VM " <<*it << " to 0\n";
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
    
    //Print out HB targets
    update_hbs_log << "Current hb_targets: ";
    for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
        update_hbs_log << *it<< " ";
    }
    update_hbs_log <<"\n";
    
    if(haveLock == false){
        hb_targets_lock.unlock();
        membership_list_lock.unlock();
    }
    update_hbs_log <<= "----------------------------";
    return;
}

string int_to_string(int num){
    string ret("");
    int first_digit = num/10;
    int sec_digit = num%10;
    ret.push_back((char)(first_digit + '0'));
    ret.push_back((char)(sec_digit + '0'));
    return ret;
}

int string_to_int(string str){
    int ret = 0;
    for(int i = 0; i < (int)str.size(); i++){
        ret = ret*10 + (str[i] - '0');
    }
    return ret;
}

//MUST HAVE LOCK BEFORE CALL THIS FUNCTION!!!
void print_membership_list(){
	membership::Logger::Handle pml_log = my_logger.get_handle("Print Membership List");
    pml_log << "\nCurrent membership list: \n";
    for(auto it = membership_list.begin(); it != membership_list.end(); it++){
        pml_log << "id: " << vm_info_map[*it].vm_num << " --- ip address: " << vm_info_map[*it].ip_addr_str
        << " --- time stamp: "<<vm_info_map[*it].time_stamp << " --- key: " <<= *it;
    }
}


/*This function send request to VM0 to get membershiplist, and set the membership list based on response
 *Input:    None
 *Return:   None
 */
void get_membership_list(bool is_vm0){
    UDP local_udp;
    Protocol local_proc;
    string request_msg = local_proc.create_J_msg();
    if(is_vm0 == false){
        while(1){
            cout << "Requesting membership list from VM0...\n";
            local_udp.send_msg(vm_hosts[0], request_msg);
            string i_msg = local_udp.read_msg_non_block(200);
            if((i_msg.size() == 0) || (i_msg[0] != 'I') ){
                continue;
            }
            int num_node = string_to_int(i_msg.substr(3,2));
            if((int)i_msg.size() == num_node*16 + 6){
                cout << "Receive I_msg from VM1: " << i_msg;
                local_proc.handle_I_msg(i_msg);
                break;
            }
        }
    }
    else{
        bool got_msg = false;
        cout << "Check if there is any VM still alive...\n";
        for(int i = 1; i < NUM_VMS; i++){
            local_udp.send_msg(vm_hosts[i], request_msg);
            string i_msg = local_udp.read_msg_non_block(200);
            if((i_msg.size() == 0) || (i_msg[0] != 'I') ){
                continue;
            }
            int num_node = string_to_int(i_msg.substr(3,2));
            if((int)i_msg.size() == num_node*16 + 6){
                got_msg = true;
                cout << "Receive I_msg from VM1: " << i_msg;
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
                    cout << "Receive I_msg from VM1: " << i_msg;
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
    
    cout << "My ip: ";
    for (int i = 0 ; i < 4; i++) {
        my_vm_info.ip_addr_str.append(to_string((unsigned int) my_vm_info.ip_addr[i]));
        if(i != 3)
            my_vm_info.ip_addr_str.push_back('.');
    }
    
    cout << my_vm_info.ip_addr_str <<"\n";
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
    //string host_name = vm_hosts[my_id];
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
        //        if(bind(my_socket_fd, p->ai_addr, p->ai_addrlen) == -1){
        //            close(my_socket_fd);
        //            perror("listener: bind");
        //            continue;
        //        }
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
        
//        membership_list_lock.lock();
//        membership_list.insert(0);
//        vm_info_map[0] = my_vm_info;
//        membership_list_lock.unlock();
    }
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
    //    else if(msg[0] == 'R'){       //Only receive this once when startup. Did it in init_machine
    //        if((msg.size()-2)%12 != 0)
    //            return;
    //        msg_handler.handle_R_msg(msg);
    //    }
}

/* This is thread handler to read and handle msg
 *Input:    None
 *Return:   None
 */
void listener_thread_handler(){
    vector<std::thread> thread_vector;
    while(1){
        string msg = my_listener->receive_msg();
        if(msg.size() == 0){
            continue;
        }
        msg_handler_thread(msg);
        
//        std::thread th(msg_handler_thread,msg);
//        thread_vector.push_back(std::move(th));
        //        http://www.cplusplus.com/forum/unices/194352/
    }
}

/* This is thread handler to send heartbeats to pre/successors
 *Input:    None
 *Return:   None
 */
void heartbeat_sender_handler(){
	membership::Logger::Handle log_handle = my_logger.get_handle("Heartbeat Sender");

    Protocol local_protocol;
    string h_msg = local_protocol.create_H_msg();
    while(1){
        UDP local_udp;
        membership_list_lock.lock();
        hb_targets_lock.lock();
        
        for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
            if(vm_info_map.find(*it) != vm_info_map.end()){
				//log_handle << vm_info_map[*it].ip_addr_str<< "    " << vm_info_map[*it].time_stamp << "   " <<= vm_info_map[*it].vm_num;
                
				//log_handle << "Send HB to ip: " << vm_info_map[*it].ip_addr_str << "    " <<= *it;
                local_udp.send_msg(vm_info_map[*it].ip_addr_str, h_msg);
            }
        }
        
        hb_targets_lock.unlock();
        membership_list_lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(HB_TIME));
    }
}

/* This is thread handler to check heartbeats of pre/successors. If timeout, set that node to DEAD, and send msg
 *Input:    None
 *Return:   None
 */
void heartbeat_checker_handler(){
	membership::Logger::Handle log_handle = my_logger.get_handle("Heartbeat Checker");
    while(1){
        membership_list_lock.lock();
        hb_targets_lock.lock();
        time_t cur_time;
        cur_time = time (NULL);
        
        for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
            std::unordered_map<int,VM_info>::iterator dead_vm_it;
            if((dead_vm_it = vm_info_map.find(*it)) != vm_info_map.end()){
                if(cur_time - vm_info_map[*it].heartbeat > HB_TIMEOUT && vm_info_map[*it].heartbeat != 0){
                    VM_info dead_vm = vm_info_map[*it];
                    vm_info_map.erase(dead_vm_it);
                    membership_list.erase(*it);
					log_handle << "Deleted VM: id: " << dead_vm.vm_num << " --- ip: "<< dead_vm.ip_addr_str << " --- ts: " << dead_vm.time_stamp << " --- Last HB: " << dead_vm.heartbeat << "--- cur_time:  " <<= cur_time;
                    
                    update_hb_targets(true);

                    //NEED TO DO: Spread GOSSIP!!!
                    Protocol p;
                    p.gossip_msg(p.create_L_msg(dead_vm.vm_num), true);
                }
            }
        }
        hb_targets_lock.unlock();
        membership_list_lock.unlock();
    }
}

/* This is thread handler wait for user input to close file before Ctrl+C
 *Input:    None
 *Return:   None
 */
void user_input_handler(){
	membership::Logger::Handle log_handle = my_logger.get_handle("User Input Handler");
    while(1){
        string input;
        cin >> input;
        if(strncmp(input.c_str(), "quit", 4) == 0){
			my_logger.write_to_file("out/log.txt");
        }
        else if(strncmp(input.c_str(), "ML", 2) == 0){
            membership_list_lock.lock();
            print_membership_list();
            membership_list_lock.unlock();
        }
        else if(strncmp(input.c_str(), "target", 6) == 0){
            hb_targets_lock.lock();
            log_handle << "HB targets: ";
            for(auto it = hb_targets.begin(); it != hb_targets.end(); it++){
                log_handle << *it << " ";
            }
            log_handle <<= "";
            hb_targets_lock.unlock();
        }
    }
}

int main(){
    init_machine();
    
    print_membership_list();
    
    cout << "My VM info: id: " << my_vm_info.vm_num << " --- ip: "<< my_vm_info.ip_addr_str << " --- ts: "<<my_vm_info.time_stamp<<"\n";
    
    cout <<"-----------Successfully Initialize-----------\n";
    std::thread listener_thread(listener_thread_handler);
    std::thread heartbeat_sender_thread(heartbeat_sender_handler);
    std::thread heartbeat_checker_thread(heartbeat_checker_handler);
    std::thread user_input_thread(user_input_handler);
    
    listener_thread.join();
    heartbeat_sender_thread.join();
    heartbeat_checker_thread.join();
    user_input_thread.join();
    
    return 0;
}















