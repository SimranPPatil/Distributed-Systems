//
//  VM_info.cpp
//
//
//  Created by Hieu Huynh on 10/7/17.
//

#include "VM_info.h"
#include "common.h"

//Constructor for state
state::state(){
  current_value = 1/my_vm_info.num_vertices;
  bool flag = true;
}

// contructor for state
state::state(long double curr_val, long double edge, bool Aflag){
  current_value = curr_val;
  outgoing_edges.push_back(edge);
  flag = Aflag;
}

//Constructor for VM
VM_info::VM_info(){
    vm_num = 0;
    for(int i = 0 ; i < 4; i++)
        ip_addr[i] = 0;
    time_stamp = "";
    id_str = "";
    ip_addr_str = "";
    heartbeat = 0;
}

/*Constructor for VM
 *This constructor set the VM's info based on the input
 */
VM_info::VM_info(int id_, unsigned char* ip_addr_, string time_stamp_){
    vm_num = id_;
    for(int i = 0 ; i < 4; i++)
        ip_addr[i] = ip_addr_[i];
    time_stamp = time_stamp_;

    id_str = "";
    id_str.append(int_to_string(vm_num));
    for(int i = 0 ; i < 4; i++){
        id_str.push_back((unsigned char)ip_addr[i]);
        ip_addr_str.append(to_string((unsigned int) ip_addr[i]));
        if(i != 3)
            ip_addr_str.push_back('.');
    }

    id_str.append(time_stamp);

    heartbeat = 0;
}

/*Constructor for VM
 *This constructor set the VM's info based on the input
 */
VM_info::VM_info(string id_str_){
    vm_num = string_to_int(id_str_.substr(0, 2));
    for(int i = 0 ; i < 4; i ++){
        ip_addr[i] = (unsigned char) id_str_[i+2];
        ip_addr_str.append(to_string((unsigned int) ip_addr[i]));
        if(i != 3)
            ip_addr_str.push_back('.');
    }
    time_stamp = id_str_.substr(6,10);
    id_str = id_str_;
    heartbeat = 0;

}

/*This function is used to construct the VM id based on the vm_num, vm ip, and timestamp
 */
void VM_info::make_id_str(){
    id_str = "";
    id_str.append(int_to_string(vm_num));
    for(int i = 0 ; i < 4; i++)
        id_str.push_back((unsigned char)ip_addr[i]);
    id_str.append(time_stamp);
    if(ip_addr_str == ""){
        for(int i = 0 ; i < 4; i ++){
            ip_addr[i] = (unsigned char) id_str[i+2];
            ip_addr_str.append(to_string((unsigned int) ip_addr[i]));
            if(i != 3)
                ip_addr_str.push_back('.');
        }
    }
}
