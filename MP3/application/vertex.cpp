#include <iostream>
#include "md5.h"
#include "vertex.h"
#include "common.h"
#include "Protocol.h"
#include "UDP.h"


using namespace std;

// #define num_vertices 5 //only for g.txt Needs to be changed

const string& Vertex::vertex_id() const {
  return v_id;
}

int Vertex::superstep() const{
  return my_vm_info.superstep;
}

long double Vertex::GetValue(){
  return v_info.current_value;
}

long double* Vertex::MutableValue(){
  return &v_info.current_value;
}
 
vector<long double> Vertex::GetOutEdgeIterator(){
  //return iterator to the outgoing edge vector
  return v_info.outgoing_edges;
}

void Vertex::SendMessageTo(const long dest_vertex, const long double message){
  //find IP of dest_vertex by finding the partition it belongs to
  // cout<<"sending message to "<<dest_vertex<<" with msg "<<message<<endl;
  long target = dest_vertex;
  Protocol p;
  UDP udp;
  string hash = md5(std::to_string(target));
  std::istringstream converter(hash.substr(27));
    unsigned int value;
  converter >> std::hex >> value;
  worker_lock.lock();
  // cout<<"value "<<value<<"alive "<<my_vm_info.alive_workers.size()<<endl;
    int index_partition = value % (my_vm_info.alive_workers.size()*NUM_PARTITIONS);
  // cout<<dest_vertex<<" with partition "<<index_partition<<endl;

  worker_lock.unlock();
    if(my_vm_info.partitions.find(index_partition) == my_vm_info.partitions.end()){
      // cout<<"not owned"<<endl;
    string ip = my_vm_info.partitions_to_VMs[index_partition];
    string t_msg = p.create_APP_msg(std::to_string(dest_vertex), message, index_partition);
      udp.send_msg(ip, t_msg);
    }
    else{
      // cout<<"owned"<<endl;
      my_vm_info.active_flag = true;
      // cout<<"size b4:"<<my_vm_info.vertex_state[index_partition%NUM_PARTITIONS][std::to_string(dest_vertex)].incoming_msg_S_1.size();
      my_vm_info.vertex_state[index_partition%NUM_PARTITIONS][std::to_string(dest_vertex)].incoming_msg_S_1.push_back(message);
      // cout<<"size after:"<<my_vm_info.vertex_state[index_partition%NUM_PARTITIONS][std::to_string(dest_vertex)].incoming_msg_S_1.size();
      for(auto it = my_vm_info.vertex_state[index_partition%NUM_PARTITIONS][std::to_string(dest_vertex)].incoming_msg_S_1.begin(); 
          it != my_vm_info.vertex_state[index_partition%NUM_PARTITIONS][std::to_string(dest_vertex)].incoming_msg_S_1.end(); it++){
        // cout<<"msgs queued: "<<*it<<endl;
      }
    }
}

void Vertex::VoteToHalt(){
  cout<<v_id<<" voting to halt"<<endl;
  v_info.flag_next = 0; 
}

long Vertex::NumVertices(){
  return my_vm_info.num_vertices;
}


void Vertex::CopyToWorker(){
    // cout<<"incopy to worker for vertex:"<<v_id<<endl;

  string hash = md5(v_id);
  std::istringstream converter(hash.substr(27));
    unsigned int value;
  converter >> std::hex >> value;
    worker_lock.lock();
    int index_partition = value % (my_vm_info.alive_workers.size()*NUM_PARTITIONS);
  worker_lock.unlock();
    // cout<<"vertex belongs to:"<<index_partition<<endl;

    my_vm_info.vertex_state[index_partition%NUM_PARTITIONS][v_id].current_value = v_info.current_value;
    //assuming outgoing edges not changed
}