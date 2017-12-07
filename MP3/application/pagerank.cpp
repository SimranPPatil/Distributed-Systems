#include <iostream>
#include "vertex.h"
#include "pagerank.h"


PageRankVertex::PageRankVertex(string vertex_id, state vertex_state){
    v_id = vertex_id;
    v_info.current_value = vertex_state.current_value;
    v_info.outgoing_edges = vertex_state.outgoing_edges;
    v_info.incoming_msg_S = vertex_state.incoming_msg_S;
    v_info.incoming_msg_S_1 = vertex_state.incoming_msg_S_1;


    // cout<<"vertex is "<<v_id<<endl;
    // cout<<v_info.current_value<<endl;
    // for(auto it = v_info.outgoing_edges.begin(); it != v_info.outgoing_edges.end(); it++)
    //     cout<<"edge:"<<*it<<endl;


}

void PageRankVertex::Compute(){//MessageIterator * msgs){
    // cout<<"Compute on :"<<this->v_id;
    if (superstep() >= 1) {
      long double sum = 0;
      for (auto i = v_info.incoming_msg_S.begin(); i!=v_info.incoming_msg_S.end(); i++)
        sum += *i;
      *MutableValue() = 0.15 / NumVertices() + 0.85 * sum;
      // cout<<"mutable val "<<*MutableValue()<<endl;
    }
    if (superstep() < 20) {
      const int n = GetOutEdgeIterator().size();
      // cout<<"size of n "<<n<<endl;
      for(auto it =  v_info.outgoing_edges.begin(); it != v_info.outgoing_edges.end(); it++){
        // cout<<"send msg to "<<*it<<" of msg:"<<(GetValue()/n)<<endl;
        SendMessageTo(*it, GetValue()/n);
      }
      // SendMessageToAllNeighbors(GetValue() / n);
    } 
    else {
      VoteToHalt();
    }
  
}

// Define functions with C symbols (create/destroy PageRank instance).
extern "C" PageRankVertex* create(string vertex_id, state vertex_state)
{
    return new PageRankVertex(vertex_id, vertex_state);
}
extern "C" void destroy(PageRankVertex* PR)
{
   delete PR ;
}