#ifndef VERTEX_H
#define VERTEX_H
#include "common.h"
// 
typedef vector<long double> MessageIterator ;
typedef vector<long double>::iterator OutEdgeIterator ;

class Vertex {
 protected:
  string v_id;
  state v_info = state(0,0,0);
  // VertexValue v_val;
  // EdgeValue e_val;
  // MessageValue m_val;	

 public:
  //constructor will be in appl - specific
  virtual void Compute() = 0; //MessageIterator* msgs) = 0;
  const string& vertex_id() const;
  int superstep() const;
  long double GetValue();
  long double* MutableValue();
  vector<long double> GetOutEdgeIterator();
  void SendMessageTo(const long dest_vertex,
                     const long double message);
  void VoteToHalt();
  void CopyToWorker();
  long NumVertices();
  virtual ~Vertex(){
    cout<<"vertex dtor"<<endl;
  }
};


#endif