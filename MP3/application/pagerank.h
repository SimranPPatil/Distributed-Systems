#ifndef PAGERANK_H
#define PAGERANK_H

class PageRankVertex : public Vertex {
 public:
  PageRankVertex(string vertex_id, state vertex_state);
  virtual void Compute();//MessageIterator * msgs);
  virtual ~PageRankVertex(){
  	cout<<"pagerank dtor"<<endl;
  }
};

#endif

