# Distributed-Systems
This is a simple distributed system with a simple file system and a graph processing system like Pregel

# Installation
--------------
make workspace
make

RUNNING
-------
To run program: ./main

Commands while running:
-----------------------
JOIN:   join the system as client, master, worker or standby master (ip dependent)
QUIT:   quit the system
ML:     Print the membership list
MyVM:   Print the vm info
TASK:   For the Client to request a task from the master
V   :   To view the loaded vertex values
Z   :   To get the total number of vertices in the graph
X   :   Print the values of the vertices

SDFS Operations:
----------------
put localfilename sdfsfilename      :       To insert or update a file
get sdfsfilename localfilename      :       To fetch a file
delete sdfsfilename                 :       To delete a file
ls sdfsfilename                     :       To list all machines where the file is present
store                               :       To list all files currently being stored at the machine

Client:
_____________
Submits the input graph and application.so when prompted.
