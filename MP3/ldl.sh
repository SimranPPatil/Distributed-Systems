#!/bin/bash
cd application
rm a*
rm c*
rm l*
rm P*
rm m*
rm u*
rm v*
rm U*
rm V*
cd ..
cp include/* application/
cp src/* application/
cd application
g++ -shared -fPIC pagerank.cpp -o application.so -std=c++11
cp application.so ../app.so
