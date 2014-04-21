#! /bin/bash

# Compile & Run ModeECB Test
g++ -std=c++11 -Wall -I ../ ModeECBTest.cpp -o ModeECBTest && ./ModeECBTest

# Compile & Run ModeCBC Test
g++ -std=c++11 -Wall -I ../ ModeCBCTest.cpp -o ModeCBCTest && ./ModeCBCTest
