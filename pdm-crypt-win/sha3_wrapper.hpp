#pragma once
#include "sha3.h"
#include <mutex>
#include <vector>
#include <iostream>
#include <functional>   // std::bind

class sha3_wrapper {
public:

	
	void add(const void* line, size_t tn) {
		arg1.push_back(line);
		arg2.push_back(tn);
		//std::thread a(&sha3_wrapper::_add,this, thread_count);
		//thrds.push_back(std::move(a));
		_add(thread_count);
		thread_count++;
	}
	
	std::string getHash() {
		return hashing.getHash();
	}
	void close_all() {
		for (auto& t : thrds) if (t.joinable())t.join();
	}
	void _add(int thd) {
		mtx.lock();
		hashing.add(arg1[thd], arg2[thd]);
		mtx.unlock();
	}
	
private:
	SHA3 hashing;
	std::mutex mtx;
	std::vector<const void*>arg1;
	std::vector<size_t>arg2;
	std::vector<std::thread> thrds;
	int thread_count = 0;
	

};