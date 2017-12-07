#include "utils.h"

// C++ style includes
#include <stdexcept>

// C style includes
#include <cstdarg>
#include <cstring>	// for strerror

// Local includes
#include "common.h"

namespace membership {

bool prefix(const std::string pre, const std::string str) {
	if(pre.size() > str.size()) return false;
	return std::equal(pre.begin(), pre.end(), str.begin());
}

int vm_num_str(int num, char * dest, bool term) {
	if(num < 1 || num > 10) {
		return -1;
	} else if(num == 10) {
		dest[0] = '1';
		dest[1] = '0';
	} else {
		dest[0] = '0';
		dest[1] = '0' + num;
	}

	if(term) dest[2] = '\0';

	return 0;
}

int vm_str_num(char * str, int * num) {
	// String and integer format checks
	if(str == NULL || str[0] == '\0' || str[1] == '\0' || num == NULL) return -1;

	// String validity checks
	if(str[0] - '0' > 1) return -1;


	if(str[0] == '0') {
		*num = str[1] - '0';
	} else if(str[0] == '1' && str[1] == '0') {
		*num = 10;
	} else {
		return -1;
	}
	
	return 0;
}

void handle_error(bool result, std::string prefixfmt, bool get_error, ...) {
	if(result == true) {
		va_list args;
		va_start(args, get_error);
		
		char error[ERROR_LENGTH];
		int ret;
		if((ret = vsnprintf(error, ERROR_LENGTH, prefixfmt.c_str(), args)) > ERROR_LENGTH) {
			throw std::length_error("Error message does not fit in buffer");
		} else if(ret == -1) {
			throw std::invalid_argument(strerror(errno));
		} else {
			// It is ok to not save errno since if errno is overwritten
			// another exception would have been thrown
			if(get_error) {
				throw std::runtime_error(std::string(error) + ": " + std::string(strerror(errno)));
			} else {
				throw std::runtime_error(std::string(error));
			}
		}

		va_end(args);
	}
}

void handle_perror(bool result, std::string prefixfmt, ...) {
	va_list args;
	va_start(args, prefixfmt);
	handle_error(result, prefixfmt, true, args);
	va_end(args);
}

void handle_qerror(bool result, std::string prefixfmt, ...) {
	va_list args;
	va_start(args, prefixfmt);
	handle_error(result, prefixfmt, false, args);
	va_end(args);
}


}	// namespace logging
