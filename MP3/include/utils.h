#ifndef MEMBERSHIP_UTILS_H
#define MEMBERSHIP_UTILS_H

// C++ style includes
#include <string>

namespace membership {

// TODO: Scalable vm count

/**
 * Checks if the given string is a prefix of the other.
 *
 * Arguments:
 * 		pre		- the prefix string
 * 		str		- the entire string
 *
 * Returns true if the given string is a prefix, otherwise false.
 */
bool prefix(const std::string pre, const std::string str);

/**
 * Converts a vm number (valid range 1-10) into a two-digit
 * string representation which prefixes a zero, '0', for
 * numbers less than 10.
 *
 * Arguments:
 * 		num		- the vm number from 1-10
 *		dest	- the buffer to hold the result. Must be at least size 3
 *		term	- null terminates the string if set to true
 *
 * Returns 0 on success, -1 on failure
 */
int vm_num_str(int num, char * dest, bool term);

/**
 * Converts a vm number string (valid range 01-10) into an
 * integer representation which. The number string may have
 * miscellaneous characters after the two-digit number since
 * the function does not check for a terminating null character.
 *
 * O(1).
 *
 * Arguments:
 * 		str		- the two-digit vm number string
 *		num		- a pointer to an integer to store the result in
 *
 * Returns 0 on success, -1 on failure
 */
int vm_str_num(char * str, int * num);

/**
 * Used to handle runtime error reporting with C++ exceptions.
 *
 * handle_perror() is used with C functions which use the traditional
 * error reporting mechanism, errno. If the function failed (result is
 * true), the error message is obtained from errno and a descriptive C++
 * exception is thrown.
 *
 * handle_qerror() is for reporting errors from general sources. The
 * exception message is obtained by evaluating the format string with
 * the given arguments.
 *
 * handle_error() combines the functionality of both of the above
 * functions. The functionality may be chosen by setting the get_error
 * parameter to true for handle_perror() and false for handle_qerror().
 * handle_error() is not exposed externally.
 * 
 * The main motivation for providing different functions is to write
 * cleaner code by eliminating the use of "magic constants," which may
 * cause confusion in reading the code.
 *
 * Arguments:
 *		result 		- a boolean value indicating if the operation failed
 *		prefixfmt 	- (optional) a printf-like format string to prefix
 *					  the error message with
 *		get_error	- (optional) a boolean value indicating if the error
 *					  message contained in errno is to be appended
 *		...			- (optional) the arguments to the format string
 *
 * Exceptions:
 * 		- length error if the message generated using the format string
 * 		  and its arguments cannot fit in a buffer of size ERROR_LENGTH
 * 		- invalid argument if the format string and its arguments cannot
 * 		  be printed
 * 		- runtime error if the result is true
 */
// void handle_error(bool result, std::string prefixfmt, bool get_error, ...);
void handle_perror(bool result, std::string prefixfmt = "", ...);
void handle_qerror(bool result, std::string prefixfmt = "", ...);


}	// namespace membership
#endif	// MEMBERSHIP_UTILS_H
