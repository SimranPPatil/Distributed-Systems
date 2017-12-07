#ifndef MEMBERSHIP_LOGGING_H
#define MEMBERSHIP_LOGGING_H

#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <mutex>

#include "common.h"

namespace membership {

class Logger {
friend class Handle;
public:
	// Public Classes
	class LogEvent {
	public:
		long long ns_since_epoch;
		std::string driver;
		std::string log;

		friend std::ostream & operator<<(std::ostream & strm, const LogEvent & evt);
	};

	class Handle {
	friend class Logger;
	public:
		// Public Constructors
		Handle(Handle && other) noexcept;

		/**
		 * Inserts tokens into the log.
		 * 		(1)	- the shift left (<<) operator appends the given
		 * 			  token to the log.
		 * 		(2)	- the shift left assign (<<=) operator appends the
		 * 			  given token to the log and finalizes the current
		 * 			  log entry. Inserting more tokens into the log
		 * 			  appends to the next log entry.
		 *
		 * Arguments:
		 * 		val	- the token to append
		 *
		 * Returns a reference to the Logger object.
		 */
		template <class T>
		Handle & operator<<(T val);

		template <class T>
		Handle & operator<<=(T val);

	private:
		// Private Constructors
		/**
		 * Default Constructor.
		 * Given for convenience, but manipulating a Handle that is
		 * default constructed yields undefined behavior.
		 *
		 * Name Constructor.
		 * Constructs the handle with a name.
		 *
		 * Arguments:
		 * 		log		- A reference to the parent logger to which
		 * 				  the handle contributes its logs
		 * 		driver	- The name of the client which writes to this
		 * 				  handle
		 */
		Handle(Logger & log, std::string driver);

		// Private Fields
		Logger & log;
		std::string driver;
		std::ostringstream log_strm;
	};

	// Constructors and the Rule of Four (TODO)
	Logger();
	~Logger();

	// Public Methods
	/**
	 * Returns an iterator to the underlying map of log entries.
	 */
	std::map<long long, LogEvent>::iterator begin();
	std::map<long long, LogEvent>::iterator end();

	/**
	 * Gets a new handle to the log. A new handle must be allocated
	 * for each concurrently executing client of the log.
	 *
	 * Thread safe.
	 *
	 * Arguments:
	 * 		driver		- the name of the client which writes to this
	 * 					  handle
	 *
	 * Returns a new handle
	 */
	Handle get_handle(std::string driver);

	/**
	 * Writes the log to a file.
	 *
	 * Arguments:
	 * 		filename	- the name of the file to write to
	 */
	void write_to_file(std::string filename);

private:
	// Private Fields
	timepnt epoch;
	std::map<long long, LogEvent> log_events;
	std::mutex log_mutex;

	// Private Methods
	void copy(const Logger & src);
	void clear();

};	// class Logger


// Template Definitions
template <class T>
Logger::Handle & Logger::Handle::operator<<(T val) {
	log_strm << val;
	return *this;
}

template <class T>
Logger::Handle & Logger::Handle::operator<<=(T val) {
	log_strm << val;

	// Construct log event
	LogEvent evt;
	evt.ns_since_epoch = std::chrono::duration_cast<unit_nanoseconds>(clk::now() - log.epoch).count();
	evt.driver = driver;
	evt.log = log_strm.str();

	// Append log to storage
	log.log_mutex.lock();
	log.log_events[evt.ns_since_epoch] = evt;
	log.log_mutex.unlock();

	// Print log
//	std::cout << evt << std::endl;

	// No need to clear since we don't extract the data
	log_strm.str("");
	return *this;
}

}	// namespace membership

#endif	// MEMBERSHIP_LOGGING_H
