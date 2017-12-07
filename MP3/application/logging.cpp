#include "logging.h"

#include <iostream>
#include <iomanip>

#include "utils.h"

namespace membership {

// Printing functionality
std::ostream & operator<<(std::ostream & strm, const Logger::LogEvent & evt) {

	return strm << "[" << std::setprecision(6) << std::fixed << std::right << std::setw(12) << (double)evt.ns_since_epoch / 1000000000 << "] " << evt.driver << ": " << evt.log;
}

// Handle Constructors
Logger::Handle::Handle(Logger & log, std::string driver)
	: log(log), driver(driver) {
}

Logger::Handle::Handle(Handle && other) noexcept
	: log(other.log),
	  driver(other.driver) {

	log_strm << other.log_strm.str();
}

// Logger Constructors
Logger::Logger() {
	epoch = clk::now();
}

Logger::~Logger() {
	clear();
}

// Public Methods
std::map<long long, Logger::LogEvent>::iterator Logger::begin() {
	return log_events.begin();
}

std::map<long long, Logger::LogEvent>::iterator Logger::end() {
	return log_events.end();
}

Logger::Handle Logger::get_handle(std::string driver) {
	return Handle(*this, driver);
}

void Logger::write_to_file(std::string filename) {
	FILE * f;
	handle_perror((f = fopen(filename.c_str(), "w")) == NULL, "Failed to open file");

	std::ostringstream ss;
	for(auto it = log_events.begin(); it != log_events.end(); it++) {
		ss << it->second << std::endl;
		fprintf(f, "%s", ss.str().c_str());
		ss.str("");
	}

	handle_perror(fclose(f) == EOF, "Failed to close file");
}

// Private Methods
void Logger::copy(const Logger & src) {
	// TODO
}

void Logger::clear() {
	// Nothing
}

}	// namespace membership
