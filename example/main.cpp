#include "log.h"
#include <fcntl.h>
#include <stdexcept>

int main(void) {
  // logging by stderr
  LOGGER_ADD_STDERR_SINK(log_default_format, LogAll);


  // logging by FILE*
  FILE *log_file = fopen("file.log", "w");
  LOGGER_ADD_FILE_SINK(log_default_format, LogAll, log_file);


  // logging by file descriptor
  int fd = open("fd.log", O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
  LOGGER_ADD_FD_SINK(log_default_format, LogAll, fd);


  // logging by syslog
  openlog("sample", LOG_CONS | LOG_PID, 0);
  LOGGER_ADD_SYSLOG_SINK(log_syslog_format, LogAll);


  LOG_INFO_IF(1, "if you see this record all right");
  LOG_ERROR_IF(0, "if you see this record it is a problem");


  for (int i = 0; i < 20; ++i) {
    LOG_INFO_EACH(10,
                  "if you see that log 2 times with 0 and 10 - all right: %d",
                  i);
  }


  LOG_INFO("hello, info!");
  LOG_TRACE("hello, trace!");
  LOG_DEBUG("hello, debug!");
  LOG_WARNING("hello, warning!");
  LOG_ERROR("hello, error!");


  LOG_THROW_IF(0, std::logic_error, "if you see this log it is a problem");
  try {
    LOG_THROW(std::logic_error, "hello, throw!");
    printf("if you see that message it is a serious problem");
  } catch (std::logic_error &) {
    // all right
  }


  LOG_FAILURE("by, %s!", "failure");
  printf("oops, if you see that log record it is a serious problem");


  LOGGER_SHUTDOWN();
  return EXIT_SUCCESS;
}
