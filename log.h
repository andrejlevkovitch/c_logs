#pragma once


#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if __STDC_VERSION__ >= 201112L || __cplusplus >= 201103L
#  ifdef __STDC_VERSION__
#    include <stdatomic.h>
#    define LOG_ATOMIC_COUNTER_TYPE atomic_int
#  elif __cplusplus
#    include <atomic>
#    define LOG_ATOMIC_COUNTER_TYPE std::atomic_int
#  endif
#else
#  define LOG_ATOMIC_COUNTER_TYPE int
#  warning "atomic required c11/c++11 standard, LOG_*_EACH is not thread safe"
#endif

#ifdef __linux__
#  include <fcntl.h>
#  include <unistd.h>
#endif

#if __has_include(<syslog.h>)
#  define LOG_USE_SYSLOG_SINK
#  include <syslog.h>

// XXX undef syslog defines for avoid intersection with logging macroses
#  undef LOG_DEBUG
#  undef LOG_INFO
#  undef LOG_WARNING
#endif


#define LOG_MESSAGE_MAX_SIZE (512)
#define LOG_RECORD_MAX_SIZE  (1024)


#ifdef __cplusplus
extern "C" {
#endif

enum LogSeverity {
  LogNone    = 0,
  LogFirst   = 0b000001,
  LogFailure = 0b000001,
  LogError   = 0b000010,
  LogThrow   = 0b000010,
  LogWarning = 0b000100,
  LogInfo    = 0b001000,
  LogDebug   = 0b010000,
  LogTrace   = 0b100000,
  LogLast    = 0b100000,
  LogAll     = 0b111111,
};


typedef struct _log_sink {
  void *data;
  void (*format)(char             buf[LOG_RECORD_MAX_SIZE],
                 enum LogSeverity severity,
                 const char *     filename,
                 int              line,
                 const char *     function,
                 const char *     message,
                 void *           data);
  void (*consume)(enum LogSeverity, const char *record, void *data);
  void (*dispose)(void *data);
  uint8_t filter;
} log_sink;

typedef struct _log_sink_list {
  log_sink *sinks;
  uint8_t   sink_count;
  uint8_t   main_filter;
} log_sink_list;


log_sink_list *log_get_sink_list();
const char *   log_severety_to_str(enum LogSeverity severity);
void           log_default_format(char             buf[LOG_RECORD_MAX_SIZE],
                                  enum LogSeverity severity,
                                  const char *     filename,
                                  int              line,
                                  const char *     function,
                                  const char *     message,
                                  void *           data);
void           log_file_consume(enum LogSeverity severity,
                                const char *     record,
                                void *           file);
void           log_file_dispose(void *file);


#ifdef __linux__

#  define PTR2FD(ptr)  (int)(uintptr_t)(ptr)
#  define FD2PTR(desc) (void *)(uintptr_t)(desc)

void log_fd_consume(enum LogSeverity severity,
                    const char *     record,
                    void *           a_desc);
void log_fd_dispose(void *file);


/**\brief add new sink to logger that writes logs to descriptor
 * \param descriptor file descriptor as int
 * \note automatically close descriptor at LOGGER_SHUTDOWN
 */
#  define LOGGER_ADD_FD_SINK(format_clb, log_filter, descriptor) \
    LOGGER_ADD_SINK(format_clb,                                  \
                    log_filter,                                  \
                    log_fd_consume,                              \
                    log_fd_dispose,                              \
                    FD2PTR(descriptor))

#endif


#ifdef LOG_USE_SYSLOG_SINK

void log_syslog_format(char             buf[LOG_RECORD_MAX_SIZE],
                       enum LogSeverity severity,
                       const char *     filename,
                       int              line,
                       const char *     function,
                       const char *     message,
                       void *           data);
void log_syslog_consume(enum LogSeverity severity,
                        const char *     record,
                        void *           data);
int  log_to_syslog_priority(enum LogSeverity severity);


/**\brief add syslog logger sink
 * \note doesn't call openlog, so you should call it manually, or it will be
 * automatically called by first syslog call
 * \note doesn't call closelog, because the use is optional
 */
#  define LOGGER_ADD_SYSLOG_SINK(format_clb, log_filter) \
    LOGGER_ADD_SINK(format_clb, log_filter, log_syslog_consume, NULL, NULL)

#endif


#define LOGGER (log_get_sink_list())

#define LOGGER_ADD_SINK(format_clb,                                 \
                        log_filter,                                 \
                        consume_clb,                                \
                        dispose_clb,                                \
                        a_data)                                     \
  {                                                                 \
    LOGGER->sink_count++;                                           \
    LOGGER->main_filter |= log_filter;                              \
    LOGGER->sinks =                                                 \
        (log_sink *)realloc(LOGGER->sinks,                          \
                            sizeof(log_sink) * LOGGER->sink_count); \
    LOGGER->sinks[LOGGER->sink_count - 1].format  = (format_clb);   \
    LOGGER->sinks[LOGGER->sink_count - 1].filter  = (log_filter);   \
    LOGGER->sinks[LOGGER->sink_count - 1].consume = (consume_clb);  \
    LOGGER->sinks[LOGGER->sink_count - 1].dispose = (dispose_clb);  \
    LOGGER->sinks[LOGGER->sink_count - 1].data    = (a_data);       \
  }

#define LOGGER_SHUTDOWN()                                                  \
  {                                                                        \
    for (uint log_sink_counter = 0; log_sink_counter < LOGGER->sink_count; \
         ++log_sink_counter) {                                             \
      log_sink *sink = &LOGGER->sinks[log_sink_counter];                   \
      if (sink->dispose) {                                                 \
        sink->dispose(sink->data);                                         \
      }                                                                    \
    }                                                                      \
    free(LOGGER->sinks);                                                   \
    LOGGER->sink_count  = 0;                                               \
    LOGGER->main_filter = 0;                                               \
  }

#define LOG_PREPARE_MESSAGE(severity, ...)                          \
  char log_fmt_str_buf[LOG_MESSAGE_MAX_SIZE];                       \
  int  log_fmt_str_buf_count =                                      \
      snprintf(log_fmt_str_buf, LOG_MESSAGE_MAX_SIZE, __VA_ARGS__); \
  if (log_fmt_str_buf_count >= LOG_MESSAGE_MAX_SIZE) {              \
    log_fmt_str_buf[LOG_MESSAGE_MAX_SIZE - 1] = '\0';               \
  }

#define LOG_PROCESS_MESSAGE(severity)                                        \
  char log_record_buf[LOG_RECORD_MAX_SIZE];                                  \
  void (*last_format_clb)(char             buf[LOG_RECORD_MAX_SIZE],         \
                          enum LogSeverity severity,                         \
                          const char *     filename,                         \
                          int              line,                             \
                          const char *     function,                         \
                          const char *     log_fmt_str_buf,                  \
                          void *           data) = NULL;                                \
  for (uint log_sink_counter = 0; log_sink_counter < LOGGER->sink_count;     \
       ++log_sink_counter) {                                                 \
    log_sink *cur_log_sink = &LOGGER->sinks[log_sink_counter];               \
    if (cur_log_sink->filter & (severity)) {                                 \
      if (cur_log_sink->format != last_format_clb) {                         \
        cur_log_sink->format(log_record_buf,                                 \
                             (severity),                                     \
                             __FILE__,                                       \
                             __LINE__,                                       \
                             __func__,                                       \
                             log_fmt_str_buf,                                \
                             cur_log_sink->data);                            \
        last_format_clb = cur_log_sink->format;                              \
      }                                                                      \
      cur_log_sink->consume((severity), log_record_buf, cur_log_sink->data); \
    }                                                                        \
  }

#define LOG_PROCESS_RECORD(severity, ...)     \
  LOG_PREPARE_MESSAGE(severity, __VA_ARGS__); \
  LOG_PROCESS_MESSAGE(severity)


#define LOG_FORMAT_IF(cond, severity, ...)          \
  if ((cond) && LOGGER->main_filter & (severity)) { \
    LOG_PROCESS_RECORD(severity, __VA_ARGS__);      \
  }

#define LOG_FORMAT(severity, ...)              \
  if (LOGGER->main_filter & (severity)) {      \
    LOG_PROCESS_RECORD(severity, __VA_ARGS__); \
  }

#define LOG_FORMAT_EACH(n, severity, ...)                  \
  if (LOGGER->main_filter & (severity)) {                  \
    static LOG_ATOMIC_COUNTER_TYPE log_atomic_counter = n; \
    if (log_atomic_counter == (n)) {                       \
      LOG_PROCESS_RECORD(severity, __VA_ARGS__);           \
      log_atomic_counter = 1;                              \
    } else {                                               \
      ++log_atomic_counter;                                \
    }                                                      \
  }


#define LOG_TRACE(...)   LOG_FORMAT(LogTrace, __VA_ARGS__)
#define LOG_DEBUG(...)   LOG_FORMAT(LogDebug, __VA_ARGS__)
#define LOG_WARNING(...) LOG_FORMAT(LogWarning, __VA_ARGS__)
#define LOG_ERROR(...)   LOG_FORMAT(LogError, __VA_ARGS__)
#define LOG_INFO(...)    LOG_FORMAT(LogInfo, __VA_ARGS__)

#define LOG_TRACE_IF(cond, ...)   LOG_FORMAT_IF(cond, LogTrace, __VA_ARGS__)
#define LOG_DEBUG_IF(cond, ...)   LOG_FORMAT_IF(cond, LogDebug, __VA_ARGS__)
#define LOG_WARNING_IF(cond, ...) LOG_FORMAT_IF(cond, LogWarning, __VA_ARGS__)
#define LOG_ERROR_IF(cond, ...)   LOG_FORMAT_IF(cond, LogError, __VA_ARGS__)
#define LOG_INFO_IF(cond, ...)    LOG_FORMAT_IF(cond, LogInfo, __VA_ARGS__)

#define LOG_TRACE_EACH(n, ...)   LOG_FORMAT_EACH(n, LogTrace, __VA_ARGS__)
#define LOG_DEBUG_EACH(n, ...)   LOG_FORMAT_EACH(n, LogDebug, __VA_ARGS__)
#define LOG_WARNING_EACH(n, ...) LOG_FORMAT_EACH(n, LogWarning, __VA_ARGS__)
#define LOG_ERROR_EACH(n, ...)   LOG_FORMAT_EACH(n, LogError, __VA_ARGS__)
#define LOG_INFO_EACH(n, ...)    LOG_FORMAT_EACH(n, LogInfo, __VA_ARGS__)


#define LOG_FAILUREX(code, ...)                  \
  {                                              \
    LOG_PROCESS_RECORD(LogFailure, __VA_ARGS__); \
    LOGGER_SHUTDOWN();                           \
    exit(code);                                  \
  }
#define LOG_FAILURE(...) LOG_FAILUREX(EXIT_FAILURE, __VA_ARGS__);

#define LOG_FAILUREX_IF(cond, code, ...)         \
  if (cond) {                                    \
    LOG_PROCESS_RECORD(LogFailure, __VA_ARGS__); \
    LOGGER_SHUTDOWN();                           \
    exit(code);                                  \
  }
#define LOG_FAILURE_IF(cond, ...) \
  LOG_FAILUREX_IF(cond, EXIT_FAILURE, __VA_ARGS__)


/**\brief add stderr logger sink
 */
#define LOGGER_ADD_STDERR_SINK(format_clb, log_filter) \
  LOGGER_ADD_SINK((format_clb), (log_filter), log_file_consume, NULL, stderr)

/**\brief add file logger sink
 * \param file FILE*
 * \note automatically close file at LOGGER_SHUTDOWN
 */
#define LOGGER_ADD_FILE_SINK(format_clb, log_filter, file) \
  LOGGER_ADD_SINK(format_clb,                              \
                  log_filter,                              \
                  log_file_consume,                        \
                  log_file_dispose,                        \
                  file)


#ifdef __cplusplus
}
#endif


#ifdef __cplusplus
#  define LOG_THROW_IF(cond, exception_class, ...) \
    if (cond) {                                    \
      LOG_PREPARE_MESSAGE(LogThrow, __VA_ARGS__);  \
      if (LOGGER->main_filter & LogThrow) {        \
        LOG_PROCESS_MESSAGE(LogThrow);             \
      }                                            \
      throw exception_class(log_fmt_str_buf);      \
    }

#  define LOG_THROW(exception_class, ...) \
    LOG_THROW_IF(1, exception_class, __VA_ARGS__)
#endif


#ifdef __cplusplus
extern "C" {
#endif

inline log_sink_list *log_get_sink_list() {
  static log_sink_list list = {NULL, 0, 0};
  return &list;
}

inline const char *log_severety_to_str(enum LogSeverity severity) {
  switch (severity) {
  case LogTrace:
    return "TRC";
  case LogDebug:
    return "DBG";
  case LogWarning:
    return "WRN";
  case LogError:
    return "ERR";
  case LogFailure:
    return "FLR";
  case LogInfo:
    return "INF";
  default:
    assert(NULL && "unknown severity");
  }

  return "UNK";
}

inline void log_default_format(char             buf[LOG_RECORD_MAX_SIZE],
                               enum LogSeverity severity,
                               const char *     filename,
                               int              line,
                               const char *     function,
                               const char *     message,
                               void *           data) {
  (void)data;

  int count = snprintf(buf,
                       LOG_RECORD_MAX_SIZE,
                       "%s %s:%d:%s | %s\n",
                       log_severety_to_str(severity),
                       filename,
                       line,
                       function,
                       message);
  if (count >= LOG_RECORD_MAX_SIZE) {
    buf[LOG_RECORD_MAX_SIZE - 1] = '\0';
  }
}

inline void
log_file_consume(enum LogSeverity severity, const char *record, void *data) {
  (void)severity;
  fprintf((FILE *)data, "%s", record);
  fflush((FILE *)data);
}

inline void log_file_dispose(void *file) {
  fclose((FILE *)file);
}


#ifdef __linux__

inline void
log_fd_consume(enum LogSeverity severity, const char *record, void *a_desc) {
  (void)severity;
  int desc = PTR2FD(a_desc);
  write(desc, record, strlen(record));
}

inline void log_fd_dispose(void *a_desc) {
  int desc = PTR2FD(a_desc);
  close(desc);
}

#endif


#ifdef LOG_USE_SYSLOG_SINK

void log_syslog_format(char             buf[LOG_RECORD_MAX_SIZE],
                       enum LogSeverity severity,
                       const char *     filename,
                       int              line,
                       const char *     function,
                       const char *     message,
                       void *           data) {
  (void)severity;
  (void)data;

  int count = snprintf(buf,
                       LOG_RECORD_MAX_SIZE,
                       "%s:%d:%s | %s",
                       filename,
                       line,
                       function,
                       message);
  if (count >= LOG_RECORD_MAX_SIZE) {
    buf[LOG_RECORD_MAX_SIZE - 1] = '\0';
  }
}

inline void
log_syslog_consume(enum LogSeverity severity, const char *record, void *data) {
  (void)data;
  syslog(log_to_syslog_priority(severity), "%s", record);
}

inline int log_to_syslog_priority(enum LogSeverity severity) {
  // XXX use magic numbers instead of syslog defines, because the defines
  // intersects with logging macroses
  switch (severity) {
  case LogFailure:
    return 0; // emerg
  case LogError:
    return 3; // err
  case LogWarning:
    return 4; // warning
  case LogInfo:
    return 6; // info
  case LogDebug:
  case LogTrace:
    return 7; // debug
  default:
    return 2; // crit
  }
}

#endif

#ifdef __cplusplus
}
#endif
