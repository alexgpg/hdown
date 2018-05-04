#ifndef HDOWN_HTTP_PARSE_H_
#define HDOWN_HTTP_PARSE_H_

#include <cstdint>

struct FindBodyParser {
  enum State {
    NEED_MORE,
    FOUND_END_OF_HEADERS,
    FOUND_BODY,
  };

  static const char *BODY_DELIMITER;

  State ParseChunk(const char *buff, size_t buff_size);

  State state = NEED_MORE;
  uint8_t matched = 0;
  size_t body_begin_pos = 0;
};

const char *FindBodyParser::BODY_DELIMITER = "\r\n\r\n";

struct RespStatusCodeParser {
  enum State {
    PREFIX,
    VERSION,
    BEFORE_CODE,
    CODE,
    PARSED,
    ERROR,
  };
  
  static const char *HTTP_VER_PREFIX;
  static const uint8_t PREFIX_LEN = 7;
  static const uint8_t CODE_LEN = 3;

  State ParseChunk(const char *buff, size_t buff_size);

  State state = PREFIX;
  uint8_t prefix_matched_count = 0;
  uint8_t code_str_len = 0;
  char code_str_buff[4]{};
  int code = 0;
};

const char *RespStatusCodeParser::HTTP_VER_PREFIX = "HTTP/1.";

struct ContentLengthParser {
  enum State {
    HEADER,
    VALUE,
    PARSED,
    ERROR,
  };
 
  static const char *CONTENT_LENGTH_PREFIX;
  static const uint8_t PREFIX_LEN = 16;

  State ParseChunk(const char *buff, size_t buff_size);  

  State state = HEADER;
  uint8_t prefix_matched_count = 0;
  char value_str[16]{};
  uint8_t value_str_len = 0;
  size_t content_len;
};

const char *ContentLengthParser::CONTENT_LENGTH_PREFIX = "Content-Length: ";

FindBodyParser::State FindBodyParser::ParseChunk(const char *buff,
                                                 size_t buff_size) { 
  for (size_t i = 0; i < buff_size; i++) {
    switch (state) {
      case NEED_MORE: {
        char search_sym = BODY_DELIMITER[matched];
        if (buff[i] == search_sym) {
          matched++;
        } else {
          matched = 0;
        }
        if (matched == 4) state = FOUND_END_OF_HEADERS;
        break;
      }
      case FOUND_END_OF_HEADERS: {
        body_begin_pos = i;
        state = FOUND_BODY;
        break;
      }
      default: {
        return state;
      }
    }
  }
  return state;
}

RespStatusCodeParser::State RespStatusCodeParser::ParseChunk(const char *buff,
                                                             size_t buff_size) {
  for (size_t i = 0; i < buff_size; i++) {
    switch (state) {
      case PREFIX: {
        char search_sym = HTTP_VER_PREFIX[prefix_matched_count]; 
        if (buff[i] == search_sym) {
          prefix_matched_count++; 
        } else {
          prefix_matched_count = 0;
        }
        if (prefix_matched_count == PREFIX_LEN) state = VERSION;
        break;
      }
      case VERSION: {
        if (buff[i] == '0' || buff[i] == '1') {
          state = BEFORE_CODE;
        } else {
          state = ERROR;
        }
        break;
      }
      case BEFORE_CODE: {
        if (buff[i] == ' ') {
          state = CODE;
        } else {
          state = ERROR;
        }
        break;
      }
      case CODE: {
        if (std::isdigit(buff[i])) {
          code_str_buff[code_str_len++] = buff[i];
          // Not too reliable.
          if (code_str_len == CODE_LEN) {
            code = std::atoi(code_str_buff);
            state = PARSED;
          }
        } else {
          state = ERROR;
        }
      }
      default: {
        return state;
      }
    }
  }
  return state;
}

ContentLengthParser::State ContentLengthParser::ParseChunk(const char *buff,
                                                           size_t buff_size) {
  for (size_t i = 0; i < buff_size; i++) {
    switch (state) {
      case HEADER: {
        char search_sym = CONTENT_LENGTH_PREFIX[prefix_matched_count]; 
        if (buff[i] == search_sym) {
          prefix_matched_count++;
        } else {
          prefix_matched_count = 0;
        }
        if (prefix_matched_count == PREFIX_LEN) {
          state = VALUE;
        }
        break;
      }
      case VALUE: {
        if (std::isdigit(buff[i])) {
          value_str[value_str_len++] = buff[i];
          if (value_str_len == sizeof(value_str)) {
            state = ERROR;
            return state;
          }
        } else if(buff[i] == '\r') {
           content_len = std::atoi(value_str);
           state = PARSED;
           return state;
        } else {
          state = ERROR;
          return state;
        }
      }
      default: {
        return state;
      }
    }
  }
  return state;
}

#endif // HDOWN_HTTP_PARSE_H_
