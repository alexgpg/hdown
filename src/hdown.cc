#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <fcntl.h>

#include <atomic>
#include <cassert>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "http_parse.h" 

static const long CONNECTION_TIMEOUT_SEC = 10;
static const long READ_TIMEOUT_SEC       = 10;
static const long WRITE_TIMEOUT_SEC      = 1;

static std::atomic<bool> terminated{false};

// Notes: HTTPS, basic auth aren't supported.
struct HttpUrl {
  static bool Parse(const std::string &url, HttpUrl &parsed_url) {
    std::string::size_type scheme_pos = url.find("http://");
    if (scheme_pos == std::string::npos || scheme_pos != 0) {
      std::cerr << "Bad URL: " << url << std::endl;
      return false;
    }

    std::string::size_type path_pos = url.find_first_of('/', scheme_pos + 7);
    if (path_pos == std::string::npos) {
      std::cerr << "Bad URL: " << url << std::endl;
      return false;
    }

    std::string hostport(url, scheme_pos + 7, path_pos - (scheme_pos + 7));
    if (hostport.empty()) {
      std::cerr << "Bad host(empty) in URL: " << url << std::endl;
      return false;
    }

    std::string::size_type colon_pos = hostport.find_first_of(':');
    if (colon_pos == std::string::npos) {
      parsed_url.host = hostport;
      parsed_url.portnum = 80;
    } else {
      if (colon_pos == hostport.size() - 1) {
        std::cerr << "Bad port in URL: " << url << std::endl;
        return false;
      } 
      auto portstr = std::string(hostport, colon_pos + 1);
      long portnum = std::atol(portstr.c_str());
      if (!(portnum > 0 && portnum <= 65535)) {
        std::cerr << "Bad port " << portstr << " in URL: " << url << std::endl;
        return false;
      }
      parsed_url.portnum = static_cast<uint16_t>(portnum);
      parsed_url.host = std::string(hostport, 0, colon_pos);
    }

    parsed_url.path = std::string(url, path_pos);
    return true;
  }

  std::string host;
  std::string path;
  uint16_t portnum;
};

std::string FilenameByPath(const std::string &path) {
  std::string filename;
  size_t found = path.find_last_of('/');
  if (found == std::string::npos) {
    filename = "index.html";
  } else {
    filename = path.substr(found + 1);
  }
  return filename;
}

enum DownloadState {
  READ_HEADERS,
  READ_BODY,
};

static const size_t BUFF_SIZE = 64 * 1024 * 1024;

FILE *CreateFile(const std::string &file_path) {
  FILE *file = std::fopen(file_path.c_str(), "w");
  if (!file) {
    std::cerr << "fopen(): Can't open file. Error: " << std::strerror(errno)
              << std::endl;
    return nullptr;
  }
  return file;
}

int Connect(const ::sockaddr *addr) {
  int sock = ::socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    std::cerr << "socket(): Can't create socket. Error: "
              << std::strerror(errno) << std::endl;
    return -1;
  }

  // Get maximum available receive buffer size.
  char buff[1024]{};
  FILE *rmem_file = std::fopen("/proc/sys/net/core/rmem_max", "r");
  size_t readed = std::fread(buff, 1, sizeof(buff), rmem_file);
  if (!readed) {
    return -1;
  } 
  if (readed > sizeof(buff)) {
    return -1;
  }

  int new_rcvbuf = std::atoi(buff);
 
  int rcvbuf;
  ::socklen_t optlen = sizeof(rcvbuf);

  std::cout << "Setting SO_RCVBUF to " << new_rcvbuf << std::endl; 
  if (::setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &new_rcvbuf, optlen) < 0) {
    std::cout << "setsockopt(): Can't set SO_RCVBUF to " << new_rcvbuf
              << ". Error: " << std::strerror(errno) << std::endl;
    return false;
  }
  
  if (::fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
    perror("fcntl(): Can't set socket nonblocking. Error: ");
  }
  
  int quickack = 1;
  if (::setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &quickack,
                   sizeof(quickack)) < 0) {
    std::perror("setsockopt(): Can't set TCP_QUICKACK option. Error: ");
    return false;
  }

  int res = ::connect(sock, addr, sizeof(*addr));
  if (!res) return sock;

  if (errno == EINPROGRESS) {
    ::fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    ::timeval tv;
    tv.tv_sec = CONNECTION_TIMEOUT_SEC;
    tv.tv_usec = 0;

    int retval = ::select(sock + 1, nullptr, &fds, nullptr, &tv);
    if (retval == 1) {
      int optval = -1;
      ::socklen_t optlen = sizeof(optval);
      if (::getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) {
        std::perror("getsockopt(): Can't get socket options. Error: ");
        ::close(sock);
        return -1;
      }
      if (optval != 0) {
        std::cerr << "Can't connect. Error: " << std::strerror(optval)
                  << std::endl;
        ::close(sock);
        return -1;
      }
    } else if (retval == 0) {
      std::cerr << "Connection timeout expired" << std::endl;
      close(sock);
      return -1;
    } else {
      // TODO: EINTR handler.
      std::perror("select(): Waiting for connetion error. Error: ");
    }
  } else {
    std::perror("connect(): Can't connect. Error: ");
  }
  return sock;
}

bool SendRequest(int sock, const HttpUrl& url) {
  std::ostringstream reqss;
  reqss << "GET " << url.path << " HTTP/1.1\n"
        << "Host: " << url.host << '\n'
        << '\n';
  std::string request = reqss.str();

  ssize_t sended;
  size_t total_sended = 0;
  while(total_sended < request.size()) {
    sended = ::send(sock, request.data(), request.size(), MSG_NOSIGNAL);   
    if (sended < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
      if (errno == EINTR) {
        continue;
      } else {
        std::perror("send(): Error on sending request. Error: ");
        return false; 
      }
    }
    if (sended > 0) {
      total_sended += sended;
      if (total_sended == request.size()) break;
    }

    ::fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    ::timeval wtv;
    wtv.tv_sec = WRITE_TIMEOUT_SEC;
    wtv.tv_usec = 0;

    int ret = ::select(sock + 1, nullptr, &wfds, nullptr, &wtv);
    if (ret == -1) {
      std::perror("select(): Error on sending request. Error: ");
      return false;
    };
    if (!ret) {
      std::cerr << "select(): Write timeout" << std::endl;
      return false;
    }
  }
  return true;
}

bool Download(const HttpUrl& url) {
  ::addrinfo hints{};
  ::addrinfo *addr_res;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  int res = ::getaddrinfo(url.host.c_str(), std::to_string(url.portnum).c_str(),
                          &hints, &addr_res);
  if (res) {
    std::cerr << "getaddrinfo(): Can't get addr info. Error: "
              << ::gai_strerror(res) << std::endl;
    exit(1);
  }

  std::unique_ptr<char[]> recv_buff(new char[BUFF_SIZE]);

  int sock;
  if ((sock = Connect(addr_res->ai_addr)) == -1) {
    return false;
  }

  ::freeaddrinfo(addr_res); 

  std::cout << "Connected...\n";

  if (!SendRequest(sock, url)) {
    ::close(sock);
    return false;
  }

  // Some server doesn't close the connection after download all data
  // but we can close the connection after request.
  ::shutdown(sock, SHUT_WR);

  std::string file_path = FilenameByPath(url.path);
  FILE *file = nullptr;
  int fd = -1;

  ssize_t readed;
  DownloadState state = READ_HEADERS;
  size_t total_received = 0;
  
  FindBodyParser body_parser; 
  FindBodyParser::State body_parser_state;

  RespStatusCodeParser resp_code_parser;
  RespStatusCodeParser::State code_parser_state;

  ContentLengthParser clen_parser;
  ContentLengthParser::State clen_parser_state;

  size_t file_size = 0;
  size_t content_len = 0;
  int pfd[2];
  ::fd_set fds;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);
  ::timeval tv;
  tv.tv_sec = READ_TIMEOUT_SEC;
  tv.tv_usec = 0;
  bool error = false;

  // Now read the response.
  while(!terminated.load(std::memory_order_relaxed)) {
    int retval = ::select(sock + 1, &fds, nullptr, nullptr, &tv);
    if (retval != 1) {
      break;
    }
    if (state == READ_HEADERS) {
      readed = ::recv(sock, recv_buff.get(), BUFF_SIZE, 0);
      if (readed == -1) {
        if (errno == EINTR) {
          continue;
        } else {
          perror("recv(): Can't read response. Error: ");
          error = true;
        }
      }
      total_received += readed;

      body_parser_state = body_parser.ParseChunk(recv_buff.get(), readed);
      code_parser_state = resp_code_parser.ParseChunk(recv_buff.get(), readed);
      clen_parser_state = clen_parser.ParseChunk(recv_buff.get(), readed);

      if (body_parser_state == FindBodyParser::FOUND_BODY) {
        if (code_parser_state == RespStatusCodeParser::PARSED) {
          const int code = resp_code_parser.code;
          if (code != 200) {
            std::cout << "Server response code: " << code << std::endl;
            break;
          } else {
            std::cout << "Server response: OK" << std::endl;
          }
        }

        if (clen_parser_state == ContentLengthParser::PARSED) {
          content_len = clen_parser.content_len;
          if (!content_len) {
            std::cerr << "Content length is zero" << std::endl;
            error = 1;
            break;
          }
        }

        // Write remains data in buffer to files. 
        // After that write buffers bypass userspace using
        // splice() syscalls.
 
        file = CreateFile(file_path);
        if (!file) {
          error = true;
          break;
        }
        fd = ::fileno(file);
        char *body_ptr = recv_buff.get() + body_parser.body_begin_pos;
        ssize_t chunk_size = readed - body_parser.body_begin_pos;
        if (chunk_size) { 
          char *wbuff = body_ptr;
          ssize_t wsize = chunk_size;
          ssize_t writed = 0;
          while(writed < chunk_size) {
            ssize_t ret = ::write(fd, wbuff, wsize);
            if (ret == -1) {
              if (errno == EINTR) {
                continue;
              } else {
                std::perror("write(): Can't write to file. Error: ");
                error = true;
                break;
              }
            }
            writed += ret;
            wbuff += ret;
            wsize -= ret;
          }
          if (error) { break; };
          file_size += chunk_size;
        }

        // Prepare splice() suff here
        // and move to userspace bypass download mode.
        res = ::pipe(pfd);
        if (res) {
          std::perror("pipe(): Can't create pipe. Error: ");
          error = true;
          break;
        }
        state = READ_BODY;
        continue;
      } 
    }
    if (state == READ_BODY) { 
      readed = ::splice(sock, nullptr, pfd[1], nullptr, BUFF_SIZE,
                        SPLICE_F_MOVE);
      if (readed == 0) { break; };
      if (readed == -1) {
        if (errno == EINTR) {
          continue;
        } else {
          std::perror("splice(): Can't read from socket: Error: ");
          error = true;
          break;
        }
      }
      total_received += readed;
      ssize_t writed = ::splice(pfd[0], nullptr, fd, nullptr, readed,
                                SPLICE_F_MOVE);
      if (writed == -1) {
        if (errno == EINTR) {
          continue;
        } else {
          std::perror("splice(): Can't write to file: Error: ");
          error = true;
          continue;
        }
      }
      file_size += writed;
      if (content_len > 0 && file_size == content_len) { break; }
    }
  };

  ::close(sock);
  if (file) std::fclose(file);

  std::cout << "Total received bytes: " << total_received << std::endl;
  std::cout << "Saved bytes         : " << file_size << std::endl;
  return !error;
}

void PrintUsage() {
  std::cerr << "Usage: ./hdown [URL]\n";
}

static void SigIntTermHandler(int s) {
  terminated.store(true, std::memory_order_relaxed);
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    std::cerr << "hdown: Missing URL\n";
    PrintUsage();
  }

  if (argc > 2) {
    std::cerr << "To many arguments\n";
    PrintUsage();
    exit(1);
  }

  struct ::sigaction sig_action;
  sig_action.sa_handler = SigIntTermHandler;
  ::sigemptyset(&sig_action.sa_mask);
  sig_action.sa_flags = 0;
  ::sigaction(SIGINT,  &sig_action, nullptr);
  ::sigaction(SIGTERM, &sig_action, nullptr);

  HttpUrl url;
  if (!HttpUrl::Parse(argv[1], url)) {
    return 1;
  };
  
  std::cout << "Host: " << url.host << std::endl;
  std::cout << "Port: " << url.portnum << std::endl;
  std::cout << "Path: " << url.path << std::endl;

  if (!Download(url)) {
    return 1;
  }

  return 0;
}
