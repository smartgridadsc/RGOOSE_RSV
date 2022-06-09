#include <sys/socket.h>
#include <unistd.h>

class UdpSock {
  public:
    UdpSock() {
      m_sd = socket(AF_INET, SOCK_DGRAM, 0);
    }
    ~UdpSock() {
      // make sure the socket resource doesn't leak
      if (isGood())
        close(m_sd);
    }
    // Don't need the other default operations
    UdpSock(const UdpSock&) = delete;
    UdpSock& operator=(const UdpSock&) = delete;
    UdpSock(UdpSock&&) = delete;
    UdpSock& operator=(UdpSock&&) = delete;

    int operator()() const {
      return m_sd;
    }

    bool isGood() const {
      return m_sd >= 0;
    }
  private:
    int m_sd = -1;
};
