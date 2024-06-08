#include <bitset>
#include <boost/asio.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/program_options.hpp>
#include <boost/stacktrace.hpp>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>

namespace progOpt = boost::program_options;
namespace asIp = boost::asio::ip;

template <int T>
class Bitset {
 private:
  std::bitset<T> bits;

 public:
  bool operator<(const Bitset<T> &b) const;
  void set(size_t pos);
};

using keyType = Bitset<256>;
using valueType = int;

extern asIp::address DHT_ADDR;
extern u_short DHT_PORT;
extern u_short DHT_PUT;
extern u_short DHT_GET;
extern u_short DHT_SUCCESS;
extern u_short DHT_FAILURE;

extern std::map<keyType, valueType> local_storage;
extern std::mutex storage_lock;

std::optional<valueType> get_from_storage(keyType key);
void save_to_storage(keyType key, valueType val);

bool send_dht_success();
bool send_dht_failure();

void validate(boost::any &v, const std::vector<std::string> &values,
              asIp::address *, int);
int main(int argc, char const *argv[]);

