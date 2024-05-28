#include <boost/algorithm/string.hpp>
#include <print>

int main() {
    std::string text = "Hello, World!";
    std::println("Original: {}", text);
    boost::to_upper(text);
    std::println("Uppercase: {}", text);
    return 0;
}