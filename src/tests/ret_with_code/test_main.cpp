// Test runner for optimized lifted code
// Calls the lifted test() function and returns its result as exit code

extern "C" int test();

int main() {
  return test();
}
