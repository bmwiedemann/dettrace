// Regression test for --timeoutSeconds: the SIGALRM handler in the tracer
// must end the run with a message and exit status 1. It used to throw an
// exception from signal context.
int main(void) {
  for (;;) {
  }
  return 0;
}
