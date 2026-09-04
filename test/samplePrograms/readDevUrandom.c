#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(){
  size_t length = 100;
  char randomBuf[length];

  int fd = open("/dev/urandom", O_RDONLY);
  if(fd == -1){
    printf("Error: %s\n", strerror(errno));
  }

  read(fd, randomBuf, length);
  for(int i = 0; i < length; i++){
    printf("%d ", (signed char)randomBuf[i]); /* char is unsigned on arm, ppc, s390 */
  }
  printf("\n");
  return 0;
}
