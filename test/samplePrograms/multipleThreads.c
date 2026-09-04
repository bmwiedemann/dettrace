#include <sys/types.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>


const int THREAD_COUNT = 10;

#define handle_error_en(en, msg) \
               do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

void* threadFunction(void* args){
  fflush(NULL);
  return NULL;
}

int main(){
  pthread_t handle[THREAD_COUNT];
  int tid[THREAD_COUNT];
  printf("Hello from parent\n");

  for(int i = 0; i < THREAD_COUNT; i++){
    tid[i] = i;
    // Do not overwrite the handle with the return value, join needs it.
    int rc = pthread_create(& handle[i], NULL, & threadFunction, (void*) & tid[i]);
    if(rc != 0){
      handle_error_en(rc, "pthread create\n");
    }
  }


  printf("Waiting for child to finish.\n");

  for(int i = 0; i < THREAD_COUNT; i++){
    pthread_join(handle[i], NULL);
  }


  printf("All done!\n");
  return 0;
}
