#include "logger.hpp"
#include "systemCallList.hpp"
#include "dettraceSystemCall.hpp"
#include "util.hpp"
#include "state.hpp"
#include "ptracer.hpp"
#include "scheduler.hpp"

#include <queue>
#include <set>

scheduler::scheduler(pid_t startingPid, logger& log):
  log(log),
  startingPid(startingPid){
  parallelProcesses.insert(startingPid);
}

pid_t scheduler::getStartingPid(){
  return startingPid;
}

bool scheduler::isInParallel(pid_t process){
  const bool parallel = parallelProcesses.find(process) != parallelProcesses.end();
  return parallel;
}

bool scheduler::isFinished(pid_t process){
  const bool finished = finishedProcesses.find(process) != finishedProcesses.end();
  return finished;
}

bool scheduler::emptyScheduler(){
  return runnableQueue.empty() && blockedQueue.empty() && parallelProcesses.empty();
}

int scheduler::numberBlocked(){
  return blockedQueue.size();
}

int scheduler::numberRunnable(){
  return runnableQueue.size();
}

pid_t scheduler::getNextRunnable(){
  if(!runnableQueue.empty()){
    return runnableQueue.front();
  }
  return -1;
}

pid_t scheduler::getNextBlocked(){
  if(!blockedQueue.empty()){
    return blockedQueue.front();
  }
  return -1;
}

void scheduler::resumeRetry(pid_t pid){
  if(blockedQueue.front() != pid){
    throw runtime_error("trying to resume retry with wrong pid");
  }
  blockedQueue.pop();
  blockedQueue.push(pid);
}


bool scheduler::isAlive(pid_t pid){
  bool found = false;
  if(parallelProcesses.find(pid) != parallelProcesses.end()){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] is in parallelProcesses\n");
    log.writeToLog(Importance::info, msg, pid);
    found = true;
    return found;
  }
  queue<pid_t> blockedTemp;
  queue<pid_t> runnableTemp;

  while(!blockedQueue.empty()){
    pid_t frontPid = blockedQueue.front();
    blockedQueue.pop();
    if(frontPid == pid){
      auto msg = 
        log.makeTextColored(Color::blue, "Process [%d] is in blockedQueue\n");
      log.writeToLog(Importance::info, msg, pid);
      found = true;
      break;
    }else{
      blockedQueue.pop();
      blockedTemp.push(frontPid);
    }
  }

  while(!blockedQueue.empty()){
    pid_t frontPid = blockedQueue.front();
    blockedTemp.push(frontPid);
    blockedQueue.pop();
  }
  blockedQueue = blockedTemp;
  
  while(!runnableQueue.empty()){
    pid_t frontPid = runnableQueue.front();
    if(frontPid == pid){
      auto msg = 
        log.makeTextColored(Color::blue, "Process [%d] is in runnableQueue\n");
      log.writeToLog(Importance::info, msg, pid);
      found = true;
      break;
    }else{
      runnableTemp.push(frontPid);
      runnableQueue.pop();
    }
  }

  while(!runnableQueue.empty()){
    pid_t frontPid = runnableQueue.front();
    runnableTemp.push(frontPid);
    runnableQueue.pop();
  }
  runnableQueue = runnableTemp;
  return found;
}

void scheduler::removeFromScheduler(pid_t pid){
  bool found = false;
  if(parallelProcesses.find(pid) != parallelProcesses.end()){
    auto msg = 
      log.makeTextColored(Color::blue, "Process [%d] removed from parallelProcesses\n");
    log.writeToLog(Importance::info, msg, pid);
    parallelProcesses.erase(pid);
    found = true;
  }
  queue<pid_t> blockedTemp;
  queue<pid_t> runnableTemp;

  // If the process was not in parallelProcesses, have to check the 
  // blockedQueue and the runnableQueue. Throw an error if we don't find it.
  while(!blockedQueue.empty()){
    pid_t frontPid = blockedQueue.front();
    blockedQueue.pop();
    if(frontPid == pid){
      auto msg = 
        log.makeTextColored(Color::blue, "Process [%d] removed from blockedQueue\n");
      log.writeToLog(Importance::info, msg, pid);
      break;
    }else{
      blockedTemp.push(frontPid);
    }
  }

  while(!blockedQueue.empty()){
    pid_t frontPid = blockedQueue.front();
    blockedTemp.push(frontPid);
    blockedQueue.pop();
  }
  blockedQueue = blockedTemp;

  // We may need to look at the runnableQueue as well.    
  while(!runnableQueue.empty()){
    pid_t frontPid = runnableQueue.front();
    runnableQueue.pop();
    if(frontPid == pid){
      auto msg = 
        log.makeTextColored(Color::blue, "Process [%d] removed from runnableQueue\n");
      log.writeToLog(Importance::info, msg, pid);
      break;
    }else{
      runnableTemp.push(frontPid);
    }
  }

  while(!runnableQueue.empty()){
    pid_t frontPid = runnableQueue.front();
    runnableTemp.push(frontPid);
    runnableQueue.pop();
  }
  runnableQueue = runnableTemp;

  finishedProcesses.insert(pid);
}

void scheduler::preemptSyscall(pid_t pid){
  pid_t frontPid = runnableQueue.front();
  if(frontPid != pid){
    throw runtime_error("trying to preempt wrong pid!");
  }
  runnableQueue.pop();
  blockedQueue.push(pid); 
}

void scheduler::resumeParallel(pid_t pid){
  pid_t frontBlocked = blockedQueue.front();
  pid_t frontRunnable = runnableQueue.front();
  if(frontBlocked == pid){
    blockedQueue.pop();
  }else if(frontRunnable == pid){
    runnableQueue.pop();
  }else{
    throw runtime_error("trying to resume pid that is not front of either queue");
  }
  parallelProcesses.insert(pid); 
}

void scheduler::addToParallelSet(pid_t newProcess){
  parallelProcesses.insert(newProcess); 
}

void scheduler::addToRunnableQueue(pid_t pid){
  // Remove the pid from parallelProcesses.
  // Push it to the runnableQueue.
  parallelProcesses.erase(pid);
  runnableQueue.push(pid);
}

void scheduler::printProcesses(){
  log.writeToLog(Importance::extra, "Printing parallelProcesses set\n");
  // Print the parallelProcesses set.
  for(auto pid : parallelProcesses){ 
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
  }

  log.writeToLog(Importance::extra, "Printing runnableQueue\n");
  // Print the runnableQueue. Their ordering is their current priority. 
  queue<pid_t> runnableCopy = runnableQueue;  
  while(!runnableCopy.empty()){
    pid_t pid = runnableCopy.front();
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
    runnableCopy.pop();
  }


  log.writeToLog(Importance::extra, "Printing blockedQueue\n");
  // Print the blockedQueue. Their ordering is their current priority. 
  queue<pid_t> blockedCopy = blockedQueue;  
  while(!blockedCopy.empty()){
    pid_t pid = blockedCopy.front();
    log.writeToLog(Importance::extra, "Pid [%d]\n", pid);
    blockedCopy.pop();
  }
  return;
}
