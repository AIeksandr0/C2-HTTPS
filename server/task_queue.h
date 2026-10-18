#pragma once
#include "shared/proto.h"
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <vector>


namespace server {

struct Task {
  uint32_t id = 0;
  proto::Op op = proto::Op::Task;
  std::vector<uint8_t> payload;
  bool delivered = false;
};

struct TaskResult {
  uint32_t id = 0;
  uint8_t op = 0;
  std::vector<uint8_t> payload;
};

class TaskQueue {
public:
  bool Enqueue(const std::string &sid, uint32_t id, proto::Op op,
               std::vector<uint8_t> payload);
  bool Dequeue(const std::string &sid, Task &out);
  void Confirm(const std::string &sid, uint32_t task_id);
  size_t Pending(const std::string &sid);
  void Drop(const std::string &sid);

  void StoreResult(const std::string &sid, uint32_t id, uint8_t op,
                   std::vector<uint8_t> payload);
  std::vector<TaskResult> TakeResults(const std::string &sid);

private:
  std::mutex mu_;
  std::map<std::string, std::deque<Task>> q_;
  std::map<std::string, std::deque<TaskResult>> results_;
  std::map<std::string, uint8_t> op_of_;
};

}