#include "task_queue.h"

namespace server {

bool TaskQueue::Enqueue(const std::string &sid, uint32_t id, proto::Op op,
                        std::vector<uint8_t> payload) {
  std::lock_guard<std::mutex> lk(mu_);
  Task t;
  t.id = id;
  t.op = op;
  t.payload = std::move(payload);
  op_of_[sid] = uint8_t(op);
  q_[sid].push_back(std::move(t));
  return true;
}

bool TaskQueue::Dequeue(const std::string &sid, Task &out) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = q_.find(sid);
  if (it == q_.end())
    return false;
  for (auto &t : it->second) {
    if (!t.delivered) {
      t.delivered = true;
      out = t;
      return true;
    }
  }
  return false;
}

void TaskQueue::Confirm(const std::string &sid, uint32_t task_id) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = q_.find(sid);
  if (it == q_.end())
    return;
  auto &dq = it->second;
  for (auto t = dq.begin(); t != dq.end(); ++t) {
    if (t->id == task_id) {
      dq.erase(t);
      return;
    }
  }
}

size_t TaskQueue::Pending(const std::string &sid) {
  std::lock_guard<std::mutex> lk(mu_);
  auto it = q_.find(sid);
  return it == q_.end() ? 0 : it->second.size();
}

void TaskQueue::Drop(const std::string &sid) {
  std::lock_guard<std::mutex> lk(mu_);
  q_.erase(sid);
  results_.erase(sid);
  op_of_.erase(sid);
}

void TaskQueue::StoreResult(const std::string &sid, uint32_t id, uint8_t op,
                            std::vector<uint8_t> payload) {
  std::lock_guard<std::mutex> lk(mu_);
  auto &dq = results_[sid];
  dq.push_back(TaskResult{id, op, std::move(payload)});
  while (dq.size() > 256)
    dq.pop_front();
}

std::vector<TaskResult> TaskQueue::TakeResults(const std::string &sid) {
  std::lock_guard<std::mutex> lk(mu_);
  std::vector<TaskResult> out;
  auto it = results_.find(sid);
  if (it == results_.end())
    return out;
  out.reserve(it->second.size());
  for (auto &r : it->second)
    out.push_back(std::move(r));
  results_.erase(it);
  return out;
}

}