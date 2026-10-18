#pragma once
#include "http_frame.h"

namespace server {

void HandleOpRoute(const http::Request &req, http::Response &res,
                   bool &handled);

}
