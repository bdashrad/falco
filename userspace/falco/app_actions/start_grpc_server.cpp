/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "defined_app_actions.h"

#ifndef MINIMAL_BUILD

#include "grpc_server.h"

namespace falco {
namespace app {

static run_result run_start_grpc_server(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	// gRPC server
	if(app.state().config->m_grpc_enabled)
	{
		falco_logger::log(LOG_INFO, "gRPC server threadiness equals to " + to_string(app.state().config->m_grpc_threadiness) + "\n");
		// TODO(fntlnz,leodido): when we want to spawn multiple threads we need to have a queue per thread, or implement
		// different queuing mechanisms, round robin, fanout? What we want to achieve?
		app.state().grpc_server.init(
			app.state().config->m_grpc_bind_address,
			app.state().config->m_grpc_threadiness,
			app.state().config->m_grpc_private_key,
			app.state().config->m_grpc_cert_chain,
			app.state().config->m_grpc_root_certs,
			app.state().config->m_log_level
			);
		app.state().grpc_server_thread = std::thread([&app] {
			app.state().grpc_server.run();
		});
	}
	return ret;
}

static bool deinit_start_grpc_server(base_action &act, std::string &errstr)
{
	application &app = ((action &) act).app;

	if(app.state().grpc_server_thread.joinable())
	{
		app.state().grpc_server.shutdown();
		app.state().grpc_server_thread.join();
	}

	return true;
}

std::shared_ptr<base_action> act_start_grpc_server(application &app)
{
	std::list<std::string> prerequsites = {"init outputs"};

	return std::make_shared<action>("start grpc server",
					"init",
					prerequsites,
					run_start_grpc_server,
					deinit_start_grpc_server,
					app);
}

}; // namespace application
}; // namespace falco

#endif
