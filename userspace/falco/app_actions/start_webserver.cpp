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

#include "webserver.h"

namespace falco {
namespace app {

static run_result run_start_webserver(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	if(app.options().trace_filename.empty() && app.state().config->m_webserver_enabled && app.state().enabled_sources.find(application::s_k8s_audit_source) != app.state().enabled_sources.end())
	{
		std::string ssl_option = (app.state().config->m_webserver_ssl_enabled ? " (SSL)" : "");
		falco_logger::log(LOG_INFO, "Starting internal webserver, listening on port " + to_string(app.state().config->m_webserver_listen_port) + ssl_option + "\n");
		app.state().webserver.init(app.state().config, app.state().engine, app.state().outputs);
		app.state().webserver.start();
	}

	return ret;
}

static bool deinit_start_webserver(base_action &act, std::string &errstr)
{
	application &app = ((action &) act).app;

	app.state().webserver.stop();

	return true;
}

std::shared_ptr<base_action> act_start_webserver(application &app)
{
	std::list<std::string> prerequsites = {"init outputs"};

	return std::make_shared<action>("start webserver",
					"init",
					prerequsites,
					run_start_webserver,
					deinit_start_webserver,
					app);
}

}; // namespace application
}; // namespace falco

#endif
