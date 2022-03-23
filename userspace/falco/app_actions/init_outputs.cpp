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

#include <stdlib.h>
#include <unistd.h>

#include "defined_app_actions.h"

namespace falco {
namespace app {

static run_result run_init_outputs(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	// read hostname
	std::string hostname;
	if(char* env_hostname = getenv("FALCO_GRPC_HOSTNAME"))
	{
		hostname = env_hostname;
	}
	else
	{
		char c_hostname[256];
		int err = gethostname(c_hostname, 256);
		if(err != 0)
		{
			ret.success = false;
			ret.errstr = "Failed to get hostname";
			ret.proceed = false;
		}
		hostname = c_hostname;
	}

	app.state().outputs->init(app.state().engine,
				  app.state().config->m_json_output,
				  app.state().config->m_json_include_output_property,
				  app.state().config->m_json_include_tags_property,
				  app.state().config->m_output_timeout,
				  app.state().config->m_notifications_rate, app.state().config->m_notifications_max_burst,
				  app.state().config->m_buffered_outputs,
				  app.state().config->m_time_format_iso_8601,
				  hostname);

	for(auto output : app.state().config->m_outputs)
	{
		app.state().outputs->add_output(output);
	}

	return ret;
}

std::shared_ptr<base_action> act_init_outputs(application &app)
{
	std::list<std::string> prerequsites = {"load config", "init falco engine"};

	return std::make_shared<action>("init outputs",
					"init",
					prerequsites,
					run_init_outputs,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

