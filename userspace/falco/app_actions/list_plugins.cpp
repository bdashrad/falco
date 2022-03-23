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

namespace falco {
namespace app {

static run_result run_list_plugins(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	if(app.options().list_plugins)
	{
		std::ostringstream os;

		for(auto &info : app.state().plugin_infos)
		{
			os << "Name: " << info.name << std::endl;
			os << "Description: " << info.description << std::endl;
			os << "Contact: " << info.contact << std::endl;
			os << "Version: " << info.plugin_version.as_string() << std::endl;

			if(info.type == TYPE_SOURCE_PLUGIN)
			{
				os << "Type: source plugin" << std::endl;
				os << "ID: " << info.id << std::endl;
			}
			else
			{
				os << "Type: extractor plugin" << std::endl;
			}
			os << std::endl;
		}

		printf("%lu Plugins Loaded:\n\n%s\n", app.state().plugin_infos.size(), os.str().c_str());
		ret.proceed = false;
	}

	return ret;
}

std::shared_ptr<base_action> act_list_plugins(application &app)
{
	std::list<std::string> prerequsites = {"load plugins"};

	return std::make_shared<action>("list plugins",
					"init",
					prerequsites,
					run_list_plugins,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

