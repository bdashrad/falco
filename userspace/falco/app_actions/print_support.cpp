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

#include <sys/utsname.h>

#include "falco_engine_version.h"
#include "defined_app_actions.h"

namespace falco {
namespace app {

static std::string read_file(std::string &filename)
{
	std::ifstream t(filename);
	std::string str((std::istreambuf_iterator<char>(t)),
			std::istreambuf_iterator<char>());

	return str;
}

static run_result run_print_support(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	if(app.options().print_support)
	{
		nlohmann::json support;
		struct utsname sysinfo;
		std::string cmdline;

		if(uname(&sysinfo) != 0)
		{
			ret.success = false;
			ret.errstr = string("Could not uname() to find system info: ") + strerror(errno);
			ret.proceed = false;
			return ret;
		}

		support["version"] = FALCO_VERSION;
		support["system_info"]["sysname"] = sysinfo.sysname;
		support["system_info"]["nodename"] = sysinfo.nodename;
		support["system_info"]["release"] = sysinfo.release;
		support["system_info"]["version"] = sysinfo.version;
		support["system_info"]["machine"] = sysinfo.machine;
		support["cmdline"] = app.state().cmdline;
		support["engine_info"]["engine_version"] = FALCO_ENGINE_VERSION;
		support["config"] = read_file(app.options().conf_filename);
		support["rules_files"] = nlohmann::json::array();
		for(auto filename : app.state().config->m_rules_filenames)
		{
			nlohmann::json finfo;
			finfo["name"] = filename;
			nlohmann::json variant;
			variant["required_engine_version"] = app.state().required_engine_versions[filename];
			variant["content"] = read_file(filename);
			finfo["variants"].push_back(variant);
			support["rules_files"].push_back(finfo);
		}
		printf("%s\n", support.dump().c_str());
	}

	return ret;
}

std::shared_ptr<base_action> act_print_support(application &app)
{
	std::list<std::string> prerequsites = {"load rules files"};

	return std::make_shared<action>("print support",
					"init",
					prerequsites,
					run_print_support,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

