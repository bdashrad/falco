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

static run_result run_load_config(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	if (app.options().conf_filename.size())
	{
		app.state().config->init(app.options().conf_filename, app.options().cmdline_config_options);
		falco_logger::set_time_format_iso_8601(app.state().config->m_time_format_iso_8601);

		// log after config init because config determines where logs go
		falco_logger::log(LOG_INFO, "Falco version " + std::string(FALCO_VERSION) + " (driver version " + std::string(DRIVER_VERSION) + ")\n");
		falco_logger::log(LOG_INFO, "Falco initialized with configuration file " + app.options().conf_filename + "\n");
	}
	else
	{
		ret.success = false;
		ret.proceed = false;

#ifndef BUILD_TYPE_RELEASE
		ret.errstr = std::string("You must create a config file at ")  + FALCO_SOURCE_CONF_FILE + ", " + FALCO_INSTALL_CONF_FILE + " or by passing -c";
#else
		ret.errstr = std::string("You must create a config file at ")  + FALCO_INSTALL_CONF_FILE + " or by passing -c";
#endif
	}

	app.state().config->m_buffered_outputs = !app.options().unbuffered_outputs;

	return ret;
}

std::shared_ptr<base_action> act_load_config(application &app)
{
	return std::make_shared<action>("load config",
					"init",
					base_action::s_no_prerequsites,
					run_load_config,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

