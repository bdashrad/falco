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

static run_result run_list_fields(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	if(app.options().list_fields)
	{
		if(app.options().list_source_fields != "" &&
		   !app.state().engine->is_source_valid(app.options().list_source_fields))
		{
			ret.success = false;
			ret.errstr = "Value for --list must be a valid source type";
			ret.proceed = false;
			return ret;
		}
		app.state().engine->list_fields(app.options().list_source_fields, app.options().verbose, app.options().names_only, app.options().markdown);

		ret.proceed = false;
	}

	return ret;
}

std::shared_ptr<base_action> act_list_fields(application &app)
{
	std::list<std::string> prerequsites = {"load plugins"};

	return std::make_shared<action>("list fields",
					"init",
					prerequsites,
					run_list_fields,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

