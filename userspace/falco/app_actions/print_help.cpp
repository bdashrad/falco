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

static run_result run_print_help(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	if(app.options().help)
	{
		printf("%s", app.options().usage().c_str());
		ret.proceed = false;
	}

	return ret;
}

std::shared_ptr<base_action> act_print_help(application &app)
{
	return std::make_shared<action>("print help",
					"easyopts",
					base_action::s_no_prerequsites,
					run_print_help,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

