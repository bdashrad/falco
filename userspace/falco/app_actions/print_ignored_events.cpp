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

static void print_all_ignored_events(application &app)
{
	sinsp_evttables* einfo = app.state().inspector->get_event_info_tables();
	const struct ppm_event_info* etable = einfo->m_event_info;
	const struct ppm_syscall_desc* stable = einfo->m_syscall_info_table;

	std::set<string> ignored_event_names;
	for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
	{
		if(!sinsp::simple_consumer_consider_evtnum(j))
		{
			std::string name = etable[j].name;
			// Ignore event names NA*
			if(name.find("NA") != 0)
			{
				ignored_event_names.insert(name);
			}
		}
	}

	for(uint32_t j = 0; j < PPM_SC_MAX; j++)
	{
		if(!sinsp::simple_consumer_consider_syscallid(j))
		{
			std::string name = stable[j].name;
			// Ignore event names NA*
			if(name.find("NA") != 0)
			{
				ignored_event_names.insert(name);
			}
		}
	}

	printf("Ignored Event(s):");
	for(auto it : ignored_event_names)
	{
		printf(" %s", it.c_str());
	}
	printf("\n");
}

static run_result run_print_ignored_events(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	if(app.options().print_ignored_events)
	{
		print_all_ignored_events(app);
		ret.proceed = false;
	}

	return ret;
}

std::shared_ptr<base_action> act_print_ignored_events(application &app)
{
	std::list<std::string> prerequsites = {"init inspector"};

	return std::make_shared<action>("print ignored events",
					"init",
					prerequsites,
					run_print_ignored_events,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

