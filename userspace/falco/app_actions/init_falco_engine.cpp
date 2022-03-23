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

void configure_output_format(application &app)
{
	std::string output_format;
	bool replace_container_info = false;

	if(app.options().print_additional == "c" || app.options().print_additional == "container")
	{
		output_format = "container=%container.name (id=%container.id)";
		replace_container_info = true;
	}
	else if(app.options().print_additional == "k" || app.options().print_additional == "kubernetes")
	{
		output_format = "k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name container=%container.id";
		replace_container_info = true;
	}
	else if(app.options().print_additional == "m" || app.options().print_additional == "mesos")
	{
		output_format = "task=%mesos.task.name container=%container.id";
		replace_container_info = true;
	}
	else if(!app.options().print_additional.empty())
	{
		output_format = app.options().print_additional;
		replace_container_info = false;
	}

	if(!output_format.empty())
	{
		app.state().engine->set_extra(output_format, replace_container_info);
	}
}

static run_result run_init_falco_engine(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	configure_output_format(app);

	// Create "factories" that can create filters/formatters for
	// syscalls and k8s audit events.

	// libs requires raw pointer, we should modify libs to use reference/shared_ptr
	std::shared_ptr<gen_event_filter_factory> syscall_filter_factory(new sinsp_filter_factory(app.state().inspector.get()));
	std::shared_ptr<gen_event_filter_factory> k8s_audit_filter_factory(new json_event_filter_factory());

	// libs requires raw pointer, we should modify libs to use reference/shared_ptr
	std::shared_ptr<gen_event_formatter_factory> syscall_formatter_factory(new sinsp_evt_formatter_factory(app.state().inspector.get()));
	std::shared_ptr<gen_event_formatter_factory> k8s_audit_formatter_factory(new json_event_formatter_factory(k8s_audit_filter_factory));

	app.state().engine->add_source(application::s_syscall_source, syscall_filter_factory, syscall_formatter_factory);
	app.state().engine->add_source(application::s_k8s_audit_source, k8s_audit_filter_factory, k8s_audit_formatter_factory);

	if(app.state().config->m_json_output)
	{
		syscall_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
		k8s_audit_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
	}

	for(const auto &src : app.options().disable_sources)
	{
		app.state().enabled_sources.erase(src);
	}

	// XXX/mstemm technically this isn't right, you could disable syscall *and* k8s_audit and configure a plugin.
	if(app.state().enabled_sources.empty())
	{
		throw std::invalid_argument("The event source \"syscall\" and \"k8s_audit\" can not be disabled together");
	}

	app.state().engine->set_min_priority(app.state().config->m_min_priority);

	return ret;
}

std::shared_ptr<base_action> act_init_falco_engine(application &app)
{
	std::list<std::string> prerequsites = {"init inspector", "load config"};

	return std::make_shared<action>("init falco engine",
					"init",
					prerequsites,
					run_init_falco_engine,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

