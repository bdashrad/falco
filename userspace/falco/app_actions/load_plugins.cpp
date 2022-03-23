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

static run_result run_load_plugins(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	// Factories that can create filters/formatters for
	// the (single) source supported by the (single) input plugin.
	// libs requires raw pointer, we should modify libs to use reference/shared_ptr
	std::shared_ptr<gen_event_filter_factory> plugin_filter_factory(new sinsp_filter_factory(app.state().inspector.get(), app.state().plugin_filter_checks));
	std::shared_ptr<gen_event_formatter_factory> plugin_formatter_factory(new sinsp_evt_formatter_factory(app.state().inspector.get(), app.state().plugin_filter_checks));

	if(app.state().config->m_json_output)
	{
		plugin_formatter_factory->set_output_format(gen_event_formatter::OF_JSON);
	}

	std::shared_ptr<sinsp_plugin> input_plugin;
	std::list<std::shared_ptr<sinsp_plugin>> extractor_plugins;
	for(auto &p : app.state().config->m_plugins)
	{
		std::shared_ptr<sinsp_plugin> plugin;
#ifdef MUSL_OPTIMIZED
		ret.success = ret.proceed = false;
		ret.errstr = "Can not load/use plugins with musl optimized build";
		return ret;
#else
		falco_logger::log(LOG_INFO, "Loading plugin (" + p.m_name + ") from file " + p.m_library_path + "\n");

		// libs requires raw pointer, we should modify libs to use reference/shared_ptr
		plugin = sinsp_plugin::register_plugin(app.state().inspector.get(),
						       p.m_library_path,
						       (p.m_init_config.empty() ? NULL : (char *)p.m_init_config.c_str()),
						       app.state().plugin_filter_checks);
#endif

		if(plugin->type() == TYPE_SOURCE_PLUGIN)
		{
			sinsp_source_plugin *splugin = static_cast<sinsp_source_plugin *>(plugin.get());

			if(input_plugin)
			{
				ret.success = false;
				ret.errstr = string("Can not load multiple source plugins. ") + input_plugin->name() + " already loaded";
				ret.proceed = false;
				return ret;
			}

			input_plugin = plugin;
			app.state().event_source = splugin->event_source();

			app.state().inspector->set_input_plugin(p.m_name);
			if(!p.m_open_params.empty())
			{
				app.state().inspector->set_input_plugin_open_params(p.m_open_params.c_str());
			}

			app.state().engine->add_source(app.state().event_source, plugin_filter_factory, plugin_formatter_factory);

		} else {
			extractor_plugins.push_back(plugin);
		}
	}

	// Ensure that extractor plugins are compatible with the event source.
	// Also, ensure that extractor plugins don't have overlapping compatible event sources.
	std::set<std::string> compat_sources_seen;
	for(auto plugin : extractor_plugins)
	{
		// If the extractor plugin names compatible sources,
		// ensure that the input plugin's source is in the list
		// of compatible sources.
		sinsp_extractor_plugin *eplugin = static_cast<sinsp_extractor_plugin *>(plugin.get());
		const std::set<std::string> &compat_sources = eplugin->extract_event_sources();
		if(input_plugin &&
		   !compat_sources.empty())
		{
			if (compat_sources.find(app.state().event_source) == compat_sources.end())
			{
				ret.success = ret.proceed = false;
				ret.errstr = string("Extractor plugin not compatible with event source ") + app.state().event_source;
				return ret;
			}

			for(const auto &compat_source : compat_sources)
			{
				if(compat_sources_seen.find(compat_source) != compat_sources_seen.end())
				{
					ret.success = ret.proceed = false;
					ret.errstr = string("Extractor plugins have overlapping compatible event source ") + compat_source;
					return ret;
				}
				compat_sources_seen.insert(compat_source);
			}
		}
	}

	app.state().plugin_infos = sinsp_plugin::plugin_infos(app.state().inspector.get());

	return ret;
}

std::shared_ptr<base_action> act_load_plugins(application &app)
{
	std::list<std::string> prerequsites = {"init falco engine", "load config"};

	return std::make_shared<action>("load plugins",
					"init",
					prerequsites,
					run_load_plugins,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

