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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "defined_app_actions.h"

namespace falco {
namespace app {

typedef std::function<void(std::shared_ptr<sinsp> inspector)> open_t;

static run_result run_open_inspector(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	if(app.options().trace_filename.size())
	{
		// Try to open the trace file as a
		// capture file first.
		try {
			app.state().inspector->open(app.options().trace_filename);
			falco_logger::log(LOG_INFO, "Reading system call events from file: " + app.options().trace_filename + "\n");
		}
		catch(sinsp_exception &e)
		{
			falco_logger::log(LOG_DEBUG, "Could not read trace file \"" + app.options().trace_filename + "\": " + string(e.what()));
			app.state().trace_is_scap=false;
		}

		if(!app.state().trace_is_scap)
		{
#ifdef MINIMAL_BUILD
			ret.success = false;
			ret.errstr = "Cannot use k8s audit events trace file with a minimal Falco build";
			ret.proceed = false;
			return ret;
#else
			try {
				string line;
				nlohmann::json j;

				// Note we only temporarily open the file here.
				// The read file read loop will be later.
				ifstream ifs(app.options().trace_filename);
				getline(ifs, line);
				j = nlohmann::json::parse(line);

				falco_logger::log(LOG_INFO, "Reading k8s audit events from file: " + app.options().trace_filename + "\n");
			}
			catch (nlohmann::json::parse_error& e)
			{
				ret.success = false;
				ret.errstr = std::string("Trace filename ") + app.options().trace_filename + " not recognized as system call events or k8s audit events";
				ret.proceed = false;
				return ret;

			}
			catch (exception &e)
			{
				ret.success = false;
				ret.errstr = std::string("Could not open trace filename ") + app.options().trace_filename + " for reading: " + e.what();
				ret.proceed = false;
				return ret;
			}
#endif
		}
	}
	else
	{
		open_t open_cb = [&app](std::shared_ptr<sinsp> inspector)
			{
				if(app.options().userspace)
				{
					// open_udig() is the underlying method used in the capture code to parse userspace events from the kernel.
					//
					// Falco uses a ptrace(2) based userspace implementation.
					// Regardless of the implementation, the underlying method remains the same.
					inspector->open_udig();
					return;
				}
				inspector->open();
			};
		open_t open_nodriver_cb = [](std::shared_ptr<sinsp> inspector) {
			inspector->open_nodriver();
		};
		open_t open_f;

		// Default mode: both event sources enabled
		if (app.state().enabled_sources.find(application::s_syscall_source) != app.state().enabled_sources.end() &&
		    app.state().enabled_sources.find(application::s_k8s_audit_source) != app.state().enabled_sources.end())
		{
			open_f = open_cb;
		}
		if (app.state().enabled_sources.find(application::s_syscall_source) == app.state().enabled_sources.end())
		{
			open_f = open_nodriver_cb;
		}
		if (app.state().enabled_sources.find(application::s_k8s_audit_source) == app.state().enabled_sources.end())
		{
			open_f = open_cb;
		}

		try
		{
			open_f(app.state().inspector);
		}
		catch(sinsp_exception &e)
		{
			// If syscall input source is enabled and not through userspace instrumentation
			if (app.state().enabled_sources.find(application::s_syscall_source) != app.state().enabled_sources.end() && !app.options().userspace)
			{
				// Try to insert the Falco kernel module
				if(system("modprobe " DRIVER_NAME " > /dev/null 2> /dev/null"))
				{
					falco_logger::log(LOG_ERR, "Unable to load the driver.\n");
				}
				open_f(app.state().inspector);
			}
			else
			{
				ret.success = false;
				ret.errstr = e.what();
				ret.proceed = false;
				return ret;
			}
		}
	}

	// This must be done after the open
	if(!app.options().all_events)
	{
		app.state().inspector->start_dropping_mode(1);
	}

	return ret;
}

std::shared_ptr<base_action> act_open_inspector(application &app)
{
	std::list<std::string> prerequsites = {"daemonize"};

	return std::make_shared<action>("open inspector",
					"run",
					prerequsites,
					run_open_inspector,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

