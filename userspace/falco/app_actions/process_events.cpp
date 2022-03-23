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

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "falco_utils.h"
#include "event_drops.h"
#ifndef MINIMAL_BUILD
#include "webserver.h"
#endif
#include "statsfilewriter.h"
#include "defined_app_actions.h"

namespace falco {
namespace app {

#ifndef MINIMAL_BUILD
// Read a jsonl file containing k8s audit events and pass each to the engine.
static void read_k8s_audit_trace_file(application &app, string &trace_filename)
{
	ifstream ifs(trace_filename);

	uint64_t line_num = 0;

	while(ifs)
	{
		string line, errstr;

		getline(ifs, line);
		line_num++;

		if(line == "")
		{
			continue;
		}

		if(!k8s_audit_handler::accept_data(app.state().engine, app.state().outputs, line, errstr))
		{
			falco_logger::log(LOG_ERR, "Could not read k8s audit event line #" + to_string(line_num) + ", \"" + line + "\": " + errstr + ", stopping");
			return;
		}
	}
}
#endif

//
// Event processing loop
//
static uint64_t do_inspect(application &app,
			   std::shared_ptr<falco_engine> engine,
			   std::shared_ptr<falco_outputs> outputs,
			   std::shared_ptr<sinsp> inspector,
			   std::string &event_source,
			   std::shared_ptr<falco_configuration> config,
			   syscall_evt_drop_mgr &sdropmgr,
			   uint64_t duration_to_tot_ns,
			   string &stats_filename,
			   uint64_t stats_interval,
			   bool all_events,
			   run_result &result)
{
	uint64_t num_evts = 0;
	int32_t rc;
	sinsp_evt* ev;
	StatsFileWriter writer;
	uint64_t duration_start = 0;
	uint32_t timeouts_since_last_success_or_msg = 0;

	sdropmgr.init(inspector,
		      outputs,
		      config->m_syscall_evt_drop_actions,
		      config->m_syscall_evt_drop_threshold,
		      config->m_syscall_evt_drop_rate,
		      config->m_syscall_evt_drop_max_burst,
		      config->m_syscall_evt_simulate_drops);

	if (stats_filename != "")
	{
		string errstr;

		if (!writer.init(inspector, stats_filename, stats_interval, errstr))
		{
			throw falco_exception(errstr);
		}
	}

	//
	// Loop through the events
	//
	while(1)
	{

		rc = inspector->next(&ev);

		writer.handle();

		if(app.state().reopen_outputs)
		{
			falco_logger::log(LOG_INFO, "SIGUSR1 received, reopening outputs...\n");
			outputs->reopen_outputs();
			app.state().reopen_outputs = false;
		}

		if(app.state().terminate)
		{
			falco_logger::log(LOG_INFO, "SIGINT received, exiting...\n");
			break;
		}
		else if (app.state().restart)
		{
			falco_logger::log(LOG_INFO, "SIGHUP received, restarting...\n");
			break;
		}
		else if(rc == SCAP_TIMEOUT)
		{
			if(unlikely(ev == nullptr))
			{
				timeouts_since_last_success_or_msg++;
				if(event_source == application::s_syscall_source &&
				   (timeouts_since_last_success_or_msg > config->m_syscall_evt_timeout_max_consecutives))
				{
					std::string rule = "Falco internal: timeouts notification";
					std::string msg = rule + ". " + std::to_string(config->m_syscall_evt_timeout_max_consecutives) + " consecutive timeouts without event.";
					std::string last_event_time_str = "none";
					if(duration_start > 0)
					{
						sinsp_utils::ts_to_string(duration_start, &last_event_time_str, false, true);
					}
					std::map<std::string, std::string> o = {
						{"last_event_time", last_event_time_str},
					};
					auto now = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
					outputs->handle_msg(now, falco_common::PRIORITY_DEBUG, msg, rule, o);
					// Reset the timeouts counter, Falco alerted
					timeouts_since_last_success_or_msg = 0;
				}
			}

			continue;
		}
		else if(rc == SCAP_EOF)
		{
			break;
		}
		else if(rc != SCAP_SUCCESS)
		{
			//
			// Event read error.
			//
			cerr << "rc = " << rc << endl;
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		// Reset the timeouts counter, Falco successfully got an event to process
		timeouts_since_last_success_or_msg = 0;
		if(duration_start == 0)
		{
			duration_start = ev->get_ts();
		}
		else if(duration_to_tot_ns > 0)
		{
			if(ev->get_ts() - duration_start >= duration_to_tot_ns)
			{
				break;
			}
		}

		if(!sdropmgr.process_event(inspector, ev))
		{
			result.success = false;
			result.errstr = "";
			result.proceed = false;
			break;
		}

		if(!ev->simple_consumer_consider() && !all_events)
		{
			continue;
		}

		// As the inspector has no filter at its level, all
		// events are returned here. Pass them to the falco
		// engine, which will match the event against the set
		// of rules. If a match is found, pass the event to
		// the outputs.
		unique_ptr<falco_engine::rule_result> res = engine->process_event(event_source, ev);
		if(res)
		{
			outputs->handle_event(res->evt, res->rule, res->source, res->priority_num, res->format, res->tags);
		}

		num_evts++;
	}

	return num_evts;
}

static run_result run_process_events(base_action &act)
{
	syscall_evt_drop_mgr sdropmgr;
	// Used for stats
	double duration;
	scap_stats cstats;

	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	duration = ((double)clock()) / CLOCKS_PER_SEC;

	if(!app.options().trace_filename.empty() && !app.state().trace_is_scap)
	{
#ifndef MINIMAL_BUILD
		read_k8s_audit_trace_file(app, app.options().trace_filename);
#endif
	}
	else
	{
		uint64_t num_evts;

		num_evts = do_inspect(app,
				      app.state().engine,
				      app.state().outputs,
				      app.state().inspector,
				      app.state().event_source,
				      app.state().config,
				      sdropmgr,
				      uint64_t(app.options().duration_to_tot*ONE_SECOND_IN_NS),
				      app.options().stats_filename,
				      app.options().stats_interval,
				      app.options().all_events,
				      ret);

		duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

		app.state().inspector->get_capture_stats(&cstats);

		if(app.options().verbose)
		{
			fprintf(stderr, "Driver Events:%" PRIu64 "\nDriver Drops:%" PRIu64 "\n",
				cstats.n_evts,
				cstats.n_drops);

			fprintf(stderr, "Elapsed time: %.3lf, Captured Events: %" PRIu64 ", %.2lf eps\n",
				duration,
				num_evts,
				num_evts / duration);
		}

	}

	// Honor -M also when using a trace file.
	// Since inspection stops as soon as all events have been consumed
	// just await the given duration is reached, if needed.
	if(!app.options().trace_filename.empty() && app.options().duration_to_tot>0)
	{
		std::this_thread::sleep_for(std::chrono::seconds(app.options().duration_to_tot));
	}

	app.state().inspector->close();
	app.state().engine->print_stats();
	sdropmgr.print_stats();

	return ret;
}

std::shared_ptr<base_action> act_process_events(application &app)
{
	std::list<std::string> prerequsites = {"open inspector"};

	return std::make_shared<action>("process_events",
					"run",
					base_action::s_no_prerequsites,
					run_process_events,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

