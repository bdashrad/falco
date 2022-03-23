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

static run_result run_init_inspector(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	app.state().inspector->set_buffer_format(app.options().event_buffer_format);

	// If required, set the CRI paths
	for (auto &p : app.options().cri_socket_paths)
	{
		if (!p.empty())
		{
			app.state().inspector->add_cri_socket_path(p);
		}
	}

	// Decide whether to do sync or async for CRI metadata fetch
	app.state().inspector->set_cri_async(!app.options().disable_cri_async);

	//
	// If required, set the snaplen
	//
	if(app.options().snaplen != 0)
	{
		app.state().inspector->set_snaplen(app.options().snaplen);
	}

	if(!app.options().all_events)
	{
		// Drop EF_DROP_SIMPLE_CONS kernel side
		app.state().inspector->set_simple_consumer();
		// Eventually, drop any EF_DROP_SIMPLE_CONS event
		// that reached userspace (there are some events that are not syscall-based
		// like signaldeliver, that have the EF_DROP_SIMPLE_CONS flag)
		app.state().inspector->set_drop_event_flags(EF_DROP_SIMPLE_CONS);
	}

	app.state().inspector->set_hostname_and_port_resolution_mode(false);

#ifndef MINIMAL_BUILD

		falco_logger::log(LOG_DEBUG, "Setting metadata download max size to " + to_string(app.state().config->m_metadata_download_max_mb) + " MB\n");
		falco_logger::log(LOG_DEBUG, "Setting metadata download chunk wait time to " + to_string(app.state().config->m_metadata_download_chunk_wait_us) + " μs\n");
		falco_logger::log(LOG_DEBUG, "Setting metadata download watch frequency to " + to_string(app.state().config->m_metadata_download_watch_freq_sec) + " seconds\n");
		app.state().inspector->set_metadata_download_params(app.state().config->m_metadata_download_max_mb * 1024 * 1024, app.state().config->m_metadata_download_chunk_wait_us, app.state().config->m_metadata_download_watch_freq_sec);

#endif

#ifndef MINIMAL_BUILD
	// Initializing k8s/mesos might have to move to open inspector
	//
	// Run k8s, if required
	//
	char *k8s_api_env = NULL;
	if(!app.options().k8s_api.empty() ||
	   (k8s_api_env = getenv("FALCO_K8S_API")))
	{
		// Create string pointers for some config vars
		// and pass to inspector. The inspector then
		// owns the pointers.
		std::string *k8s_api_ptr = new string((!app.options().k8s_api.empty() ? app.options().k8s_api : k8s_api_env));
		std::string *k8s_api_cert_ptr = new string(app.options().k8s_api_cert);
		std::string *k8s_node_name_ptr = new string(app.options().k8s_node_name);

		if(k8s_api_cert_ptr->empty())
		{
			if(char* k8s_cert_env = getenv("FALCO_K8S_API_CERT"))
			{
				*k8s_api_cert_ptr = k8s_cert_env;
			}
		}
		app.state().inspector->init_k8s_client(k8s_api_ptr, k8s_api_cert_ptr, k8s_node_name_ptr, app.options().verbose);
	}

	//
	// Run mesos, if required
	//
	if(!app.options().mesos_api.empty())
	{
		// Differs from init_k8s_client in that it
		// passes a pointer but the inspector does
		// *not* own it and does not use it after
		// init_mesos_client() returns.
		app.state().inspector->init_mesos_client(&(app.options().mesos_api), app.options().verbose);
	}
	else if(char* mesos_api_env = getenv("FALCO_MESOS_API"))
	{
		std::string mesos_api_copy = mesos_api_env;
		app.state().inspector->init_mesos_client(&mesos_api_copy, app.options().verbose);
	}

#endif
	return ret;
}

std::shared_ptr<base_action> act_init_inspector(application &app)
{
	std::list<std::string> prerequsites = {"load config"};

	return std::make_shared<action>("init inspector",
					"init",
					prerequsites,
					run_init_inspector,
					base_action::s_do_nothing,
					app);
}

}; // namespace application
}; // namespace falco

