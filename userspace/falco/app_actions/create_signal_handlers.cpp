/*
Copyright (C) 2020 The Falco Authors.

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

#include <functional>

#include <string.h>
#include <signal.h>

#include "defined_app_actions.h"

namespace falco {
namespace app {

// This is initially set to a dummy application. When
// run_create_signal_handlers is called, it will be rebound to the
// provided application, and in deinit it will be rebound back to the
// dummy application.
//
// deinit() also unregisters the signal handlers.

static application dummy;
static std::reference_wrapper<application> s_app = dummy;

static void signal_callback(int signal)
{
	s_app.get().state().terminate = true;
}

static void reopen_outputs(int signal)
{
	s_app.get().state().reopen_outputs = true;
}

static void restart_falco(int signal)
{
	s_app.get().state().restart = true;
}

static bool create_handler(int sig, void (*func)(int), run_result &ret)
{
	if(signal(sig, func) == SIG_ERR)
	{
		char errbuf[1024];

		if (strerror_r(errno, errbuf, sizeof(errbuf)) != 0)
		{
			snprintf(errbuf, sizeof(errbuf)-1, "Errno %d", errno);
		}

		ret.success = false;
		ret.errstr = std::string("Could not create signal handler for ") +
			   strsignal(sig) +
			   ": " +
			   errbuf;

		ret.proceed = false;
	}

	return ret.success;
}

static run_result run_create_signal_handlers(base_action &act)
{
	run_result ret = {true, "", true};
	application &app = ((action &) act).app;

	s_app = app;

	if(! create_handler(SIGINT, signal_callback, ret) ||
	   ! create_handler(SIGTERM, signal_callback, ret) ||
	   ! create_handler(SIGUSR1, reopen_outputs, ret) ||
	   ! create_handler(SIGHUP, restart_falco, ret))
	{
		return ret;
	}

	return ret;
}

bool deinit_create_signal_handlers(base_action &act, std::string &errstr)
{
	run_result ret = {true, "", true};

	if(! create_handler(SIGINT, SIG_DFL, ret) ||
	   ! create_handler(SIGTERM, SIG_DFL, ret) ||
	   ! create_handler(SIGUSR1, SIG_DFL, ret) ||
	   ! create_handler(SIGHUP, SIG_DFL, ret))
	{
		errstr = ret.errstr;
		return false;
	}

	s_app = dummy;

	return true;
}

std::shared_ptr<base_action> act_create_signal_handlers(application &app)
{
	return std::make_shared<action>("create signal handlers",
					"init",
					base_action::s_no_prerequsites,
					run_create_signal_handlers,
					deinit_create_signal_handlers,
					app);
}

}; // namespace app
}; // namespace falco
