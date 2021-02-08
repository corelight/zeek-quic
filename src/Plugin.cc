
#include "Plugin.h"
#include "GQUIC.h"

#include <zeek/plugin/Plugin.h>
#include <zeek/analyzer/Component.h>

namespace plugin { namespace Corelight_GQUIC { Plugin plugin; } }

using namespace plugin::Corelight_GQUIC;

zeek::plugin::Configuration Plugin::Configure()
	{
	auto c = new zeek::analyzer::Component("GQUIC",
	    ::analyzer::gquic::GQUIC_Analyzer::Instantiate);
	AddComponent(c);
  zeek::plugin::Configuration config;
	config.name = "Corelight::GQUIC";
	config.description = "Google QUIC (QGUIC) protocol analyzer";
	config.version.major = 0;
	config.version.minor = 4;
	return config;
	}
