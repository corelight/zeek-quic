
#include "Plugin.h"
#include "GQUIC.h"

#include <plugin/Plugin.h>
#include "analyzer/Component.h"

namespace plugin { namespace Corelight_GQUIC { Plugin plugin; } }

using namespace plugin::Corelight_GQUIC;

plugin::Configuration Plugin::Configure()
	{
	auto c = new ::analyzer::Component("GQUIC",
	    ::analyzer::gquic::GQUIC_Analyzer::Instantiate);
	AddComponent(c);
	plugin::Configuration config;
	config.name = "Corelight::GQUIC";
	config.description = "Google QUIC (QGUIC) protocol analyzer";
	config.version.major = 0;
	config.version.minor = 4;
	return config;
	}
