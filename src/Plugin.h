
#pragma once

#include <plugin/Plugin.h>

namespace plugin {
namespace Corelight_GQUIC {

class Plugin : public ::plugin::Plugin
{
protected:
	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}
