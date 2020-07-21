
#ifndef BRO_PLUGIN_CORELIGHT_GQUIC
#define BRO_PLUGIN_CORELIGHT_GQUIC

#include <plugin/Plugin.h>
#include "file_analysis/Component.h"

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

#endif
