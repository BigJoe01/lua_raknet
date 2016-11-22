//----------------------------------------------------------
// Raknet lua helper
//----------------------------------------------------------
#pragma once
extern "C"
{
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}
#include "RakPeer.h"
#include "RelayPlugin.h"
#include "PluginInterface2.h"

#define DRaknetRelayMeta ":raknet_relay_meta:"
#define DRaknetRelayConst "raknet_relay"

struct RAKPEER;

RakNet::PluginInterface2* RAKPLUGIN_RELAY_NEW(lua_State *l, RAKPEER* Peer );
RakNet::RelayPlugin* RAKPLUGIN_RELAY_CHECK(lua_State *l, int iIndex );

int luaopen_raknet_relay(lua_State *l);
