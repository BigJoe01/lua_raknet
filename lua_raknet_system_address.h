//----------------------------------------------------------
// Raknet lua bindigs
//----------------------------------------------------------
#pragma once
extern "C"
{
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include "RakNetTypes.h"

#define DRaknetSystemAddressMeta ":raknet_system_address:"

inline RakNet::SystemAddress* RAKSYSTEMADDRESS_CHECK( lua_State* l, int iIndex );
RakNet::SystemAddress* RAKSYSTEMADDRESS_NEW( lua_State* l, int iMetaRef, const char* sHost, int iPort );

int luaopen_system_address(lua_State *l);