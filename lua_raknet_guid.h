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

#define DRaknetGuidMeta ":raknet_guid:"

inline RakNet::RakNetGUID* RAKGUID_CHECK(lua_State* l, int iIndex);
RakNet::RakNetGUID* RAKGUID_NEW(lua_State* l, int iMetaRef, int id);

int luaopen_raknet_guid(lua_State *l);