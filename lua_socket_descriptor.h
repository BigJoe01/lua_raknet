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

#define DMaxRaknetSocketDescriptor 5
#define DRaknetSocketDescriptorMeta ":raknet_socket_descriptor:"

struct RAKSOCKETDESCRIPTOR
{
	RakNet::SocketDescriptor Descriptors[DMaxRaknetSocketDescriptor];
	int iUsedCount;
};

inline RAKSOCKETDESCRIPTOR* RAKSOCKETDESCRIPTOR_CHECK( lua_State* l, int iIndex );
RAKSOCKETDESCRIPTOR* RAKSOCKETDESCRIPTOR_NEW( lua_State* l, int iMetaRef );

int luaopen_socket_descriptor(lua_State *l);