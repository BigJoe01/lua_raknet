#include "lua_socket_descriptor.h"
#include "lua_raknet_helper.h"
#include <assert.h>

RAKSOCKETDESCRIPTOR* RAKSOCKETDESCRIPTOR_CHECK( lua_State* l, int iIndex )
{
	assert(lua_gettop(l) > 0);
#ifdef _DEBUG
	RAKSOCKETDESCRIPTOR* instance = (RAKSOCKETDESCRIPTOR*)luaL_checkudata(l, iIndex, DRaknetSocketDescriptorMeta);
	if ( instance != nullptr )
		luaL_error(l,"Invalid raknet socket descriptor meta at index : %d", iIndex);
	return instance;
#else
	return (RAKSOCKETDESCRIPTOR*)lua_touserdata(l, iIndex);
#endif
}

RAKSOCKETDESCRIPTOR* RAKSOCKETDESCRIPTOR_NEW( lua_State* l, int iMetaRef )
{
	RAKSOCKETDESCRIPTOR  Desc;
	RAKSOCKETDESCRIPTOR* Descriptor = (RAKSOCKETDESCRIPTOR*) lua_newuserdata(l, sizeof(RAKSOCKETDESCRIPTOR));
	memcpy(Descriptor, &Desc, sizeof(RAKSOCKETDESCRIPTOR)); // defaults
	lua_rawgeti(l,LUA_REGISTRYINDEX,iMetaRef);
	lua_setmetatable(l, -2);
	return Descriptor;
}

static int raknet_descriptor_gc( lua_State *l )
{
	return 0;
}

/// Add lua socket descriptor
// @param descriptor userdata
// @param table with params { block_socket = bool, socket_options = int, host = string, port = int, socket_family = af_inet, report_port_ps = int }
// @return boolean, success
static int socket_descriptor_add( lua_State *l )
{
	int iTop = lua_gettop(l);
	RAKSOCKETDESCRIPTOR* Descriptor = RAKSOCKETDESCRIPTOR_CHECK(l,1);
	if ( iTop < 2 || Descriptor->iUsedCount >= DMaxRaknetSocketDescriptor || lua_type(l,2) != LUA_TTABLE )
	{
		lua_pushboolean(l, false );
		return 1;
	}

	RakNet::SocketDescriptor* pDescriptor = &Descriptor->Descriptors[Descriptor->iUsedCount];
	pDescriptor->blockingSocket = RakNetHelper::GetFieldAsBool   (l, "block_socket", false);
	pDescriptor->extraSocketOptions = RakNetHelper::GetFieldAsInteger(l, "socket_options", 0);
	const char* sHost = RakNetHelper::GetFieldAsString (l, "host", "127.0.0.1");
	assert(strlen(sHost) < 32);
	strcpy_s(pDescriptor->hostAddress, 32, sHost);
	pDescriptor->port = RakNetHelper::GetFieldAsInteger(l, "port", 0);
	pDescriptor->socketFamily = RakNetHelper::GetFieldAsInteger(l, "socket_family", 2); // af_inet
	pDescriptor->remotePortRakNetWasStartedOn_PS3_PSP2 = RakNetHelper::GetFieldAsInteger(l, "remote_port_ps", 0);
	Descriptor->iUsedCount++;
	lua_pushboolean(l, true);
	return 1;
}

static const struct luaL_Reg raknet_socket_descriptor_meta [] = {
	{"add", socket_descriptor_add },
	{NULL, NULL}
};

int luaopen_socket_descriptor( lua_State *l )
{
	luaL_newmetatable(l, DRaknetSocketDescriptorMeta);
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_socket_descriptor_meta);
	lua_setfield(l, -2, "__index");
	lua_pushcfunction(l, raknet_descriptor_gc);
	lua_setfield(l, -2, "__gc");
	return 1;
}