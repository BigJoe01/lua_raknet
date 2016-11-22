#include "lua_raknet_system_address.h"
#include "lua_raknet_helper.h"
#include <assert.h>

#pragma warning( disable : 4800 )

RakNet::SystemAddress* RAKSYSTEMADDRESS_CHECK( lua_State* l, int iIndex )
{
#ifdef _DEBUG
	assert(lua_gettop(l) > 0);
	RakNet::SystemAddress* instance = (RakNet::SystemAddress*)luaL_checkudata(l, iIndex, DRaknetSystemAddressMeta);
	if (!instance)
		luaL_error(l,"Invalid raknet system address meta at index : %d", iIndex);
	assert(((RakNet::NetObjectType*)instance)->ucType == RAK_MAGIC_SYSTEM_ADDR);
	return instance;
#else
	RakNet::SystemAddress* instance = (RakNet::SystemAddress*)lua_touserdata(l, iIndex);
	return instance;
#endif
}

RakNet::SystemAddress* RAKSYSTEMADDRESS_NEW( lua_State* l, int iMetaRef, const char* sHost, int iPort )
{
	RakNet::SystemAddress* pSystemAddress = (RakNet::SystemAddress*) lua_newuserdata(l, sizeof(RakNet::SystemAddress));
	if ( sHost && iPort > 0 )
		*pSystemAddress = RakNet::SystemAddress( sHost, iPort );
	else if ( sHost && iPort == 0 )
		*pSystemAddress = RakNet::SystemAddress( sHost );
	else
		*pSystemAddress = RakNet::UNASSIGNED_SYSTEM_ADDRESS;
	lua_rawgeti(l,LUA_REGISTRYINDEX,iMetaRef);
	lua_setmetatable(l, -2);
	return pSystemAddress;
}


///Convert system address to string
// @param public key userdata
// @return string converted system address
static int raknet_system_address_tostring( lua_State *l )
{
	char strAddr[64];
	RAKSYSTEMADDRESS_CHECK(l,1)->ToString(true,strAddr);
	lua_pushstring(l,strAddr);
	return 1;
}


/// Metatable metamethod <
// @param public key userdata
// @param public key userdata
static int raknet_system_address_less_than( lua_State *l )
{
	assert( lua_gettop(l) > 1 && lua_type(l,1) == LUA_TUSERDATA && lua_type(l,2) == LUA_TUSERDATA );
	lua_pushboolean( l, *RAKSYSTEMADDRESS_CHECK(l,1) < *RAKSYSTEMADDRESS_CHECK(l,2) );
	return 1;
}

/// Metatable metamethod =
// @param public key userdata
// @param public key userdata
static int raknet_system_address_equal( lua_State *l )
{
	assert( lua_gettop(l) > 1 && lua_type(l,1) == LUA_TUSERDATA && lua_type(l,2) == LUA_TUSERDATA );
	lua_pushboolean( l, *RAKSYSTEMADDRESS_CHECK(l,1) == *RAKSYSTEMADDRESS_CHECK(l,2) );
	return 1;
}

/// Metatable metamethod <=
// @param public key userdata
// @param public key userdata
static int raknet_system_address_less_than_equal( lua_State *l )
{
	assert( lua_gettop(l) > 1 && lua_type(l,1) == LUA_TUSERDATA && lua_type(l,2) == LUA_TUSERDATA );
	RakNet::SystemAddress* pSystemAddress1 = RAKSYSTEMADDRESS_CHECK(l,1);
	RakNet::SystemAddress* pSystemAddress2 = RAKSYSTEMADDRESS_CHECK(l,2);
	lua_pushboolean( l, (*pSystemAddress1 == *pSystemAddress2) || (*pSystemAddress1 < *pSystemAddress2) );
	return 1;
}

///Get system address using debug port
// @param system address userdata
// @return boolean
static int raknet_sa_is_debug_port( lua_State *l )
{
	lua_pushboolean(l, RAKSYSTEMADDRESS_CHECK(l,1)->debugPort );
	return 1;
}

///Get system address is loopback adapter
// @param system address userdata
// @return boolean
static int raknet_sa_is_loopback( lua_State *l )
{
	lua_pushboolean(l, RAKSYSTEMADDRESS_CHECK(l,1)->IsLoopback() );
	return 1;
}

///Get system address is lan address
// @param system address userdata
// @return boolean
static int raknet_sa_is_lan_address( lua_State *l )
{
	lua_pushboolean(l, RAKSYSTEMADDRESS_CHECK(l,1)->IsLANAddress() );
	return 1;
}


///Get system address ip version
// @param system address userdata
// @return number ipv 4 - 4, ipv 6 - 6
static int raknet_sa_get_ip_version( lua_State *l )
{
	lua_pushnumber(l, RAKSYSTEMADDRESS_CHECK(l,1)->GetIPVersion() );
	return 1;
}

///Get system address ip proto
// @param system address userdata
// @return number ipv 4 - 4, ipv 6 - 6
static int raknet_sa_get_ip_proto( lua_State *l )
{
	lua_pushnumber(l, RAKSYSTEMADDRESS_CHECK(l,1)->GetIPPROTO() );
	return 1;
}

///Set system address as loopback adapter
// @param system address userdata
// @param Ip version optional
static int raknet_sa_set_loopback( lua_State *l )
{
	if ( lua_gettop(l) > 1 )
		RAKSYSTEMADDRESS_CHECK(l,1)->SetToLoopback( (unsigned char) lua_tointeger(l,2));
	else
		RAKSYSTEMADDRESS_CHECK(l,1)->SetToLoopback();
	return 0;
}

///Convert system address to string
// @param system address userdata
// @param write port
// @param port delimeter
// @return string
static int raknet_sa_to_string( lua_State *l )
{
	char strData[64];
	char strDelimeter = '|';
	const char* pDelimeter = lua_tostring(l,3);
	if ( pDelimeter )
		strDelimeter = pDelimeter[0];

	RAKSYSTEMADDRESS_CHECK(l,1)->ToString(lua_toboolean(l,2), strData, strDelimeter);
	lua_pushstring(l,strData);
	return 1;
}

///Set system as unassigned system address
// @param system address userdata
static int raknet_sa_set_unassigned( lua_State *l )
{
	*RAKSYSTEMADDRESS_CHECK(l,1) = RakNet::UNASSIGNED_SYSTEM_ADDRESS;
	return 0;
}

///Get system address port
// @param system address userdata
// @return number
static int raknet_sa_get_port( lua_State *l )
{
	lua_pushnumber(l, RAKSYSTEMADDRESS_CHECK(l,1)->GetPort());
	return 1;
}

///Get system address port network order
// @param system address userdata
// @return number
static int raknet_sa_get_port_network_order( lua_State *l )
{
	lua_pushnumber(l, RAKSYSTEMADDRESS_CHECK(l,1)->GetPortNetworkOrder());
	return 1;
}

///Get system address integer hash
// @param system address userdata
// @return number
static int raknet_sa_to_integer( lua_State *l )
{
	lua_pushnumber(l, RakNet::SystemAddress::ToInteger( *RAKSYSTEMADDRESS_CHECK(l,1) ) );
	return 1;
}

///Convert string to system address
// @param system address userdata
// @param str data
// @param port delimeter
// @param ip version
// @return boolean
static int raknet_sa_from_string( lua_State *l )
{
	int iTop = lua_gettop(l);
	assert( iTop > 1 );
	const char* strData = lua_tostring(l,2);
	const char* strDelimeter = lua_tostring(l,3);
	char Delimeter = strDelimeter ? strDelimeter[0] : '|';
	int iVersion = lua_tointeger(l,4);
	bool bSuccess = false; 
	if ( iTop > 3 )
		bSuccess = RAKSYSTEMADDRESS_CHECK(l,1)->FromString(strData, Delimeter, iVersion);
	else if ( iTop > 2 )
		bSuccess = RAKSYSTEMADDRESS_CHECK(l,1)->FromString(strData, Delimeter);
	else if ( iTop > 1 )
		bSuccess = RAKSYSTEMADDRESS_CHECK(l,1)->FromString(strData);
	lua_pushboolean(l,bSuccess);
	return 1;
}

///Convert string to system address, direct port
// @param system address userdata
// @param str data
// @param port
// @param ip version
// @return boolean
static int raknet_sa_from_stringp(lua_State *l)
{
	int iTop = lua_gettop(l);
	assert(iTop > 2);
	const char* strData = lua_tostring(l, 2);
	int iPort = lua_tointeger(l, 3);
	int iVersion = lua_tointeger(l, 4);
	bool bSuccess = false;
	if (iTop > 3)
		bSuccess = RAKSYSTEMADDRESS_CHECK(l, 1)->FromStringExplicitPort(strData, iPort, iVersion);
	else if (iTop > 2)
		bSuccess = RAKSYSTEMADDRESS_CHECK(l, 1)->FromStringExplicitPort(strData, iPort);
	lua_pushboolean(l, bSuccess);
	return 1;
}

///Set system address port
// @param system address userdata
// @param port
// @return number
static int raknet_sa_set_port( lua_State *l )
{
	assert( lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	RAKSYSTEMADDRESS_CHECK(l,1)->SetPortHostOrder( (unsigned short) lua_tointeger(l,2) );
	return 0;
}

///Clone system address
// @param src system address userdata
// @param dest system address userdata
// @return
static int raknet_sa_copy_to(lua_State *l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA);
	*RAKSYSTEMADDRESS_CHECK(l, 1) = *RAKSYSTEMADDRESS_CHECK(l, 1);
	return 0;
}

static const struct luaL_Reg raknet_system_address_meta [] = {
	{"is_debug_port", raknet_sa_is_debug_port },
	{"is_loopback", raknet_sa_is_loopback },
	{"is_lan_address", raknet_sa_is_lan_address },
	{"get_ip_version", raknet_sa_get_ip_version },
	{"get_ip_proto",  raknet_sa_get_ip_proto },
	{"set_loopback", raknet_sa_set_loopback },
	{"to_string", raknet_sa_to_string },
	{"set_unassigned", raknet_sa_set_unassigned },
	{"get_port", raknet_sa_get_port },
	{"set_port", raknet_sa_set_port },
	{"get_port_network_order", raknet_sa_get_port_network_order },
	{"to_integer", raknet_sa_to_integer },
	{"from_string", raknet_sa_from_string },
	{"from_stringp", raknet_sa_from_stringp },
	{"copy_to", raknet_sa_copy_to },
	{NULL, NULL}
};

int luaopen_system_address( lua_State *l )
{
	luaL_newmetatable(l, DRaknetSystemAddressMeta);
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_system_address_meta);
	lua_setfield(l, -2, "__index");
	
	lua_pushcfunction(l, raknet_system_address_tostring);
	lua_setfield(l, -2, "__tostring");
	
	lua_pushcfunction(l, raknet_system_address_less_than);
	lua_setfield(l, -2, "__lt");

	lua_pushcfunction(l, raknet_system_address_less_than_equal);
	lua_setfield(l, -2, "__le");

	lua_pushcfunction(l, raknet_system_address_equal);
	lua_setfield(l, -2, "__eq");

	return 1;
}