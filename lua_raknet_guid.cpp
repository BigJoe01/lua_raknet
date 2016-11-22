#include "lua_raknet_guid.h"
#include "lua_raknet_helper.h"
#include <assert.h>
#pragma warning( disable : 4800 )

/// Raknet guid module
// Guid is unique identifier in raknet 
// @module Guid

inline RakNet::RakNetGUID* RAKGUID_CHECK(lua_State* l, int iIndex)
{
	assert(lua_gettop(l) > 0);
#ifdef _DEBUG
	RakNet::RakNetGUID* instance = (RakNet::RakNetGUID*)luaL_checkudata(l, iIndex, DRaknetGuidMeta);
	if (!instance)
		luaL_error(l, "Invalid raknet guid meta at index : %d", iIndex);
	assert(((RakNet::NetObjectType*)instance)->ucType == RAK_MAGIC_GUID);
	return instance;
#else
	RakNet::RakNetGUID* instance = (RakNet::RakNetGUID*)lua_touserdata(l, iIndex);
	return instance;
#endif
}

RakNet::RakNetGUID* RAKGUID_NEW(lua_State* l, int iMetaRef, int id)
{
	RakNet::RakNetGUID* pGuid = (RakNet::RakNetGUID*) lua_newuserdata(l, sizeof(RakNet::RakNetGUID));
	*pGuid = RakNet::RakNetGUID((uint64_t)id);
	lua_rawgeti(l, LUA_REGISTRYINDEX, iMetaRef);
	lua_setmetatable(l, -2);
	return pGuid;
}

/// operator <
// @function __lt
// @param guid userdata
// @param guid userdata
// @usage guid < guid
static int raknet_guid_less_than(lua_State *l)
{
	assert(lua_gettop(l) > 1 );
	lua_pushboolean(l, *RAKGUID_CHECK(l, 1) < *RAKGUID_CHECK(l, 2));
	return 1;
}

/// operator =
// @function __eq
// @param guid userdata
// @param guid userdata
// @usage guid == guid
static int raknet_guid_equal(lua_State *l)
{
	assert(lua_gettop(l) > 1);
	lua_pushboolean(l, *RAKGUID_CHECK(l, 1) == *RAKGUID_CHECK(l, 2));
	return 1;
}

/// operator <=
// @function __le
// @param guid userdata
// @param guid userdata
// @usage guid <= guid
static int raknet_guid_less_than_equal(lua_State *l)
{
	assert(lua_gettop(l) > 1);
	RakNet::RakNetGUID* pGuid1 = RAKGUID_CHECK(l, 1);
	RakNet::RakNetGUID* pGuid2 = RAKGUID_CHECK(l, 2);
	lua_pushboolean(l, (*pGuid1 == *pGuid2) || (*pGuid1 < *pGuid2));
	return 1;
}

/// Convert guid to string
// @function to_string
// @param  guid userdata
// @return string converted system address
// @usage guid:to_string()
static int raknet_guid_tostring(lua_State *l)
{
	char strAddr[64];
	RAKGUID_CHECK(l, 1)->ToString(strAddr);
	lua_pushstring(l, strAddr);
	return 1;
}

/// Get guid as integer
// @function to_integer
// @param guid userdata
// @return integer
// @usage guid:to_integer()
static int raknet_guid_to_integer(lua_State *l)
{
	lua_pushnumber(l, RakNet::RakNetGUID::ToUint32( *RAKGUID_CHECK(l, 1)));
	return 1;
}

/// Get guid as number internal uint64_t
// @function to_number
// @param guid userdata
// @return number
// @usage guid:to_number()
static int raknet_guid_to_number(lua_State *l)
{
	lua_pushnumber(l, RAKGUID_CHECK(l, 1)->g );
	return 1;
}

/// Convert string to guid
// @function from_string
// @param guid userdata
// @param uniqueid string
// @return success
// @usage guid:from_string('1231123231')
static int raknet_guid_from_string(lua_State *l)
{
	assert( lua_gettop(l) > 1 && lua_type(l,2) == LUA_TSTRING );
	lua_pushboolean(l, RAKGUID_CHECK(l, 1)->FromString( lua_tostring(l,2) ));
	return 1;
}

/// Convert number to guid, using uint64_t
// @function from_number
// @param guid userdata
// @param uniqueid number
// @usage guid:from_number('343434343')
static int raknet_guid_from_number(lua_State *l)
{
	assert( lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	RAKGUID_CHECK(l, 1)->FromUint64((uint64_t) lua_tonumber(l,2));
	return 0;
}

/// Convert number ( integer ) to guid
// @function from_integer
// @param guid userdata
// @param uniqueid nummber
// @usage guid:from_number('343434343')
static int raknet_guid_from_integer(lua_State *l)
{
	assert( lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	RAKGUID_CHECK(l, 1)->FromUint64((uint64_t) lua_tointeger(l,2));
	return 0;
}

/// Copy guid to another guid
// @function copy_to
// @param guid userdata
// @param dest_guid userdata
// @usage guid:copty_to( target_guid )
static int raknet_guid_copy_to(lua_State *l)
{
	assert(lua_gettop(l) > 1 );
	*RAKGUID_CHECK(l, 1) = *RAKGUID_CHECK(l, 2);
	return 0;
}

static const struct luaL_Reg raknet_guid_meta[] = {
	{ "to_integer", raknet_guid_to_integer },
	{ "to_number", raknet_guid_to_number },
	{ "from_string", raknet_guid_from_string },
	{ "from_number", raknet_guid_from_number },
	{ "from_integer", raknet_guid_from_integer },
	{ "to_string", raknet_guid_tostring },
	{ "copy_to" , raknet_guid_copy_to },
	{ NULL, NULL }
};

int luaopen_raknet_guid(lua_State *l)
{
	luaL_newmetatable(l, DRaknetGuidMeta);
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_guid_meta);
	lua_setfield(l, -2, "__index");

	lua_pushcfunction(l, raknet_guid_tostring);
	lua_setfield(l, -2, "__tostring");

	lua_pushcfunction(l, raknet_guid_less_than);
	lua_setfield(l, -2, "__lt");

	lua_pushcfunction(l, raknet_guid_less_than_equal);
	lua_setfield(l, -2, "__le");

	lua_pushcfunction(l, raknet_guid_equal);
	lua_setfield(l, -2, "__eq");

	return 1;
}