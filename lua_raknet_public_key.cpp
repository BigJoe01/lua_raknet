#include "lua_raknet_public_key.h"
#include "lua_raknet_helper.h"
#include <assert.h>

#pragma warning( disable : 4800 )

RAKPUBLICKEY* RAKPUBLICKEY_CHECK( lua_State* l, int iIndex )
{
	assert(lua_gettop(l) > 0);
#ifdef _DEBUG
	RAKPUBLICKEY* instance = (RAKPUBLICKEY*)luaL_checkudata(l, iIndex, DRaknetPublicKeyMeta);
	if (!instance)
		luaL_error(l,"Invalid raknet public key meta at index : %d", iIndex);
#else
	RAKPUBLICKEY* instance = (RAKPUBLICKEY*)lua_touserdata(l, iIndex);
	assert(instance != nullptr);
#endif
	return instance;
}

RAKPUBLICKEY* RAKPUBLICKEY_NEW( lua_State* l, int iMetaRef )
{
	RAKPUBLICKEY* Descriptor = (RAKPUBLICKEY*) lua_newuserdata(l, sizeof(RAKPUBLICKEY));
	memset(Descriptor, 0, sizeof(RAKPUBLICKEY)); // defaults
	lua_rawgeti(l,LUA_REGISTRYINDEX,iMetaRef);
	lua_setmetatable(l, -2);
	return Descriptor;
}

static int raknet_public_key_gc( lua_State *l )
{
	return 0;
}

// Common
static void set_key_from_lua( char* Dest, bool bIsHex, const char* pStr, int iLen, int key_size )
{
	if ( bIsHex )
	{
		assert( iLen > key_size * 2 );
		hex2bin( pStr,Dest);	
	}
	else
	{	
		assert( iLen > key_size );
		memcpy( Dest, pStr, iLen );
	}
}

/// Set public key mode
// @param public key userdata
// @param integer mode
static int set_public_key_mode( lua_State *l )
{
	assert( lua_gettop(l) > 1 );
	RAKPUBLICKEY* PublicKey = RAKPUBLICKEY_CHECK(l,1);
	PublicKey->PublicKeyMode = (RakNet::PublicKeyMode) lua_tointeger(l,2);
	return 0;
}

/// Set remote server public key
// @param public key userdata
// @param key data
// @param is hex data
static int set_remote_server_public( lua_State *l )
{
	assert( lua_gettop(l) > 1 );
	RAKPUBLICKEY* PublicKey = RAKPUBLICKEY_CHECK(l,1);
	set_key_from_lua(PublicKey->remoteServerPublicKey, lua_toboolean(l, 3), lua_tostring(l, 2), strlen(lua_tostring(l, 2)), DRaknetPublickKeySize );
	return 0;
}

/// Set my public key
// @param public key userdata
// @param key data
// @param is hex data
static int set_public_key( lua_State *l )
{
	assert( lua_gettop(l) > 1 );
	RAKPUBLICKEY* PublicKey = RAKPUBLICKEY_CHECK(l,1);
	set_key_from_lua(PublicKey->myPublicKey, lua_toboolean(l, 3), lua_tostring(l, 2), strlen(lua_tostring(l, 2)), DRaknetPublickKeySize );
	return 0;
}

/// Set my private key
// @param public key userdata
// @param key data
// @param is hex data
static int set_private_key( lua_State *l )
{
	assert( lua_gettop(l) > 1 );
	RAKPUBLICKEY* PublicKey = RAKPUBLICKEY_CHECK(l,1);
	set_key_from_lua(PublicKey->myPrivateKey, lua_toboolean(l, 3), lua_tostring(l, 2), strlen(lua_tostring(l, 2)), DRaknetPrivateKeySize );
	return 0;
}

static const struct luaL_Reg raknet_public_key_meta [] = {
	{"key_mode",      set_public_key_mode },
	{"remote_server", set_remote_server_public },
	{"public_key",  set_public_key },
	{"private_key", set_private_key },
	{NULL, NULL}
};

int luaopen_raknet_public_key( lua_State *l )
{
	luaL_newmetatable(l, DRaknetPublicKeyMeta);
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_public_key_meta);
	lua_setfield(l, -2, "__index");
	lua_pushcfunction(l, raknet_public_key_gc);
	lua_setfield(l, -2, "__gc");
	return 1;
}