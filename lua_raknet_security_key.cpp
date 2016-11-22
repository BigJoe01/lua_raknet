#include "lua_raknet_security_key.h"
#include "lua_raknet_helper.h"
#include <assert.h>
#include "compat.h"
#include "NativeFeatureIncludes.h"

#if LIBCAT_SECURITY==1
#include "cat/io/Base64.hpp"
#endif

#pragma warning( disable : 4800 )
#define DBase64BuffSize 256

RAKSECURITYKEY* RAKSECURITY_CHECK( lua_State* l, int iIndex )
{
	assert(lua_gettop(l) > 0);
#ifdef _DEBUG
	RAKSECURITYKEY* instance = (RAKSECURITYKEY*)luaL_checkudata(l, iIndex, DRaknetPublicKeyMeta);
	if (!instance)
		luaL_error(l,"Invalid raknet security key meta at index : %d", iIndex);
	return instance;
#else
	return (RAKSECURITYKEY*)lua_touserdata(l, iIndex);
#endif
}

RAKSECURITYKEY* RAKSECURITY_NEW( lua_State* l, int iMetaRef )
{
	RAKSECURITYKEY* Descriptor = (RAKSECURITYKEY*) lua_newuserdata(l, sizeof(RAKSECURITYKEY));
	memset(Descriptor, 0, sizeof(RAKSECURITYKEY)); // defaults
	lua_rawgeti(l,LUA_REGISTRYINDEX,iMetaRef);
	lua_setmetatable(l, -2);
	return Descriptor;
}

static int raknet_security_key_gc( lua_State *l )
{
	return 0;
}

// Common
static void set_key_from_lua( char* pDest, const char* pStr, int iLen, int key_size )
{
#if LIBCAT_SECURITY==1
	cat::ReadBase64( pStr, iLen,(void*) pDest, key_size);
#else
	*pDest = '\0';
#endif
}

/// Set public key mode
// @param public key userdata
// @param integer mode
static int set_security_key_mode( lua_State *l )
{
	assert( lua_gettop(l) > 1 );
	RAKSECURITYKEY* PublicKey = RAKSECURITY_CHECK(l,1);
	PublicKey->PublicKeyMode = (RakNet::PublicKeyMode) lua_tointeger(l,2);
	return 0;
}

/// Set remote server public key
// @param public key userdata
// @param key data
static int set_remote_server_public( lua_State *l )
{
	assert( lua_gettop(l) > 1 );
	if ( lua_type(l,2) == LUA_TNIL )
		return 0;
	RAKSECURITYKEY* PublicKey = RAKSECURITY_CHECK(l,1);
	set_key_from_lua(PublicKey->remotePublicKey, lua_tostring(l, 2), strlen(lua_tostring(l, 2)), DRaknetPublickKeySize );
	PublicKey->bRemotePublicKey = true;
	return 0;
}

/// Get Remote server public
// @param public key userdata
static int get_remote_server_public( lua_State *l )
{
	assert( lua_gettop(l) > 0 );
	RAKSECURITYKEY* PublicKey = RAKSECURITY_CHECK(l,1);
	if ( !PublicKey->bRemotePublicKey )
	{
		lua_pushnil(l);
		return 1;
	}
	char key[DBase64BuffSize];
	get_key_from_lua(PublicKey->remotePublicKey, key, DRaknetPublickKeySize );
	lua_pushstring(l, key );
	return 1;
}



/// Set my public key
// @param public key userdata
// @param key data
static int set_public_key( lua_State *l )
{
	assert( lua_gettop(l) > 1 );
	if ( lua_type(l,2) == LUA_TNIL )
		return 0;
	RAKSECURITYKEY* PublicKey = RAKSECURITY_CHECK(l,1);
	set_key_from_lua(PublicKey->PublicKey, lua_tostring(l, 2), strlen(lua_tostring(l, 2)), DRaknetPublickKeySize );
	PublicKey->bPublicKey = true;
	return 0;
}

/// Set my private key
// @param public key userdata
// @param key data
// @param is hex data
static int set_private_key( lua_State *l )
{
	assert( lua_gettop(l) > 1 );
	if ( lua_type(l,2) == LUA_TNIL )
		return 0;
	RAKSECURITYKEY* PublicKey = RAKSECURITY_CHECK(l,1);
	set_key_from_lua(PublicKey->PrivateKey, lua_tostring(l, 2), strlen(lua_tostring(l, 2)), DRaknetPrivateKeySize );
	PublicKey->bPublicKey = true;
	return 0;
}

void get_key_from_lua( char* pubKey, char* destKey, int iKeySize )
{
#if LIBCAT_SECURITY==1
	cat::WriteBase64Str( (const void*)pubKey, iKeySize,  destKey, DBase64BuffSize );
#else
	*destKey = '\0';
#endif
}

/// Get Public key
// @param public key userdata
static int get_private_key( lua_State *l )
{
	assert( lua_gettop(l) > 0 );
	RAKSECURITYKEY* PublicKey = RAKSECURITY_CHECK(l,1);
	if ( !PublicKey->bPrivateKey )
	{
		lua_pushnil(l);
		return 1;
	}
	char key[DBase64BuffSize];
	get_key_from_lua(PublicKey->PrivateKey, key, DRaknetPrivateKeySize );
	lua_pushstring(l, key );
	return 1;
}

/// Get Private key
// @param public key userdata
static int get_public_key( lua_State *l )
{
	assert( lua_gettop(l) > 0 );
	RAKSECURITYKEY* PublicKey = RAKSECURITY_CHECK(l,1);
	if ( !PublicKey->bPublicKey )
	{
		lua_pushnil(l);
		return 1;
	}
	char key[DBase64BuffSize];
	get_key_from_lua(PublicKey->PublicKey, key, DRaknetPublickKeySize );
	lua_pushstring(l, key);
	return 1;
}

/// Clear keys
// @param public key userdata
static int clear_keys( lua_State *l )
{
	assert( lua_gettop(l) > 0 );
	RAKSECURITYKEY* PublicKey = RAKSECURITY_CHECK(l,1);
	memset(PublicKey,0,sizeof(RAKSECURITYKEY));
	return 0;
}


static const struct luaL_Reg raknet_public_key_meta [] = {
	{"key_mode",      set_security_key_mode },
	{"set_remote_public_key", set_remote_server_public },
	{"get_remote_public_key", get_remote_server_public },
	{"set_public_key",  set_public_key },
	{"set_private_key", set_private_key },
	{"get_public_key",  get_public_key },
	{"get_private_key", get_private_key },
	{"clear", clear_keys },
	{NULL, NULL}
};

int luaopen_raknet_security_key( lua_State *l )
{
	luaL_newmetatable(l, DRaknetPublicKeyMeta);
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_public_key_meta);
	lua_setfield(l, -2, "__index");
	lua_pushcfunction(l, raknet_security_key_gc);
	lua_setfield(l, -2, "__gc");
	return 1;
}