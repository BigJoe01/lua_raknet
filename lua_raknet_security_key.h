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
#include "RakString.h"

#define DRaknetPublickKeySize 64
#define DRaknetPrivateKeySize 32

#define DRaknetPublicKeyMeta ":raknet_security_key:"

struct RAKSECURITYKEY
{
	RakNet::PublicKeyMode PublicKeyMode;
	char remotePublicKey[DRaknetPublickKeySize];
	char PublicKey[DRaknetPublickKeySize];
	char PrivateKey[DRaknetPrivateKeySize];
	bool bRemotePublicKey;
	bool bPublicKey;
	bool bPrivateKey;
};

RAKSECURITYKEY* RAKSECURITY_CHECK( lua_State* l, int iIndex );
RAKSECURITYKEY* RAKSECURITY_NEW( lua_State* l, int iMetaRef );

void get_key_from_lua( char* pubKey, char* destKey, int iKeySize );

int luaopen_raknet_security_key(lua_State *l);