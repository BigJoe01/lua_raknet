//----------------------------------------------------------
// Raknet lua bindigs
//----------------------------------------------------------

extern "C"
{
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include "RakNetTypes.h"

#define DRaknetPublickKeySize 64
#define DRaknetPrivateKeySize 32

#define DRaknetPublicKeyMeta ":raknet_public_key:"

struct RAKPUBLICKEY
{
	RakNet::PublicKeyMode PublicKeyMode;
	char remoteServerPublicKey[DRaknetPublickKeySize];
	char myPublicKey[DRaknetPublickKeySize];
	char myPrivateKey[DRaknetPrivateKeySize];
};

RAKPUBLICKEY* RAKPUBLICKEY_CHECK( lua_State* l, int iIndex );
RAKPUBLICKEY* RAKPUBLICKEY_NEW( lua_State* l, int iMetaRef );

int luaopen_raknet_public_key(lua_State *l);