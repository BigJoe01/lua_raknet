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

#include "RakPeer.h"
#include "RakPeerInterface.h"
#include "PluginInterface2.h"
#include "DS_List.h"

#define  DMaxPlugins 20
#define  DRaknetPluginsName "raknet_plugin"
#define  DRaknetModuleName "raknet"
#define  DRaknetMetaName   ":raknet_meta_t:"
#define  DRaknetMaxConnections 50
#define  DRaknetDefaultPort 5000
#define  DRaknetDefaultHost "127.0.0.1"
#define  DRaknetDefaultPriority -99999
#define  DDisconnectBlockDuration 200
#define  DDisconnectOrderingChannel 0
#define  DDisconnectPriority PacketPriority::LOW_PRIORITY
#define  DConnectDefaultHost "127.0.0.1"
#define  DConnectDefaultPort 5000
#define  DRaknetTempBufferSize 8192

struct RAKPEER_CONNECTIONS
{
	DataStructures::List<RakNet::SystemAddress> addresses;
	DataStructures::List<RakNet::RakNetGUID> guids;
};

struct RAKPEER
{
	RakNet::RakPeer* pPeer;
	RakNet::PluginInterface2* aPlugins[DMaxPlugins];
	RAKPEER_CONNECTIONS Connections;
	char cTempBuffer[DRaknetTempBufferSize];
	int iMetaSocketeDescriptor_Ref;
	int iMetaPublicKey_Ref;
	int iMetaSystemAddress_Ref;
	int iMetaGuid_Ref;
	int iMetaBitStream_Ref;
};

int luaopen_raknet(lua_State *l);