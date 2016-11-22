//----------------------------------------------------------
// Raknet lua bindigs
//----------------------------------------------------------

#include "lua_raknet.h"
#include "lua_raknet_helper.h"
#include <assert.h>

#pragma warning ( disable : 4800 )
#pragma warning ( disable : 4244 )
//---------------------------------------------------------------------------
#include "BitStream.h"
#include "RakPeer.h"
#include "RakSleep.h"
#include "RakNetTypes.h"
#include "BitStream.h"
#include "RakNetTime.h"
#include "GetTime.h"
#if LIBCAT_SECURITY==1
 #include "cat/crypt/tunnel/EasyHandshake.hpp"
#endif

//---------------------------------------------------------------------------
#include "lua_socket_descriptor.h"
#include "lua_raknet_security_key.h"
#include "lua_raknet_system_address.h"
#include "lua_raknet_guid.h"
#include "lua_raknet_bitstream.h"
#include "lua_raknet_plugin_console.h"
#include "lua_raknet_plugin_relay.h"
#include "lua_raknet_helper.h"


//---------------------------------------------------------------------------
// Default RakPeer class
//---------------------------------------------------------------------------

static void RAKPEER_INIT( RAKPEER* peer )
{
	assert(peer);
	peer->pPeer = nullptr;
	peer->iMetaSocketeDescriptor_Ref = 0;
	peer->iMetaPublicKey_Ref = 0;
	peer->iMetaSystemAddress_Ref = 0;
	peer->iMetaGuid_Ref = 0;
	peer->iMetaBitStream_Ref = 0;
	memset(peer->aPlugins,0,DMaxPlugins * sizeof(RakNet::PluginInterface2*));
}

static RakNet::RakPeer* RAKPEER_CREATEPEER(RAKPEER* peer)
{
	assert(peer);
	RakNet::RakPeer* pPeer = (RakNet::RakPeer*)RakNet::RakPeer::GetInstance();
	assert(pPeer);
	peer->pPeer = pPeer;
	return pPeer;
}

static bool RAKPEER_DESTROYPEER( RAKPEER* peer )
{
	assert(peer);
	assert( peer->pPeer );
	for ( int iIndex = 0; iIndex < DMaxPlugins; iIndex ++ )
	{
		RakNet::PluginInterface2* pPlugin = peer->aPlugins[iIndex];
		if ( pPlugin )
		{
			peer->pPeer->DetachPlugin( pPlugin );
			peer->aPlugins[iIndex] = nullptr;
			delete pPlugin;
		}
	}
	RakNet::RakPeer::DestroyInstance( peer->pPeer );
	peer->pPeer = nullptr;
	return true;
}

//---------------------------------------------------------
inline RAKPEER* RAKPEER_CHECK(lua_State *l, int iIndex)
{
	assert(lua_gettop(l) > 0);
#ifdef _DEBUG
	RAKPEER* instance = (RAKPEER*)luaL_checkudata(l, iIndex, DRaknetMetaName);
	if (!instance)
		luaL_error(l,"Invalid raknet metadata at index : %d", iIndex);
#else
	RAKPEER* instance = (RAKPEER*)lua_touserdata(l, iIndex);
	assert(instance);
#endif
	return instance;
}

//---------------------------------------------------------------------------
// Raknet metatable functions
//---------------------------------------------------------------------------

static int raknet_gc( lua_State *l )
{
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	assert(Peer);
	RAKPEER_DESTROYPEER( Peer );
	return 0;
}

//--------------------------------------
// Raknet startup
// @param Raknet Userdata
// @param Max. connection
// @param Socket descriptor, if nil, use default
// @param Thread priority
// @return StartUp result 
static int raknet_startup( lua_State* l )
{
	int top = lua_gettop(l);
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	
	int iConnections = top > 1 ? lua_tointeger(l,2) : DRaknetMaxConnections;
	RakNet::SocketDescriptor* pSocketDescriptor = nullptr;
	int iDescriptors = 1;
	RakNet::SocketDescriptor  DefaultDescriptor( DRaknetDefaultPort, DRaknetDefaultHost );
	if( top > 2 && !lua_isnil(l,3) )
	{
		RAKSOCKETDESCRIPTOR* Descriptor = RAKSOCKETDESCRIPTOR_CHECK(l,3);
		pSocketDescriptor = Descriptor->Descriptors;
		iDescriptors      = Descriptor->iUsedCount;
	}
	else
		pSocketDescriptor = &DefaultDescriptor;
	
	int iThreadPriority = top > 3 ? lua_tointeger(l, 4) : DRaknetDefaultPriority;

	RakNet::StartupResult Result = Peer->pPeer->Startup(iConnections, pSocketDescriptor, iDescriptors, iThreadPriority );
	lua_pushboolean(l, Result == RakNet::StartupResult::RAKNET_STARTED );
	lua_pushinteger(l,(int) Result);
	return 2;
}

//--------------------------------------
// Raknet shutdown
// @param Raknet Userdata
// @param Block duration
// @param Ordering channel
// @param Priority
static int raknet_shutdown( lua_State* l )
{
	int top = lua_gettop(l);
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	unsigned int iBlockDuration = top > 1 ? lua_tointeger(l,2) : DDisconnectBlockDuration;
	unsigned char cChannel = top > 2 ? lua_tointeger(l,3) : DDisconnectOrderingChannel;
	PacketPriority ePPriority = top > 3 ? (PacketPriority)lua_tointeger(l,4) : DDisconnectPriority;
	Peer->pPeer->Shutdown( iBlockDuration, cChannel, ePPriority );	
	return 0;
}

//--------------------------------------
// Raknet disable security
static int raknet_disable_securiuty( lua_State* l )
{
	RAKPEER_CHECK(l,1)->pPeer->DisableSecurity();
	return 0;
}

//--------------------------------------
// Raknet Initializate security
// @param Raknet Userdata
// @param Public key
// @param Require client key
static int raknet_init_security( lua_State* l )
{
	assert( lua_gettop(l) > 2  && lua_type(l,2) == LUA_TUSERDATA && lua_type(l,3) == LUA_TBOOLEAN );
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	RAKSECURITYKEY* Key = RAKSECURITY_CHECK(l,2);
	lua_pushboolean( l, Peer->pPeer->InitializeSecurity( Key->PublicKey ,Key->PrivateKey,lua_toboolean(l,3)));
	return 1;
}

//--------------------------------------
// Raknet Add Ip to security exception list
// @param Raknet Userdata
// @param string ip ( wildcard * supported )
static int raknet_add_to_exception_list( lua_State* l )
{
	RAKPEER_CHECK(l,1)->pPeer->AddToSecurityExceptionList(lua_tostring(l,2));
	return 0;
}

//--------------------------------------
// Raknet Remove Ip from security exception list
// @param Raknet Userdata
// @param string ip ( wildcard * supported, 0 remove all ) or nil
static int remove_from_security_exception_list ( lua_State* l )
{
	RAKPEER_CHECK(l,1)->pPeer->RemoveFromSecurityExceptionList(lua_tostring(l,2));
	return 0;
}

//--------------------------------------
// Raknet Ip is in security exception list
// @param Raknet Userdata
// @param string ip
static int raknet_is_in_exception_list( lua_State* l )
{
	assert( lua_gettop(l) > 1 && lua_type(l,2) == LUA_TSTRING );
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	lua_pushboolean( l, Peer->pPeer->IsInSecurityExceptionList(lua_tostring(l,2)));
	return 1;
}

//--------------------------------------
// Raknet Set maximum incoming connection
// @param Raknet Userdata
// @param Max connection, integer
static int raknet_set_max_inc_connection( lua_State* l )
{
	assert( lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	RAKPEER_CHECK(l,1)->pPeer->SetMaximumIncomingConnections(lua_tointeger(l,2));
	return 0;
}

//--------------------------------------
// Raknet Get maximum incoming connection
// @param Raknet Userdata
// @return Maximum connection
static int raknet_get_max_inc_connection( lua_State* l )
{
	lua_pushinteger(l, RAKPEER_CHECK(l,1)->pPeer->GetMaximumIncomingConnections() );
	return 1;
}

//--------------------------------------
// Raknet Get number of connection opened
// @param Raknet Userdata
// @return number of connections
static int raknet_number_of_connections( lua_State* l )
{
	lua_pushinteger(l, RAKPEER_CHECK(l,1)->pPeer->NumberOfConnections() );
	return 1;
}

//--------------------------------------
// Raknet Set incoming password
// @param Raknet Userdata
// @param password
static int raknet_set_inc_password( lua_State* l )
{
	assert( lua_gettop(l) > 1 && lua_type(l,2) == LUA_TSTRING );
	RAKPEER_CHECK(l,1)->pPeer->SetIncomingPassword(lua_tostring(l,2), strlen(lua_tostring(l,2)));
	return 0;
}

//--------------------------------------
// Raknet Get incoming password
// @param Raknet Userdata
// @return password
static int raknet_get_inc_password( lua_State* l )
{
	assert( lua_gettop(l) > 0);
	char passwd[256];
	int  passwd_size = sizeof(passwd);
	RAKPEER_CHECK(l,1)->pPeer->GetIncomingPassword(passwd, &passwd_size);
	lua_pushlstring(l, passwd, passwd_size );
	return 1;
}

//--------------------------------------
// Raknet Connect to host
// @param Raknet Userdata
// @param table with params
// @return bool, result 
// { host = string, port = int , password = string, public_key = userdata or nil, socket_index = int, connection_attempt = int, time_between_send = int, timeout = int }
static int raknet_connect( lua_State* l )
{
	assert( lua_gettop(l) > 0);
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	assert( lua_type(l,2) == LUA_TTABLE );
	const char* sHost = RakNetHelper::GetFieldAsString(l, "host", DConnectDefaultHost);
	unsigned short usPort = RakNetHelper::GetFieldAsInteger(l, "port", DConnectDefaultPort);
	const char* sPassword = RakNetHelper::GetFieldAsString(l, "password", "");
	int iPasswordSize = strlen(sPassword);
	unsigned int uiSocketIndex = RakNetHelper::GetFieldAsInteger(l,"socket_index", 0);
	unsigned int uiConnectionAttempt = RakNetHelper::GetFieldAsInteger(l,"connection_attempt", 6);
	unsigned int uiTimeMsBetweenTry = RakNetHelper::GetFieldAsInteger(l,"time_between_send", 1000);
	unsigned int uiTimeoutTime = RakNetHelper::GetFieldAsInteger(l,"timeout", 0);
	
	RakNet::PublicKey PublicKey;
	RakNet::PublicKey* pPKey = nullptr;
	RAKSECURITYKEY* pPublicKey = (RAKSECURITYKEY*)RakNetHelper::GetFieldAsUserData(l, "public_key", DRaknetPublicKeyMeta, nullptr);
	if ( pPublicKey )
	{
		PublicKey.publicKeyMode = pPublicKey->PublicKeyMode;
		PublicKey.myPrivateKey  = pPublicKey->PrivateKey;
		PublicKey.myPublicKey   = pPublicKey->PublicKey;
		PublicKey.remoteServerPublicKey = pPublicKey->remotePublicKey;
		pPKey = &PublicKey;
	}
	RakNet::ConnectionAttemptResult Result = Peer->pPeer->Connect(sHost,usPort,sPassword, iPasswordSize, pPKey, uiSocketIndex, uiConnectionAttempt, uiTimeMsBetweenTry, uiTimeoutTime ); 

	bool bSuccess = Result == RakNet::ConnectionAttemptResult::CONNECTION_ATTEMPT_STARTED;
	lua_pushboolean(l, bSuccess );
	lua_pushnumber(l, (int)Result);
	return 2;
}

//--------------------------------------
// Raknet Get is active
// @param Raknet Userdata
// @return bool, active state
static int raknet_is_active( lua_State* l )
{
	lua_pushboolean(l, RAKPEER_CHECK(l,1)->pPeer->IsActive() );
	return 1;
}

//--------------------------------------
// Raknet Get Connection list
// @param Raknet Userdata
// @return connection list size
static int raknet_get_connection_list(lua_State* l)
{
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	Peer->pPeer->GetSystemList(Peer->Connections.addresses, Peer->Connections.guids);
	lua_pushnumber(l, Peer->Connections.addresses.Size() );
	return 1;
}

//--------------------------------------
// Raknet Clear connection list
// @param Raknet Userdata
static int raknet_clear_connections(lua_State* l)
{
	assert(lua_gettop(l) > 0);
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	Peer->Connections.addresses.Clear(false, __FILE__, __LINE__ );
	Peer->Connections.guids.Clear(false, __FILE__, __LINE__ );
	return 0;
}


//--------------------------------------
// Raknet Get next receipt number
// @param Raknet Userdata
// @return integer next recepit number
static int raknet_get_next_send_receipt( lua_State* l )
{
	lua_pushnumber(l, RAKPEER_CHECK(l,1)->pPeer->GetNextSendReceipt() );
	return 1;
}

//--------------------------------------
// Raknet increment receipt number
// @param Raknet Userdata
// @return integer next recepit number
static int raknet_inc_next_send_receipt( lua_State* l )
{
	lua_pushnumber(l, RAKPEER_CHECK(l,1)->pPeer->IncrementNextSendReceipt() );
	return 1;
}

//--------------------------------------
// Raknet send bitstream to loopback
// @param Raknet Userdata
// @return
static int raknet_send_loopback(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA );
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l, 2);
	RAKPEER_CHECK(l, 1)->pPeer->SendLoopback( (const char*)pBitStream->GetData(), pBitStream->GetNumberOfBytesUsed());
	return 0;
}


//--------------------------------------
/// Raknet send bitstream
// @param Raknet Userdata
// @param Raknet BitStream
// @param Packet Priority
// @param Packet Reliability
// @param Ordering Channel
// @param System Address or guid or Guid number or Lua Table ( guid number list )
// @param Broadcast
// @param ReceiptNumber
// @return how many bytes sent
static int raknet_send( lua_State* l)
{
	assert(lua_gettop(l) > 7 && ( lua_type(l,6) == LUA_TUSERDATA || lua_type(l,6) == LUA_TNUMBER ) );
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l,2);
	PacketPriority Priority = (PacketPriority)lua_tointeger(l,3);
	PacketReliability Reliability = (PacketReliability)lua_tointeger(l,4);
	unsigned char Channel = (unsigned char)lua_tointeger(l,5);
	bool  bBroadCast = lua_toboolean(l,7);
	uint32_t ReceiptNumber = (uint32_t) lua_tonumber(l,8);
	int iType = lua_type(l,6);

	if ( lua_type(l,6) == LUA_TUSERDATA)
	{
		void* pGuidOrSysAddr = lua_touserdata(l,6);
		if (((RakNet::NetObjectType*)pGuidOrSysAddr)->ucType == RAK_MAGIC_SYSTEM_ADDR)
			lua_pushnumber( l, Peer->pPeer->Send( pBitStream, Priority,Reliability,Channel, (*((RakNet::SystemAddress*)pGuidOrSysAddr)), bBroadCast, ReceiptNumber) );
		else
			lua_pushnumber( l, Peer->pPeer->Send( pBitStream, Priority,Reliability,Channel, (*((RakNet::RakNetGUID*)pGuidOrSysAddr)), bBroadCast, ReceiptNumber) );
	}
	else if ( iType == LUA_TTABLE)
	{		
		lua_pushvalue(l,6);
		lua_pushnil(l);
		while ( lua_next(l, -2) != 0 )
		{
			int iType = lua_type(l,-1);
			if ( iType == LUA_TUSERDATA)
			{
				void* pGuidOrSysAddr = lua_touserdata(l,-1);
				if (((RakNet::NetObjectType*)pGuidOrSysAddr)->ucType == RAK_MAGIC_SYSTEM_ADDR)
					lua_pushnumber( l, Peer->pPeer->Send( pBitStream, Priority,Reliability,Channel, (*((RakNet::SystemAddress*)pGuidOrSysAddr)), bBroadCast, ReceiptNumber) );
				else
					lua_pushnumber( l, Peer->pPeer->Send( pBitStream, Priority,Reliability,Channel, (*((RakNet::RakNetGUID*)pGuidOrSysAddr)), bBroadCast, ReceiptNumber) );
			}
			else if ( iType == LUA_TNUMBER )
			{
				RakNet::RakNetGUID Guid( (uint64_t)lua_tonumber(l,-1));
				lua_pushnumber( l, Peer->pPeer->Send( pBitStream, Priority,Reliability,Channel, Guid, bBroadCast, ReceiptNumber) );
			}
			lua_pop(l, 1);
		}
		lua_pop(l,1);
	}
	else if ( iType == LUA_TNUMBER )
	{
		RakNet::RakNetGUID Guid( (uint64_t)lua_tonumber(l,6));
		lua_pushnumber( l, Peer->pPeer->Send( pBitStream, Priority,Reliability,Channel, Guid, bBroadCast, ReceiptNumber) );
	}
	else
		lua_pushnumber( l,0 );
	return 1;
}


//--------------------------------------
// Raknet receive packet
// @param Raknet Userdata
// @param SystemAddress
// @param Guid
// @param Mode ( BitStream / string / nil )
// @return packet light userdata, if bitstream param 
static int raknet_receive(lua_State* l)
{
	int iResSize = 1;
	assert(lua_gettop(l) > 3);
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	RakNet::Packet* pPacket = Peer->pPeer->Receive();
	if (!pPacket)
		lua_pushnil(l);
	else
	{
		*RAKSYSTEMADDRESS_CHECK(l, 2) = pPacket->systemAddress;
		*RAKGUID_CHECK(l, 3) = pPacket->guid;
		lua_pushlightuserdata(l, pPacket);

		if ( lua_type(l, 4) == LUA_TUSERDATA)
			RAKBITSTREAM_RECREATE(l, 4, Peer->iMetaBitStream_Ref, pPacket->data, pPacket->length, false);
		else
		{
			lua_pushlightuserdata(l, pPacket->data);
			lua_pushnumber(l, pPacket->length);
			iResSize += 2;
		}
		
	}
	return iResSize;
}

//--------------------------------------
// Raknet deallocate received packet
// @param Raknet Userdata
// @param Packet lightuserdata
// @return
static int raknet_packet_deallocate(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TLIGHTUSERDATA );
	RAKPEER_CHECK(l, 1)->pPeer->DeallocatePacket((RakNet::Packet*)lua_touserdata(l, 2));
	return 0;
}


//--------------------------------------
// Raknet get maximum connection allowed
// @param Raknet Userdata
// @return integer connections
static int raknet_get_maximum_peers( lua_State* l )
{
	lua_pushnumber(l, RAKPEER_CHECK(l,1)->pPeer->GetMaximumNumberOfPeers() );
	return 1;
}

//--------------------------------------
// Raknet close connection
// @param Raknet Userdata
// @param RaknetGuid or System Address or Guid number
// @param Disconnect notification
// @param Ordering channel
// @param Packet Priority

static int raknet_close_connection(lua_State* l)
{
	assert(lua_gettop(l) > 4);
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	bool     bNotification  = lua_toboolean(l, 3);
	unsigned char ucChannel = lua_tointeger(l, 4);
	PacketPriority ePriority = (PacketPriority)lua_tointeger(l, 5);
	int iType = lua_type(l,2);
	
	if ( iType == LUA_TUSERDATA )
	{
		void*    pGuidOrSysAddr = lua_touserdata(l, 2);
		if (((RakNet::NetObjectType*)pGuidOrSysAddr)->ucType == RAK_MAGIC_SYSTEM_ADDR)
			Peer->pPeer->CloseConnection((*((RakNet::SystemAddress*)pGuidOrSysAddr)), bNotification, ucChannel, ePriority);
		else
			Peer->pPeer->CloseConnection((*((RakNet::RakNetGUID*)pGuidOrSysAddr)), bNotification, ucChannel, ePriority);
	}
	else if ( iType == LUA_TNUMBER )
	{
		RakNet::RakNetGUID Guid( (uint64_t)lua_tonumber(l,2));
		Peer->pPeer->CloseConnection(Guid, bNotification, ucChannel, ePriority);
	}

	return 0;
}

//--------------------------------------
// Raknet Cancel connection attempt
// @param Raknet Userdata
// @param System Address
static int raknet_cancel_connection_attempt(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA );
	RAKPEER_CHECK(l, 1)->pPeer->CancelConnectionAttempt(*RAKSYSTEMADDRESS_CHECK(l, 2));
	return 0;
}

//--------------------------------------
// Raknet Get connection state
// @param Raknet Userdata
// @param RaknetGuid or System Address or Guid number
static int raknet_get_connection_state(lua_State* l)
{
	assert(lua_gettop(l) > 1 && ( lua_type(l,2) == LUA_TNUMBER || lua_type(l,2) == LUA_TUSERDATA) );
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	if ( lua_type(l,2) == LUA_TUSERDATA )
	{
		void*    pGuidOrSysAddr = lua_touserdata(l, 2);
		if (((RakNet::NetObjectType*)pGuidOrSysAddr)->ucType == RAK_MAGIC_SYSTEM_ADDR)
			lua_pushnumber(l, Peer->pPeer->GetConnectionState((*((RakNet::SystemAddress*)pGuidOrSysAddr))));
		else
			lua_pushnumber(l, Peer->pPeer->GetConnectionState((*((RakNet::RakNetGUID*)pGuidOrSysAddr))));
	}
	else
	{
		RakNet::RakNetGUID Guid( (uint64_t) lua_tonumber(l,2) );
		lua_pushnumber(l, Peer->pPeer->GetConnectionState( Guid ));
	}
	return 1;
}

//--------------------------------------
// Raknet Get system address index
// @param Raknet Userdata
// @param System Address
// @return number, index
static int raknet_get_index_from_system_addr(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA );
	lua_pushnumber(l, RAKPEER_CHECK(l, 1)->pPeer->GetIndexFromSystemAddress(*RAKSYSTEMADDRESS_CHECK(l, 2)));
	return 1;
}

//--------------------------------------
// Raknet add ip address to bannlist
// @param Raknet Userdata
// @param Host address
// @param timeout
static int raknet_add_to_ban_list(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TSTRING && lua_type(l,3) == LUA_TNUMBER );
	RAKPEER_CHECK(l, 1)->pPeer->AddToBanList(lua_tostring(l, 2), lua_tointeger(l, 3));
	return 0;
}

//--------------------------------------
// Raknet add ip address to bannlist
// @param Raknet Userdata
// @param Host address
static int raknet_remove_from_ban_list(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TSTRING );
	RAKPEER_CHECK(l, 1)->pPeer->RemoveFromBanList(lua_tostring(l, 2));
	return 0;
}

//--------------------------------------
// Raknet clear bann list
// @param Raknet Userdata
static int raknet_clear_ban_list(lua_State* l)
{
	RAKPEER_CHECK(l, 1)->pPeer->ClearBanList();
	return 0;
}

//--------------------------------------
// Raknet Get Ip address banned
// @param Raknet Userdata
// @param Host
// @return boolean
static int raknet_is_ip_banned(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TSTRING );
	lua_pushboolean( l, RAKPEER_CHECK(l, 1)->pPeer->IsBanned( lua_tostring(l,2)));
	return 1;
}

//--------------------------------------
// Raknet Limit Ip Connection Frequency
// @param Raknet Userdata
// @param bool
static int raknet_limit_ip_conn_freq(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TBOOLEAN );
	RAKPEER_CHECK(l, 1)->pPeer->SetLimitIPConnectionFrequency(lua_toboolean(l,2));
	return 0;
}

//--------------------------------------
// Raknet ping system address
// @param Raknet Userdata
// @param System address
static int raknet_ping(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA);
	RAKPEER_CHECK(l, 1)->pPeer->Ping(*RAKSYSTEMADDRESS_CHECK(l, 2));
	return 0;
}

//--------------------------------------
// Raknet get ping
// @param Raknet Userdata
// @param System address
// @param Average,last, lowest ping
static int raknet_get_ping(lua_State* l)
{
	assert(lua_gettop(l) > 1);
	RakNet::RakPeer* Peer = RAKPEER_CHECK(l, 1)->pPeer;
	RakNet::SystemAddress& SystemAddress = *RAKSYSTEMADDRESS_CHECK(l, 2);
	lua_pushnumber(l, Peer->GetAveragePing(SystemAddress));
	lua_pushnumber(l, Peer->GetLastPing(SystemAddress));
	lua_pushnumber(l, Peer->GetLowestPing(SystemAddress));
	return 3;
}

//--------------------------------------
// Raknet ping host
// @param Raknet Userdata
// @param Host, string
// @param Port, int
// @param OnlyReplayAcceptConnection
// @param Socket index
// @return Success, bool
static int raknet_ping_host(lua_State* l)
{
	assert(lua_gettop(l) > 4 && lua_type(l,2) == LUA_TSTRING && lua_type(l,2) == LUA_TNUMBER && lua_type(l,2) == LUA_TBOOLEAN && lua_type(l,2) == LUA_TNUMBER);
	lua_pushboolean(l, RAKPEER_CHECK(l, 1)->pPeer->Ping(lua_tostring(l, 2),lua_tointeger(l, 3),lua_toboolean(l, 4),lua_tointeger(l, 5)));
	return 1;
}

//--------------------------------------
// Raknet set ocasional ping
// @param Raknet Userdata
// @param Value, bool
static int raknet_set_occasional_ping(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TBOOLEAN );
	RAKPEER_CHECK(l, 1)->pPeer->SetOccasionalPing(lua_toboolean(l, 2));
	return 0;
}

//--------------------------------------
// Raknet get clock diff
// @param Raknet Userdata
// @param System address or guid or guid number
// @return number
static int raknet_get_clock_diff(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA);

	if ( lua_type(l,2) == LUA_TUSERDATA )
	{
		void* pGuidOrSysAddr = lua_touserdata(l,2);	
		if (((RakNet::NetObjectType*)pGuidOrSysAddr)->ucType == RAK_MAGIC_SYSTEM_ADDR)
			lua_pushnumber(l, RAKPEER_CHECK(l, 1)->pPeer->GetClockDifferential((*((RakNet::SystemAddress*)pGuidOrSysAddr))));
		else
			lua_pushnumber(l, RAKPEER_CHECK(l, 1)->pPeer->GetClockDifferential((*((RakNet::RakNetGUID*)pGuidOrSysAddr))));
	}
	else
	{
			RakNet::RakNetGUID Guid( (uint64_t)lua_tonumber(l,2) );
			lua_pushnumber(l, RAKPEER_CHECK(l, 1)->pPeer->GetClockDifferential( Guid ));
	}
	
	return 1;
}

//--------------------------------------
// Raknet set offline ping response
// @param Raknet Userdata
// @param Bitstream with stored data
// @return
static int raknet_set_offline_ping_response(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA );
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l, 2);
	RAKPEER_CHECK(l, 1)->pPeer->SetOfflinePingResponse((const char *)pBitStream->GetData(), pBitStream->GetNumberOfBytesUsed());
	return 0;
}

//--------------------------------------
// Raknet Get offline ping response
// @param Raknet Userdata
// @param Bitstream where data pushed
// @return success, bool
static int raknet_get_offline_ping_response(lua_State* l)
{
	assert(lua_gettop(l) > 1);
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	char* pData = nullptr;
	unsigned int uiSize = 0;
	Peer->pPeer->GetOfflinePingResponse(&pData, &uiSize);
	if (uiSize == 0)
	{
		lua_pushboolean(l, false);
		return 1;
	}
	lua_pushboolean(l, true);
	RakNet::BitStream* pBitStream = RAKBITSTREAM_RECREATE(l, 2, Peer->iMetaBitStream_Ref, (unsigned char*) pData, uiSize, true );
	return 1;
}


//--------------------------------------
///Raknet Get internal id
// @param Raknet Peer
// @param System address
// @param Internal index, max. MAXIMUM_NUMBER_OF_INTERNAL_IDS
// @param Result system address
static int raknet_get_internal_id(lua_State* l)
{
	assert(lua_gettop(l) > 3 && lua_type(l,2) == LUA_TUSERDATA && lua_type(l,3) == LUA_TNUMBER && lua_type(l,4) == LUA_TUSERDATA );
	*RAKSYSTEMADDRESS_CHECK(l,4) = RAKPEER_CHECK(l, 1)->pPeer->GetInternalID( *RAKSYSTEMADDRESS_CHECK(l,2), lua_tonumber(l,3) );
	return 0;
}

//--------------------------------------
///Raknet Get external id
// @param Raknet Peer
// @param System address
// @param Result system address
static int raknet_get_external_id(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TUSERDATA && lua_type(l,3) == LUA_TUSERDATA );
	*RAKSYSTEMADDRESS_CHECK(l,3) = RAKPEER_CHECK(l, 1)->pPeer->GetExternalID( *RAKSYSTEMADDRESS_CHECK(l,2) );
	return 0;
}

//--------------------------------------
///Raknet Get my bound address
// @param Raknet Peer
// @param Socket index
// @param Result system address
static int raknet_get_my_bound_address(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TUSERDATA );
	*RAKSYSTEMADDRESS_CHECK(l,3) = RAKPEER_CHECK(l, 1)->pPeer->GetMyBoundAddress( lua_tonumber(l,2) );
	return 0;
}

//--------------------------------------
///Raknet Get guid from system address
// @param Raknet Peer
// @param SystemAddress
// @param Result guid
static int raknet_get_guid_from_address(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TUSERDATA && lua_type(l,3) == LUA_TUSERDATA );
	*RAKGUID_CHECK(l,3) = RAKPEER_CHECK(l, 1)->pPeer->GetGuidFromSystemAddress( *RAKSYSTEMADDRESS_CHECK(l,2) );
	return 0;
}


//--------------------------------------
///Raknet Get system address from guid
// @param Raknet Peer
// @param Guid
// @param Result system address
static int raknet_get_system_address_from_guid(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TUSERDATA && lua_type(l,3) == LUA_TUSERDATA );
	*RAKSYSTEMADDRESS_CHECK(l,3) = RAKPEER_CHECK(l, 1)->pPeer->GetSystemAddressFromGuid( *RAKGUID_CHECK(l,2) );
	return 0;
}

//--------------------------------------
///Raknet Get client public key from system address
// @param Raknet Peer
// @param System Address
// @result Hex Public key
static int raknet_get_client_public_key(lua_State* l)
{
	char Key[256];
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA);
	char pkey[DRaknetPublickKeySize];
	RAKPEER_CHECK(l, 1)->pPeer->GetClientPublicKeyFromSystemAddress( *RAKSYSTEMADDRESS_CHECK(l,2), pkey );
	get_key_from_lua(pkey, Key, DRaknetPublickKeySize );
	lua_pushstring(l, Key);
	return 1;
}

//--------------------------------------
///Raknet Set system timeout time
// @param Raknet Peer
// @param Timeout time
// @param System address
static int raknet_set_timeout_time(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TUSERDATA );
	RAKPEER_CHECK(l, 1)->pPeer->SetTimeoutTime( lua_tointeger(l,2), *RAKSYSTEMADDRESS_CHECK(l,3) );
	return 0;
}

//--------------------------------------
///Raknet Get system timeout time
// @param Raknet Peer
// @param System address
// @return Timeout time
static int raknet_get_timeout_time(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA );
	lua_pushnumber(l, RAKPEER_CHECK(l, 1)->pPeer->GetTimeoutTime( *RAKSYSTEMADDRESS_CHECK(l,3) ));
	return 1;
}

//--------------------------------------
///Raknet Get mtu size
// @param Raknet Peer
// @param System address
// @return int, mtu size
static int raknet_get_mtu_size(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TUSERDATA );
	lua_pushnumber(l, RAKPEER_CHECK(l, 1)->pPeer->GetMTUSize( *RAKSYSTEMADDRESS_CHECK(l,3) ));
	return 1;
}

//--------------------------------------
///Raknet Get number of address
// @param Raknet Peer
// @return int, size
static int raknet_get_addresses(lua_State* l)
{
	assert(lua_gettop(l) > 0 );
	lua_pushnumber(l, RAKPEER_CHECK(l, 1)->pPeer->GetNumberOfAddresses());
	return 1;
}

//--------------------------------------
///Raknet Get Local ip
// @param Raknet Peer
// @param int, index
// @return string, op
static int raknet_get_local_ip(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	lua_pushstring(l, RAKPEER_CHECK(l, 1)->pPeer->GetLocalIP( lua_tointeger(l,2) ));
	return 1;
}


//--------------------------------------
///Raknet is local ip
// @param Raknet Peer
// @param str, ip address
// @return bool
static int raknet_is_local_ip(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TSTRING );
	lua_pushboolean(l, RAKPEER_CHECK(l, 1)->pPeer->IsLocalIP( lua_tostring(l,2) ));
	return 1;
}

//--------------------------------------
///Raknet allow connection ip migration
// @param Raknet Peer
// @param bool
static int raknet_allow_connection_ip_migration(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TBOOLEAN );
	RAKPEER_CHECK(l, 1)->pPeer->AllowConnectionResponseIPMigration( lua_toboolean(l,2));
	return 0;
}

//--------------------------------------
///Raknet advertise system
// @param Raknet Peer
// @param host
// @param remoteport
// @param bitstream
// @param connection socket index
// @retur bool
static int raknet_advertise_system(lua_State* l)
{
	assert(lua_gettop(l) > 4 && lua_type(l,2) == LUA_TSTRING && lua_type(l,3) == LUA_TNUMBER &&  lua_type(l,4) == LUA_TUSERDATA && lua_type(l,5) == LUA_TNUMBER );
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l,4);
	const char* pData = (const char*) pBitStream->GetData();
	int iDataSize = pBitStream->GetNumberOfBytesUsed();
	lua_pushboolean( l, RAKPEER_CHECK(l, 1)->pPeer->AdvertiseSystem( lua_tostring(l,2), lua_tointeger(l,3), pData, iDataSize, lua_tointeger(l,5) ));
	return 1;
}


//--------------------------------------
///Raknet split message interval
// @param Raknet Peer
// @param int, interval
static int raknet_split_message_interval(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	RAKPEER_CHECK(l, 1)->pPeer->SetSplitMessageProgressInterval( lua_toboolean(l,2));
	return 0;
}

//--------------------------------------
///Raknet get split message interval
// @param Raknet Peer
// @return int, interval
static int raknet_get_split_message_interval(lua_State* l)
{
	lua_pushnumber( l, RAKPEER_CHECK(l, 1)->pPeer->GetSplitMessageProgressInterval());
	return 1;
}
//--------------------------------------
///Raknet set unreliable timeout
// @param Raknet Peer
// @param timeout time ms
static int raknet_set_unrealible_timeout(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	RAKPEER_CHECK(l, 1)->pPeer->SetUnreliableTimeout( (RakNet::TimeMS) lua_tointeger(l,2));
	return 0;
}

//--------------------------------------
///Raknet send message to host
// @param Raknet Peer
// @param string, host
// @param int, remote port
// @param int ttl
// @param socket index
static int raknet_send_ttl(lua_State* l)
{
	assert(lua_gettop(l) > 4 && lua_type(l,2) == LUA_TSTRING && lua_type(l,3) == LUA_TNUMBER && lua_type(l,4) == LUA_TNUMBER && lua_type(l,5) == LUA_TNUMBER );
	RAKPEER_CHECK(l, 1)->pPeer->SendTTL( lua_tostring(l,2), lua_tointeger(l,3), lua_tointeger(l,4), lua_tointeger(l,5));
	return 0;
}

//--------------------------------------
///Raknet Set internal id
// @param Raknet Peer
// @param System address
// @param Internal index, max. MAXIMUM_NUMBER_OF_INTERNAL_IDS
static int raknet_set_internal_id(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TUSERDATA && lua_type(l,3) == LUA_TNUMBER );
	RAKPEER_CHECK(l, 1)->pPeer->SetInternalID( *RAKSYSTEMADDRESS_CHECK(l,2), lua_tonumber(l,3) );
	return 0;
}

//--------------------------------------
///Raknet attach light userdata plugin
// @param Raknet Userdata
// @param plugin
static int raknet_plugin_attach(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TLIGHTUSERDATA );
	RAKPEER_CHECK(l, 1)->pPeer->AttachPlugin( (RakNet::PluginInterface2*)lua_touserdata(l,2) );
	return 0;
}

//--------------------------------------
///Raknet detach light userdata plugin
// @param Raknet Userdata
// @param plugin
static int raknet_plugin_detach(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TLIGHTUSERDATA );
	RAKPEER_CHECK(l, 1)->pPeer->DetachPlugin( (RakNet::PluginInterface2*)lua_touserdata(l,2));
	return 0;
}

//--------------------------------------
///Raknet Allocate new packet with specified size
// @param Raknet Userdata
// @param int, size
// @return light userdata, packet
static int raknet_allocate_packet(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	lua_pushlightuserdata( l,  RAKPEER_CHECK(l, 1)->pPeer->AllocatePacket( lua_tointeger(l,2) ));
	return 1;
}

//--------------------------------------
///Raknet Push back packet
// @param Raknet Userdata
// @param light userdata, packet
// @param push back at head
static int raknet_pushback_packet(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TLIGHTUSERDATA && lua_type(l,3) == LUA_TBOOLEAN );
	RAKPEER_CHECK(l, 1)->pPeer->PushBackPacket( (RakNet::Packet*)lua_touserdata(l,2), lua_toboolean(l,3));
	return 0;
}


//--------------------------------------
///Raknet Apply network simulator
// @param Raknet Userdata
// @param packet loss,  range 0-1
// @param min extra ping
// @param extra ping variance
static int raknet_apply_network_simulator(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TNUMBER && lua_type(l,4) == LUA_TNUMBER  );
	assert( lua_tonumber(l,2) >= 0 && lua_tonumber(l,2) <= 1 );
	RAKPEER_CHECK(l, 1)->pPeer->ApplyNetworkSimulator( lua_tonumber(l,2), lua_tointeger(l,3), lua_tointeger(l,4) );
	return 0;
}


//--------------------------------------
///Raknet Set peer outgoing bandwith limit
// @param Raknet Userdata
// @param int, Max. bits per second
static int raknet_set_peer_outgoing_bandwith_limit(lua_State* l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER );
	RAKPEER_CHECK(l, 1)->pPeer->SetPerConnectionOutgoingBandwidthLimit( lua_tointeger(l,2) );
	return 0;
}

//--------------------------------------
///Raknet receive puffer size
// @param Raknet Userdata
// @param awaiting packagets size
static int raknet_get_receive_buffer_size(lua_State* l)
{
	lua_pushnumber(l,RAKPEER_CHECK(l, 1)->pPeer->GetReceiveBufferSize());
	return 1;
}

//--------------------------------------
// Raknet get awaiting packagets
// @param Raknet Userdata
// @return bool, networks simulator state
static int raknet_network_simulator_active(lua_State* l)
{
	lua_pushboolean( l, RAKPEER_CHECK(l, 1)->pPeer->IsNetworkSimulatorActive());
	return 1;
}

//--------------------------------------
// Raknet get connections
// @param Raknet Userdata
// @param index
// @param Raknet system address object
// @param Raknet guid object
static int raknet_get_connection(lua_State* l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TUSERDATA && lua_type(l,4) == LUA_TUSERDATA );
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	int iIndex = lua_tointeger(l, 2);
	*RAKSYSTEMADDRESS_CHECK(l, 3) = Peer->Connections.addresses.Get(iIndex);
	*RAKGUID_CHECK(l,4) = Peer->Connections.guids.Get(iIndex);
	return 0;
}



static void convert_raknet_stat( lua_State* l, RakNet::RakNetStatistics& Stat, int iMode, int iLevel, char* cBuffer )
{
	if ( iMode == 1 )
	{
		RakNet::StatisticsToString(&Stat, cBuffer, iLevel );
		lua_pushstring(l,cBuffer);
	}
	else if ( iMode == 2)
	{
		RakNetHelper::StatisticsToLuaTable( l, &Stat, iLevel );
	}
	else
		lua_pushnil(l);
}

//--------------------------------------
// Raknet get statistics
// @param Raknet Userdata
// @param mode ( 1-string, 2-table )
// @param index or system address
// @param verbosity level
// @return string or talbe or json string
static int raknet_get_raknet_statistics(lua_State* l)
{
	assert( lua_gettop(l) > 3 && lua_type(l,2) == LUA_TNUMBER && ( lua_type(l,3) == LUA_TNUMBER || lua_type(l,3) == LUA_TUSERDATA ) && lua_type(l,4) == LUA_TNUMBER );

	RakNet::RakNetStatistics Statistics;
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	bool bSuccess = false;
	if ( lua_type(l,3) == LUA_TUSERDATA )
		bSuccess = Peer->pPeer->GetStatistics( *RAKSYSTEMADDRESS_CHECK(l,3), &Statistics );
	else
		bSuccess = Peer->pPeer->GetStatistics( lua_tointeger(l,3), &Statistics );

	if ( bSuccess )
		convert_raknet_stat( l, Statistics, lua_tointeger(l,2), lua_tointeger(l,4), Peer->cTempBuffer );
	else
		lua_pushnil(l);
	
	return 1;
}


//---------------------------------------------------------------------------
// Raknet metatable
//---------------------------------------------------------------------------

static const struct luaL_Reg raknet_metatable[] = {
	{"startup", raknet_startup },
	{"shutdown", raknet_shutdown },
	{"initialize_security", raknet_init_security },
	{"disable_security", raknet_disable_securiuty },
	{"add_to_security_exception_list", raknet_add_to_exception_list },
	{"remove_from_security_exception_list", raknet_add_to_exception_list },
	{"is_in_security_exception_list", raknet_is_in_exception_list },
	{"set_max_incoming_connection", raknet_set_max_inc_connection },
	{"get_max_incoming_connection", raknet_get_max_inc_connection },
	{"number_of_connections", raknet_number_of_connections },
	{"set_incoming_password", raknet_set_inc_password },
	{"get_incoming_password", raknet_get_inc_password },
	{"connect", raknet_connect },
	{"get_connection_list", raknet_get_connection_list },
	{"get_connnection", raknet_get_connection },
	{"clear_connections", raknet_clear_connections },
	// connect with socket
	{"is_active", raknet_is_active },
	{"get_next_send_receipt", raknet_get_next_send_receipt },
	{"inc_next_send_receipt", raknet_inc_next_send_receipt },
	// send data
	{"send", raknet_send },
	{"send_loopback", raknet_send_loopback },
	{"packet_receive", raknet_receive },
	{"packet_deallocate", raknet_packet_deallocate },
	{"get_maximum_peers", raknet_get_maximum_peers },
	{"close_connection", raknet_close_connection },
	{"cancel_connection_attempt", raknet_cancel_connection_attempt },
	{"get_connection_state", raknet_get_connection_state },
	{"get_index_from_system_address", raknet_get_index_from_system_addr },
	{"bann_add", raknet_add_to_ban_list },
	{"bann_remove", raknet_remove_from_ban_list },
	{"bann_clear", raknet_clear_ban_list },
	{"is_banned", raknet_is_ip_banned },
	{"set_limit_ipconn_freq", raknet_limit_ip_conn_freq },
	{"ping", raknet_ping },
	{"ping_host", raknet_ping_host },
	{"get_ping", raknet_get_ping },
	{"set_occasional_ping", raknet_set_occasional_ping},
	{"get_clock_diff", raknet_get_clock_diff },
	{"set_offline_ping_response", raknet_set_offline_ping_response },
	{"get_offline_ping_response", raknet_get_offline_ping_response },
	{"get_internal_id", raknet_get_internal_id },
	{"set_internal_id", raknet_set_internal_id },
	{"get_external_id", raknet_get_external_id },
	{"get_my_bound_address",raknet_get_my_bound_address},
	{"get_guid_from_system_address",raknet_get_guid_from_address},
	{"get_system_address_from_guid",raknet_get_system_address_from_guid },
	{"get_client_public_key", raknet_get_client_public_key },
	{"set_timeout_time", raknet_set_timeout_time },
	{"get_timeout_time", raknet_get_timeout_time },
	{"plugin_attach",raknet_plugin_attach },
	{"plugin_detach",raknet_plugin_detach },
	{"get_mtu_size",raknet_get_mtu_size },
	{"get_number_of_addresses", raknet_get_addresses },
	{"get_local_ip", raknet_get_local_ip },
	{"is_local_ip", raknet_is_local_ip },
	{"allow_connection_ipmigration", raknet_allow_connection_ip_migration },
	{"advertise_system", raknet_advertise_system },
	{"split_message_interval", raknet_get_split_message_interval},
	{"get_split_message_interval", raknet_get_split_message_interval },
	{"set_unrealiable_timeout", raknet_set_unrealible_timeout },
	{"send_ttl", raknet_send_ttl },
	{"packet_push_back",raknet_pushback_packet },
	{"packet_allocate", raknet_allocate_packet }, 
	// get sockets
	// release sockets
	{"apply_network_simulator", raknet_apply_network_simulator },
	{"set_outgoing_bandwidth_limit", raknet_set_peer_outgoing_bandwith_limit },
	{"is_net_simulator_active", raknet_network_simulator_active },
	{"get_statistics", raknet_get_raknet_statistics },
	{"get_receive_buffer_size", raknet_get_receive_buffer_size },

	{NULL, NULL}
};

void luaopen_raknet_metatable( lua_State *l )
{
	luaL_newmetatable(l, DRaknetMetaName);
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_metatable);
	lua_setfield(l, -2, "__index");
	lua_pushcfunction(l, raknet_gc);
	lua_setfield(l, -2, "__gc");
}

//---------------------------------------------------------------------------
// Raknet module functions
//---------------------------------------------------------------------------

static int raknet_module_new_peer( lua_State* l)
{
	RAKPEER* Peer = (RAKPEER*)lua_newuserdata(l, sizeof(RAKPEER));
	if (!Peer)
	{
		lua_pushnil(l);
		return 1;
	}
		
	RAKPEER_INIT(Peer);
	RAKPEER_CREATEPEER(Peer);
	luaL_getmetatable(l, DRaknetMetaName );
	lua_setmetatable(l, -2);

	// meta table cache
	luaL_getmetatable(l, DRaknetSocketDescriptorMeta);
	Peer->iMetaSocketeDescriptor_Ref = luaL_ref(l, LUA_REGISTRYINDEX);
	
	luaL_getmetatable(l, DRaknetPublicKeyMeta);
	Peer->iMetaPublicKey_Ref = luaL_ref(l, LUA_REGISTRYINDEX);
	
	luaL_getmetatable(l, DRaknetSystemAddressMeta);
	Peer->iMetaSystemAddress_Ref = luaL_ref(l, LUA_REGISTRYINDEX);

	luaL_getmetatable(l, DRaknetGuidMeta);
	Peer->iMetaGuid_Ref = luaL_ref(l, LUA_REGISTRYINDEX);
	
	luaL_getmetatable(l, DRaknetBitStreamMeta);
	Peer->iMetaBitStream_Ref = luaL_ref(l, LUA_REGISTRYINDEX);

	return 1;
}

static int raknet_module_new_descriptors( lua_State* l)
{
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	RAKSOCKETDESCRIPTOR_NEW(l, Peer->iMetaSocketeDescriptor_Ref );
	return 1;
}

static int raknet_module_new_public_key( lua_State* l)
{
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	RAKSECURITY_NEW(l, Peer->iMetaPublicKey_Ref );
	return 1;
}

static int raknet_module_new_system_address( lua_State* l)
{
	RAKPEER* Peer = RAKPEER_CHECK(l,1);
	int iTop = lua_gettop(l);
	const char* sHost = iTop > 1 ? lua_tostring(l,2) : nullptr;
	int iPort = iTop > 2 ? lua_tointeger(l,3) : 0;
	RakNet::SystemAddress* pAddress = RAKSYSTEMADDRESS_NEW(l, Peer->iMetaSystemAddress_Ref, sHost, iPort );
	return 1;
}

static int raknet_module_new_guid(lua_State* l)
{
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	int iTop = lua_gettop(l);
	int iGuid = iTop > 1 ? lua_tointeger(l, 2) : -1;
	RakNet::RakNetGUID* pGuid = RAKGUID_NEW(l, Peer->iMetaGuid_Ref, iGuid );
	return 1;
}

/// Create new bitstream
//  @param Packet or UserData value or string
//  @param number if first param is userdata, or string
static int raknet_module_new_bitstream(lua_State* l)
{
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	int iTop = lua_gettop(l);
	int iType = lua_type(l, 1);
	RakNet::BitStream* pBitStream = nullptr;
	if ( iTop > 1 && iType == LUA_TSTRING )
	{		
		RakNet::RakString strData = lua_tostring(l, 1);
		int iCmdSize = lua_tointeger(l, 2);
		pBitStream = RAKBITSTREAM_NEW(l, Peer->iMetaBitStream_Ref, nullptr, 0, false );
		pBitStream->IgnoreBytes(iCmdSize);
		pBitStream->Write<RakNet::RakString>(strData);
	}
	else if (iTop > 1 && iType == LUA_TLIGHTUSERDATA )
	{
		void* pUserData = lua_touserdata(l, 1);
		int iSize = lua_tointeger(l, 2);
		pBitStream = RAKBITSTREAM_NEW(l, Peer->iMetaBitStream_Ref, (unsigned char*)pUserData, iSize, true );
	}
	else if (iTop == 1 && iType == LUA_TLIGHTUSERDATA)
	{
		RakNet::Packet* pPacket = (RakNet::Packet*)lua_touserdata(l, 1);
		pBitStream = RAKBITSTREAM_NEW(l, Peer->iMetaBitStream_Ref, pPacket->data, pPacket->length, true);
	}
	else if (iTop == 1 && iType == LUA_TNUMBER)
	{
		pBitStream = RAKBITSTREAM_NEW(l, Peer->iMetaBitStream_Ref, nullptr, lua_tointeger(l,1), true );
	}
	else
	{
		assert(false);
	}
	
	return 1;
}

static int raknet_module_unassigned_player_index(lua_State* l)
{
	lua_pushnumber(l, RakNet::UNASSIGNED_PLAYER_INDEX);
	return 1;
}

static int raknet_module_unassigned_network_id(lua_State* l)
{
	lua_pushnumber(l, RakNet::UNASSIGNED_NETWORK_ID);
	return 1;
}

static int raknet_module_sleep(lua_State* l)
{
	assert(lua_gettop(l) > 0 && lua_type(l,1) == LUA_TNUMBER );
	RakSleep( lua_tointeger(l,1));
	return 0;
}

static int raknet_module_get_time_ms(lua_State* l)
{
	lua_pushnumber(l, RakNet::GetTimeMS());
	return 1;
}

static int raknet_module_get_time_us(lua_State* l)
{
	lua_pushnumber(l, RakNet::GetTimeUS());
	return 1;
}

#if LIBCAT_SECURITY==1
static int raknet_module_gen_key(lua_State* l)
{
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	cat::EasyHandshake::Initialize();
	cat::EasyHandshake handshake;
	RAKSECURITYKEY* pKey = RAKSECURITY_NEW(l, Peer->iMetaPublicKey_Ref);
	handshake.GenerateServerKey(pKey->PublicKey, pKey->PrivateKey);
	pKey->bPublicKey = true;
	pKey->bPrivateKey = true;
	return 1;
}
#endif

//---------------------------------------------------------------------------
// Default raknet module
//---------------------------------------------------------------------------

static const struct luaL_Reg raknet_module [] = {
	{"new_peer", raknet_module_new_peer },
	{"new_socket_descriptors", raknet_module_new_descriptors },
	{"new_public_key", raknet_module_new_public_key },
	{"new_system_address", raknet_module_new_system_address },
	{"new_guid", raknet_module_new_guid },
	{"new_bitstream", raknet_module_new_bitstream },	
	{"get_unassigned_player_index", raknet_module_unassigned_player_index },
	{"get_unassigned_network_id", raknet_module_unassigned_network_id },
	{"sleep", raknet_module_sleep },
	{"get_time", raknet_module_get_time_ms },
	{"get_time_us", raknet_module_get_time_us },

#if LIBCAT_SECURITY==1
	{"gen_secure_key", raknet_module_gen_key },
#endif

	{NULL, NULL}
};


//---------------------------------------------------------------------------
// Default raknet plugins
//---------------------------------------------------------------------------

/// Create new relay plugin
//  @function new_relay
//  @param RakPeer
//  @param bAutoAttach
//  @return RelayPlugin lightuserdata
//  @usage raknet_plugin.new_relay( Peer, true )
static int raknet_plugin_relay(lua_State* l)
{
	assert(lua_gettop(l) > 1 );
	RAKPEER* Peer = RAKPEER_CHECK(l, 1);
	bool     bAutoAttach = lua_toboolean(l,2);
	RakNet::PluginInterface2* pPlugin = RAKPLUGIN_RELAY_NEW(l, Peer );
	if ( bAutoAttach )
		Peer->pPeer->AttachPlugin(pPlugin);
	assert(pPlugin);
	return 1;
}

static const struct luaL_Reg raknet_plugins[] = {
	{"new_relay", raknet_plugin_relay },
	{ NULL, NULL }
};

void luaopen_raknet_module( lua_State *l )
{
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_module);
	lua_setglobal(l,DRaknetModuleName);

	luaL_register(l, nullptr, raknet_plugins);
	lua_setglobal(l, DRaknetPluginsName);
}


//---------------------------------------------------------------------------
// Default raknet registration
//---------------------------------------------------------------------------
int luaopen_raknet(lua_State *l)
{
	luaopen_raknet_metatable( l );
	luaopen_raknet_bitstream( l );
	luaopen_raknet_guid( l );
	luaopen_raknet_security_key( l );
	luaopen_socket_descriptor( l );
	luaopen_raknet_module( l );
	luaopen_raknet_relay( l );
	return 1;
}