#include "lua_raknet_plugin_relay.h"
#include <assert.h>
#include "GetTime.h"
#include "lua_raknet_guid.h"
#include "lua_raknet_bitstream.h"
#include "RakNetTypes.h"
#include "lua_raknet_helper.h"

#pragma warning( disable : 4800 )
#pragma warning( disable : 4244 )

/// Raknet relay server plugin
// @module Relay plugin


RakNet::PluginInterface2* RAKPLUGIN_RELAY_NEW(lua_State *l, RAKPEER* Peer )
{
	RakNet::PluginInterface2* pPlugin = RakNet::RelayPlugin::GetInstance();
	lua_pushlightuserdata(l,pPlugin);
	luaL_newmetatable(l,DRaknetRelayMeta);
	lua_setmetatable(l,-2);
	return pPlugin;
}

RakNet::RelayPlugin* RAKPLUGIN_RELAY_CHECK(lua_State *l, int iIndex )
{
#ifdef _DEBUG
	assert(lua_gettop(l) > 0);
	RakNet::RelayPlugin* instance = *(RakNet::BitStream**)luaL_checkudata(l, iIndex, DRaknetRelayMeta);
	assert(instance != nullptr);
	if (!instance)
		luaL_error(l, "Invalid raknet relay meta at index : %d", iIndex);
	return instance;
#else
	return  (RakNet::RelayPlugin*)lua_touserdata(l, iIndex);
#endif
}

///Add Participant on server
// @function add_participant_srv
// @param relay light_user_data
// @param key string
// @param user guid
// @return relay_enum @see RelayPluginEnums
static int raknet_relay_add_participant_srv(lua_State *l)
{
	assert(lua_gettop(l) > 2 );
	lua_pushnumber(l, RAKPLUGIN_RELAY_CHECK(l,1)->AddParticipantOnServer( RakNet::RakString(lua_tostring(l,2)), *RAKGUID_CHECK(l,3)));
	return 1;
}

///Remove Participant on server
// @function remove_participant_srv
// @param relay light_user_data
// @param user guid
static int raknet_relay_remove_participant_srv(lua_State *l)
{
	assert(lua_gettop(l) > 1 );
	RAKPLUGIN_RELAY_CHECK(l,1)->RemoveParticipantOnServer( *RAKGUID_CHECK(l,3));
	return 0;
}

///Set accept add participant requests
// @function set_accept_participant_requests
// @param relay light_user_data
// @param accept boolean
static int raknet_relay_accept_participant_req(lua_State *l)
{
	assert(lua_gettop(l) > 1 );
	RAKPLUGIN_RELAY_CHECK(l,1)->SetAcceptAddParticipantRequests( lua_toboolean(l,2) );
	return 0;
}

///Add participant requests from client
// @function add_participant_req_from_client
// @param relay light_user_data
// @param key string
// @param server guid
static int raknet_relay_add_participant_req_client(lua_State *l)
{
	assert(lua_gettop(l) > 2 );
	RAKPLUGIN_RELAY_CHECK(l,1)->AddParticipantRequestFromClient( RakNet::RakString(lua_tostring(l,2)), *RAKGUID_CHECK(l,3));
	return 0;
}

///Remove participant request from client
// @function remove_participant_req_from_client
// @param relay light_user_data
// @param server guid
static int raknet_relay_remove_participant_req_client(lua_State *l)
{
	assert(lua_gettop(l) > 2 );
	RAKPLUGIN_RELAY_CHECK(l,1)->RemoveParticipantRequestFromClient( *RAKGUID_CHECK(l,2) );
	return 0;
}


///Send to participant
// @function send_to_participant
// @param relay light_user_data
// @param server guid
// @param dest_user guid
// @param bitstream user_data
// @param priority number
// @param reliability number
// @param channel number
static int raknet_relay_send_to_participant(lua_State *l)
{
	assert(lua_gettop(l) > 6 );
	RAKPLUGIN_RELAY_CHECK(l,1)->SendToParticipant(
		*RAKGUID_CHECK(l,2),
		RakNet::RakString(*RAKGUID_CHECK(l,3)->ToString()),
		RAKBITSTREAM_CHECK(l,4),
		(PacketPriority) lua_tointeger(l,5),
		(PacketReliability) lua_tointeger(l,6),
		lua_tointeger(l,7) );
	return 0;
}

///Send to group
// @function send_to_group
// @param relay light_user_data
// @param server guid
// @param bitstream user_data
// @param priority number
// @param reliability number
// @param channel number
static int raknet_relay_send_to_group(lua_State *l)
{
	assert(lua_gettop(l) > 5 );
	RAKPLUGIN_RELAY_CHECK(l,1)->SendGroupMessage(
		*RAKGUID_CHECK(l,2),
		RAKBITSTREAM_CHECK(l,3),
		(PacketPriority) lua_tointeger(l,4),
		(PacketReliability) lua_tointeger(l,5),
		(char)lua_tointeger(l,6) );
	return 0;
}

///Join group request
// @function join_group_request
// @param relay light_user_data
// @param server guid
// @param group_name string
static int raknet_relay_join_group_request(lua_State *l)
{
	assert(lua_gettop(l) > 2 );
	RAKPLUGIN_RELAY_CHECK(l,1)->JoinGroupRequest( *RAKGUID_CHECK(l,2), RakNet::RakString(lua_tostring(l,3)));
	return 0;
}

///Leave group
// @function leave_group
// @param relay light_user_data
// @param server guid
static int raknet_relay_leave_group(lua_State *l)
{
	assert(lua_gettop(l) > 1 );
	RAKPLUGIN_RELAY_CHECK(l,1)->LeaveGroup( *RAKGUID_CHECK(l,2) );
	return 0;
}

///Get group list
// @function leave_group
// @param relay light_user_data
// @param server guid
static int raknet_relay_get_groups(lua_State *l)
{
	assert(lua_gettop(l) > 1 );
	RAKPLUGIN_RELAY_CHECK(l,1)->GetGroupList( *RAKGUID_CHECK(l,2) );
	return 0;
}

static const struct luaL_Reg raknet_relay_meta[] = {
	{"add_participant_srv", raknet_relay_add_participant_srv },
	{"remove_participant_srv", raknet_relay_remove_participant_srv },
	{"set_accept_participant_requests", raknet_relay_accept_participant_req },
	{"add_participant_req_from_client", raknet_relay_add_participant_req_client },
	{"remove_participant_req_from_client", raknet_relay_remove_participant_req_client },
	{"send_to_participant", raknet_relay_send_to_participant },
	{"send_to_group", raknet_relay_send_to_group },
	{"join_group_request", raknet_relay_join_group_request },
	{"leave_group", raknet_relay_leave_group },
	{"get_groups", raknet_relay_get_groups },
	{ NULL, NULL }
};

static int luaopen_relay_const(lua_State *l)
{	

		// server
		DSET_TABLE_NUMBER( "message_to_server_from_client" , RakNet::RelayPluginEnums::RPE_MESSAGE_TO_SERVER_FROM_CLIENT)
		DSET_TABLE_NUMBER( "add_client_request_from_client" , RakNet::RelayPluginEnums::RPE_ADD_CLIENT_REQUEST_FROM_CLIENT)
		DSET_TABLE_NUMBER( "remove_client_request_from_client" , RakNet::RelayPluginEnums::RPE_REMOVE_CLIENT_REQUEST_FROM_CLIENT)
		DSET_TABLE_NUMBER( "group_message_from_client" , RakNet::RelayPluginEnums::RPE_GROUP_MESSAGE_FROM_CLIENT)
		DSET_TABLE_NUMBER( "join_group_request_from_client" , RakNet::RelayPluginEnums::RPE_JOIN_GROUP_REQUEST_FROM_CLIENT)
		DSET_TABLE_NUMBER( "leave_group_request_from_client" , RakNet::RelayPluginEnums::RPE_LEAVE_GROUP_REQUEST_FROM_CLIENT)
		DSET_TABLE_NUMBER( "get_group_list_request_from_client" , RakNet::RelayPluginEnums::RPE_GET_GROUP_LIST_REQUEST_FROM_CLIENT)
		
		// client
		DSET_TABLE_NUMBER( "message_to_client_from_server" , RakNet::RelayPluginEnums::RPE_MESSAGE_TO_CLIENT_FROM_SERVER)
		DSET_TABLE_NUMBER( "add_client_not_allowed" , RakNet::RelayPluginEnums::RPE_ADD_CLIENT_NOT_ALLOWED)
		DSET_TABLE_NUMBER( "add_client_target_not_connected" , RakNet::RelayPluginEnums::RPE_ADD_CLIENT_TARGET_NOT_CONNECTED)
		DSET_TABLE_NUMBER( "add_client_name_already_in_use" , RakNet::RelayPluginEnums::RPE_ADD_CLIENT_NAME_ALREADY_IN_USE)
		DSET_TABLE_NUMBER( "add_client_success" , RakNet::RelayPluginEnums::RPE_ADD_CLIENT_SUCCESS)
		DSET_TABLE_NUMBER( "user_entered_room" , RakNet::RelayPluginEnums::RPE_USER_ENTERED_ROOM)
		DSET_TABLE_NUMBER( "user_left_room" , RakNet::RelayPluginEnums::RPE_USER_LEFT_ROOM)
		DSET_TABLE_NUMBER( "group_msg_from_server" , RakNet::RelayPluginEnums::RPE_GROUP_MSG_FROM_SERVER)
		DSET_TABLE_NUMBER( "get_group_list_reply_from_server" , RakNet::RelayPluginEnums::RPE_GET_GROUP_LIST_REPLY_FROM_SERVER)
		DSET_TABLE_NUMBER( "join_group_success" , RakNet::RelayPluginEnums::RPE_JOIN_GROUP_SUCCESS)
		DSET_TABLE_NUMBER( "join_group_failure" , RakNet::RelayPluginEnums::RPE_JOIN_GROUP_FAILURE)
		
		return 1;
}

int luaopen_raknet_relay(lua_State *l)
{
	luaL_newmetatable(l, DRaknetRelayMeta);
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_relay_meta);
	lua_setfield(l, -2, "__index");

	lua_newtable( l );
	luaopen_relay_const( l );
	lua_setglobal( l, DRaknetRelayConst );

	return 1;
}