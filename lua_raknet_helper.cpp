#include "lua_raknet_helper.h"
#include <assert.h>
#include "GetTime.h"
#pragma warning( disable : 4800 )
#pragma warning( disable : 4244 )

int RakNetHelper::GetFieldAsInteger(lua_State* l, const char* sName, const int iDefault)
{
	int iResult = iDefault;
	lua_pushstring(l, sName);
	lua_rawget(l, -2);
	int iType = lua_type(l, -1);
	if (iType == LUA_TNUMBER)
		iResult = lua_tointeger(l, -1);
	lua_pop(l, 1);
	return iResult;
}


const char* RakNetHelper::GetFieldAsString(lua_State* l, const char* sName, const char* sDefault)
{
	const char* sResult = sDefault;
	lua_pushstring(l, sName);
	lua_rawget(l, -2);
	int iType = lua_type(l, -1);
	if (iType == LUA_TSTRING)
		sResult = lua_tostring(l, -1);
	lua_pop(l, 1);
	return sResult;
}

bool RakNetHelper::GetFieldAsBool(lua_State* l, const char* sName, const bool bDefault)
{
	bool bResult = bDefault;
	lua_pushstring(l, sName);
	lua_rawget(l, -2);
	int iType = lua_type(l, -1);
	if (iType == LUA_TBOOLEAN)
		bResult = lua_toboolean(l, -1);
	lua_pop(l, 1);
	return bResult;
}

void* RakNetHelper::GetFieldAsUserData(lua_State* l, const char* sName, const char* sMetaName, void* pDefault )
{
	void* pResult = pDefault;
	lua_pushstring(l, sName);
	lua_rawget(l, -2);
	int iType = lua_type(l, -1);
	if (iType == LUA_TUSERDATA)
	{
#ifdef _DEBUG
		pResult = luaL_checkudata(l, -1, sMetaName );
#else
		pResult = lua_touserdata(l, -1);
#endif
		
	}
	lua_pop(l, 1);
	return pResult;
}

static int char2int(char input)
{
	if(input >= '0' && input <= '9')
		return input - '0';
	if(input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if(input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	assert(false);
	return 0;
}

void RakNetHelper::hex2bin(const char* src, char* target)
{
	while(*src && src[1])
	{
		*(target++) = char2int(*src)*16 + char2int(src[1]);
		src += 2;
	}
}

void RakNetHelper::StatisticsToLuaTable( lua_State* l, RakNet::RakNetStatistics *s, int verbosityLevel )
{
	if ( s == 0 )
	{
		lua_pushnil(l);
		return;
	}

	if (verbosityLevel >= 0)
	{
		lua_newtable(l);
		DSET_TABLE_NUMBER("bytes_per_sec_sent",s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::ACTUAL_BYTES_SENT]);
		DSET_TABLE_NUMBER("bytes_per_sec_received",s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::ACTUAL_BYTES_RECEIVED]);
		DSET_TABLE_NUMBER("average_packet_loss",s->packetlossLastSecond*100.0f);
	}

	if (verbosityLevel >= 1)
	{
		DSET_TABLE_NUMBER("user_msg_bytes_per_sec_pushed",s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_PUSHED]);
		
		DSET_TABLE_NUMBER("total_bytes_send",s->runningTotal[RakNet::RNSPerSecondMetrics::ACTUAL_BYTES_SENT]);
		DSET_TABLE_NUMBER("total_bytes_received",s->runningTotal[RakNet::RNSPerSecondMetrics::ACTUAL_BYTES_RECEIVED]);
		DSET_TABLE_NUMBER("total_msg_bytes_pushed",s->runningTotal[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_PUSHED]);

		DSET_TABLE_NUMBER("current_packet_loss",s->packetlossLastSecond*100.0f);
		DSET_TABLE_NUMBER("elapsed_time_in_sec",(uint64_t)((RakNet::GetTimeUS()-s->connectionStartTime)/1000000 ));
		
		if (s->BPSLimitByCongestionControl!=0)
		{
			DSET_TABLE_NUMBER("send_capacity_bytes",(long long unsigned int) s->BPSLimitByCongestionControl);
			DSET_TABLE_NUMBER("send_capacity_percent",100.0f * s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::ACTUAL_BYTES_SENT] / s->BPSLimitByCongestionControl);
		}

		if (s->BPSLimitByOutgoingBandwidthLimit!=0)
		{
			DSET_TABLE_NUMBER("send_limit_bytes",(long long unsigned int) s->BPSLimitByOutgoingBandwidthLimit);
			DSET_TABLE_NUMBER("send_limit_percent",100.0f * 100.0f * s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::ACTUAL_BYTES_SENT] / s->BPSLimitByOutgoingBandwidthLimit);
		}
	}	
	
	if (verbosityLevel >= 2)
	{
		DSET_TABLE_NUMBER("user_msg_bytes_per_sec_send",(long long unsigned int) s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_SENT]);
		DSET_TABLE_NUMBER("user_msg_bytes_per_sec_resent",(long long unsigned int) s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_RESENT]);
		DSET_TABLE_NUMBER("user_msg_bytes_per_sec_received_progressed",(long long unsigned int) s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_RECEIVED_PROCESSED]);
		DSET_TABLE_NUMBER("user_msg_bytes_per_sec_ignored",(long long unsigned int) s->valueOverLastSecond[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_RECEIVED_IGNORED]);
		
		DSET_TABLE_NUMBER("total_msg_bytes_sent",(long long unsigned int) s->runningTotal[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_SENT]);
		DSET_TABLE_NUMBER("total_msg_bytes_resent",(long long unsigned int) s->runningTotal[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_RESENT]);
		DSET_TABLE_NUMBER("total_msg_bytes_pushed",(long long unsigned int) s->runningTotal[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_PUSHED]);
		DSET_TABLE_NUMBER("total_msg_bytes_returned",(long long unsigned int) s->runningTotal[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_RECEIVED_PROCESSED]);
		DSET_TABLE_NUMBER("total_msg_bytes_ignored",(long long unsigned int) s->runningTotal[RakNet::RNSPerSecondMetrics::USER_MESSAGE_BYTES_RECEIVED_IGNORED]);

		DSET_TABLE_NUMBER("resend_buffer_messages",s->messagesInResendBuffer);
		DSET_TABLE_NUMBER("resend_buffer_bytes",(long long unsigned int) s->bytesInResendBuffer);

		DSET_TABLE_NUMBER("resend_buffer_m_immediate",s->messageInSendBuffer[PacketPriority::IMMEDIATE_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_m_hight",s->messageInSendBuffer[PacketPriority::HIGH_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_m_medium",s->messageInSendBuffer[PacketPriority::MEDIUM_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_m_low",s->messageInSendBuffer[PacketPriority::LOW_PRIORITY]);

		DSET_TABLE_NUMBER("resend_buffer_msg_immediate",s->messageInSendBuffer[PacketPriority::IMMEDIATE_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_msg_hight",s->messageInSendBuffer[PacketPriority::HIGH_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_msg_medium",s->messageInSendBuffer[PacketPriority::MEDIUM_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_msg_low",s->messageInSendBuffer[PacketPriority::LOW_PRIORITY]);

		DSET_TABLE_NUMBER("resend_buffer_bytes_immediate",s->messageInSendBuffer[PacketPriority::IMMEDIATE_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_bytes_hight",s->messageInSendBuffer[PacketPriority::HIGH_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_bytes_medium",s->messageInSendBuffer[PacketPriority::MEDIUM_PRIORITY]);
		DSET_TABLE_NUMBER("resend_buffer_bytes_low",s->messageInSendBuffer[PacketPriority::LOW_PRIORITY]);
	}
}