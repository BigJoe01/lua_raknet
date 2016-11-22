//----------------------------------------------------------
// Raknet lua helper
//----------------------------------------------------------
#pragma once
extern "C"
{
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}
#include "RakNetStatistics.h"

namespace RakNetHelper
{
	#define DSET_TABLE_NUMBER(NAME,VALUE) \
		lua_pushstring( l , NAME ); lua_pushnumber( l, VALUE ); lua_settable(l, -3 );

	#define DSET_TABLE_STRING(NAME,VALUE) \
		lua_pushstring( l , NAME ); lua_pushstring( l, VALUE ); lua_settable(l, -3 );

	void hex2bin(const char* src, char* target);

	int GetFieldAsInteger(lua_State* l, const char* sName, const int iDefault);
	const char* GetFieldAsString(lua_State* l, const char* sName, const char* sDefault);
	bool GetFieldAsBool(lua_State* l, const char* sName, const bool bDefault);
	void* GetFieldAsUserData(lua_State* l, const char* sName, const char* sMetaName, void* pDefault );

	void StatisticsToLuaTable( lua_State* l, RakNet::RakNetStatistics *s, int verbosityLevel );

}
