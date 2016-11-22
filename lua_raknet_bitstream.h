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

#define DRaknetBitStreamMeta ":raknet_bitstream:"
#define DRaknetBitStreamConst "bitstream"
#define DRaknetBitStreamPrintsBuffer 4096

inline RakNet::BitStream* RAKBITSTREAM_CHECK(lua_State* l, int iIndex);
inline RakNet::BitStream* RAKBITSTREAM_NEW(lua_State* l, int iMetaRef, unsigned char* pData, int iDataSize, bool bCopy);
inline RakNet::BitStream* RAKBITSTREAM_RECREATE(lua_State* l, int iIndex, int iMetaRef, unsigned char* pData, int iDataSize, bool bCopy);

struct SLuaBitstream
{
	enum EMode
	{
		m_normal = 1,
		m_compressed = 2,
		m_compressed_delta = 3,
	};

	enum EType
	{
		t_bit = 1,
		t_bool,
		t_byte,
		t_short,
		t_uint,
		t_int,
		t_double,
		t_float,
		t_string,
		
		t_vector = 20,
		t_normal_vector,
		t_guid,
		t_system_addr,
		t_bitstream,
		t_table
	};
};

int luaopen_raknet_bitstream(lua_State *l);