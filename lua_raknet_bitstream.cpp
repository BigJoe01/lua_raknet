#include "lua_raknet_bitstream.h"
#include "lua_raknet_guid.h"
#include "lua_raknet_system_address.h"
#include "lua_raknet_helper.h"
#include "BitStream.h"

#include <assert.h>

#pragma warning( disable : 4800 )
#pragma warning( disable : 4018 )
#pragma warning( disable : 4244 )

/// Raknet bitstream module
// @module BitStream

RakNet::BitStream* RAKBITSTREAM_CHECK(lua_State* l, int iIndex)
{
#ifdef _DEBUG
	assert(lua_gettop(l) > 0);
	RakNet::BitStream* instance = *(RakNet::BitStream**)luaL_checkudata(l, iIndex, DRaknetBitStreamMeta);
	assert(instance != nullptr);
	if (!instance)
		luaL_error(l, "Invalid raknet bitstream meta at index : %d", iIndex);
	return instance;
#else
	return  *(RakNet::BitStream**)lua_touserdata(l, iIndex);
#endif
}

RakNet::BitStream* RAKBITSTREAM_NEW(lua_State* l, int iMetaRef, unsigned char* pData, int iDataSize, bool bCopy )
{
	RakNet::BitStream** ppStream = (RakNet::BitStream**)lua_newuserdata(l, sizeof(RakNet::BitStream*));
	if (pData && iDataSize)
		*ppStream = new RakNet::BitStream(pData, iDataSize, bCopy);
	else if (!pData && iDataSize)
		*ppStream = new RakNet::BitStream(iDataSize);
	else
		*ppStream = new RakNet::BitStream();

	lua_rawgeti(l, LUA_REGISTRYINDEX, iMetaRef);
	lua_setmetatable(l, -2);
	return *ppStream;
}

RakNet::BitStream* RAKBITSTREAM_RECREATE(lua_State* l, int iIndex, int iMetaRef, unsigned char* pData, int iDataSize, bool bCopy)
{
#ifdef _DEBUG
	RakNet::BitStream** ppStream = (RakNet::BitStream**)luaL_checkudata(l, iIndex, DRaknetBitStreamMeta);
#else
	RakNet::BitStream** ppStream = (RakNet::BitStream**)lua_touserdata(l, iIndex);
#endif
	if (*ppStream)
		delete (RakNet::BitStream*)*ppStream;

	if (pData && iDataSize)
		*ppStream = new RakNet::BitStream(pData, iDataSize, bCopy);
	else if (!pData && iDataSize)
		*ppStream = new RakNet::BitStream(iDataSize);
	else
		*ppStream = new RakNet::BitStream();

	lua_rawgeti(l, LUA_REGISTRYINDEX, iMetaRef);
	lua_setmetatable(l, -2);
	return *ppStream;
}

/*****************************************************************/
//  BitStream functions
/*****************************************************************/


template<typename T> 
inline void stwrite(RakNet::BitStream* pStream, const T& data, int mode)
{
	switch (mode)
	{
	case 1: pStream->Write<T>(data);
		break;
	case 2: pStream->WriteCompressed<T>(data);
		break;
	case 3: pStream->WriteCompressedDelta<T>(data);
		break;
	default: 
		assert(false);
		break;
	}
}

template<typename T> 
inline T stread(RakNet::BitStream* pStream, int mode)
{
	T data;
	switch (mode)
	{
	case 1: pStream->Read<T>(data);
		break;
	case 2: pStream->ReadCompressed<T>(data);
		break;
	case 3: pStream->ReadCompressedDelta<T>(data);
		break;
	default: 
		assert(false);
		break;
	}
	return data;
}

/*********************************************************************/
inline void stwrite_table(RakNet::BitStream* pStream, lua_State *l, int iTable, int mode)
{
	assert( lua_type(l,iTable) == LUA_TTABLE );
	int iSize = lua_objlen(l,iTable);
	for ( int iIndex = 1; iIndex <= iSize; iIndex++)
	{
		lua_rawgeti(l,iTable,iIndex);
		int iType = lua_type(l,-1);
		if ( iType == LUA_TNUMBER)
			stwrite<double>( pStream, lua_tonumber(l,-1), mode);
		else if ( iType == LUA_TBOOLEAN )
			stwrite<bool>( pStream, lua_toboolean(l,-1), mode );
		else if ( iType == LUA_TSTRING )
			stwrite<RakNet::RakString>( pStream, RakNet::RakString( lua_tostring(l,-1)), mode );
		lua_pop(l,1);
	}
}

/*********************************************************************/
inline void stread_table(RakNet::BitStream* pStream, lua_State *l, int iTable, int mode)
{
	assert( lua_type(l,iTable) == LUA_TTABLE );
	int iSize = lua_objlen(l,iTable);
	for ( int iIndex = 1; iIndex <= iSize; iIndex++)
	{
		lua_rawgeti(l,iTable,iIndex);
		int iType = lua_type(l,-1);
		lua_pop(l,1);
		if ( iType == LUA_TNUMBER)
			lua_pushnumber(l,  stread<double>( pStream, mode) );
		else if ( iType == LUA_TBOOLEAN )
			lua_pushboolean(l, stread<bool>( pStream, mode ) );
		else if ( iType == LUA_TSTRING )
			lua_pushstring(l, stread<RakNet::RakString>( pStream, mode ).C_String() );
		lua_rawseti( l, -2, iIndex);	
	}
}


/************************************************************************************/
inline void stwrite_vector(RakNet::BitStream* pStream, double dX, double dY, double dZ, bool bNormal)
{
	if (bNormal)
		pStream->WriteNormVector<double>(dX,dY,dZ);
	else
		pStream->WriteVector<double>(dX,dY,dZ);
}

inline void stread_vector(RakNet::BitStream* pStream, double& dX, double& dY, double& dZ, bool bNormal)
{
	if (bNormal)
		pStream->ReadNormVector<double>(dX,dY,dZ);
	else
		pStream->ReadVector<double>(dX,dY,dZ);
}


///Write data to bitstream
// @function write
// @param bitstream userdata
// @param mode int @see SLuaBitstream
// @param type int @see SLuaBitstream
// @param ...

static int raknet_bitstream_write( lua_State* l )
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TNUMBER );
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l, 1);
	SLuaBitstream::EMode eMode = (SLuaBitstream::EMode) lua_tointeger( l, 2 );
	SLuaBitstream::EType eType = (SLuaBitstream::EType) lua_tointeger( l, 3 );

	switch (eType)
	{
		case SLuaBitstream::t_bit:         lua_toboolean(l,4) ? pBitStream->Write1() : pBitStream->Write0(); break;
		case SLuaBitstream::t_bool:        stwrite<bool>(pBitStream, lua_toboolean(l,4), eMode ); break;
		case SLuaBitstream::t_byte:        stwrite<unsigned char>( pBitStream, (unsigned char) lua_tointeger(l,4), eMode ); break;
		case SLuaBitstream::t_bitstream:   stwrite<RakNet::BitStream*>( pBitStream,RAKBITSTREAM_CHECK(l, 4), eMode); break;
		case SLuaBitstream::t_double:      stwrite<double>( pBitStream, lua_tonumber(l,4), eMode ); break;
		case SLuaBitstream::t_float:       stwrite<float>(pBitStream, (float) lua_tonumber(l,4), eMode); break;
		case SLuaBitstream::t_guid:        stwrite<RakNet::RakNetGUID>( pBitStream, *RAKGUID_CHECK(l,4), eMode); break;
		case SLuaBitstream::t_int:         stwrite<int>(pBitStream, lua_tointeger(l,4), eMode); break;
		case SLuaBitstream::t_short:       stwrite<short int>( pBitStream, (short int) lua_tointeger(l,4), eMode); break;
		case SLuaBitstream::t_string:      stwrite<RakNet::RakString>( pBitStream, RakNet::RakString( lua_tostring(l,4)), eMode ); break;
		case SLuaBitstream::t_uint:        stwrite<unsigned int>( pBitStream, (unsigned int) lua_tointeger(l,4), eMode ); break;
		case SLuaBitstream::t_system_addr: stwrite<RakNet::SystemAddress>( pBitStream, *RAKSYSTEMADDRESS_CHECK(l,4), eMode); break;
		case SLuaBitstream::t_table:       stwrite_table( pBitStream, l, 4 , eMode ); break;
		case SLuaBitstream::t_vector:        
		case SLuaBitstream::t_normal_vector: assert(lua_gettop(l) > 5 ) ; stwrite_vector( pBitStream, lua_tonumber(l,4), lua_tonumber(l,5), lua_tonumber(l,6), eType == SLuaBitstream::t_normal_vector ); break;

	default:
		assert(false);
		break;
	}
	return 0;
}

///Read data from bitstream
// @function read
// @param bitstream userdata
// @param read mode int @see SLuaBitstream
// @param read type int @see SLuaBitstream
// @param [ guid system address ] userdata

static int raknet_bitstream_read( lua_State* l )
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TNUMBER );
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l, 1);
	SLuaBitstream::EMode eMode = (SLuaBitstream::EMode) lua_tointeger( l, 2 );
	SLuaBitstream::EType eType = (SLuaBitstream::EType) lua_tointeger( l, 3 );
	
	int iResCount = 1;
	switch (eType)
	{
		case SLuaBitstream::t_bit:         lua_pushboolean( l, pBitStream->ReadBit() ); break;
		case SLuaBitstream::t_bool:        lua_pushboolean( l, stread<bool>(pBitStream, eMode )); break;
		case SLuaBitstream::t_byte:        lua_pushinteger( l, stread<unsigned char>( pBitStream, eMode )); break;
		case SLuaBitstream::t_double:      lua_pushnumber( l, stread<double>( pBitStream, eMode )); break;
		case SLuaBitstream::t_float:       lua_pushnumber( l, stread<float>(pBitStream, eMode) ); break;
		case SLuaBitstream::t_guid:        {
											assert(lua_gettop(l) > 3 ) ;
											*RAKGUID_CHECK(l,4) = stread<RakNet::RakNetGUID>( pBitStream, eMode);
											break;
										   }
		case SLuaBitstream::t_int:         lua_pushinteger( l, stread<int>( pBitStream, eMode )); break;
		case SLuaBitstream::t_short:       lua_pushinteger( l, stread<short int>( pBitStream, eMode )); break;
		case SLuaBitstream::t_string:      {											
											lua_pushstring(l, stread<RakNet::RakString>( pBitStream, eMode ).C_String());
											break;
										   }
		case SLuaBitstream::t_uint:        lua_pushnumber( l, stread<unsigned int>( pBitStream, eMode )); break;

		case SLuaBitstream::t_system_addr: {
											assert(lua_gettop(l) > 3 );
											*RAKSYSTEMADDRESS_CHECK(l,4) = stread<RakNet::SystemAddress>( pBitStream, eMode);
											break;
										   }
		case SLuaBitstream::t_table:       stread_table( pBitStream, l, 4 , eMode ); break;
		case SLuaBitstream::t_vector:        
		case SLuaBitstream::t_normal_vector: 
											{
												double dX,dY,dZ = 0;
												stread_vector( pBitStream, dX,dY,dZ, eType == SLuaBitstream::t_normal_vector );
												lua_pushnumber(l,dX);
												lua_pushnumber(l,dY);
												lua_pushnumber(l,dZ);
												iResCount = 3;
												break;
											}
	default:
		assert(false);
		break;
	}
	return iResCount;
}

///Reset bitstream
// @param bitstream userdata
static int raknet_bitstream_reset(lua_State *l)
{
	RAKBITSTREAM_CHECK(l, 1)->Reset();
	return 0;
}

///Resize bitstream
// @param bitstream userdata
// @param number, new size
// @param bool, keep old data
static int raknet_bitstream_resize(lua_State *l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,1) == LUA_TUSERDATA && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TBOOLEAN);
	
	int iNewSize = lua_tointeger(l,2);
	bool bKeepOld = lua_toboolean(l,3);
	RakNet::BitStream** ppBitStream = (RakNet::BitStream**)lua_touserdata(l,1);
	if ( bKeepOld )
	{
		assert( iNewSize >= BITS_TO_BYTES( (*ppBitStream)->GetNumberOfBitsAllocated()) );
		RakNet::BitStream* pOldBitStream = *ppBitStream;
		*ppBitStream = new RakNet::BitStream( iNewSize );
		(*ppBitStream)->Write( pOldBitStream );
		delete pOldBitStream;
	}
	else
	{
		*ppBitStream = new RakNet::BitStream( iNewSize );
	}
	return 0;
}

///Write bitstream command
// write byte to specifyed offset
// @param bitstream userdata
// @param number, offset
// @param number, size
// @param commands...
static int raknet_bitstream_command(lua_State *l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TNUMBER);
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l, 1);
	int iOffset = lua_tonumber(l,2);
	int iSize   = lua_tonumber(l,3);
	int iStart  = 4;
	int iEnd    = iOffset + iSize;

	assert( iEnd <= BITS_TO_BYTES(pBitStream->GetNumberOfBitsAllocated()));
	for ( int iIndex = iOffset; iIndex < iEnd; iIndex++ )
	{
		pBitStream->GetData()[iIndex] = (unsigned char)lua_tointeger(l, iStart );
		iStart++;
	}
	
	return 0;
}

///Read bitstream command
// Read byte from specifyed offset
// @param bitstream userdata
// @param number, offset
// @param number, size
static int raknet_bitstream_read_command(lua_State *l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TNUMBER );
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l, 1);
	int iOffset = lua_tonumber(l,2);
	int iSize   = lua_tonumber(l,3);
	int iEnd    = iOffset + iSize;
	assert( iEnd <= BITS_TO_BYTES( pBitStream->GetNumberOfBitsAllocated()) );
	for ( int iIndex = iOffset; iIndex < iEnd; iIndex++ )
		lua_pushnumber(l, pBitStream->GetData()[iOffset]);
	return iSize;
}

///Reset pointers
// Reset read or write pointers
// @param bitstream userdata
// @param bool, read pointer
// @param bool, write pointer
static int raknet_bitstream_reset_pointer(lua_State *l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TBOOLEAN && lua_type(l,3) == LUA_TBOOLEAN );
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l, 1);
	if ( lua_toboolean(l,2) )
		pBitStream->ResetReadPointer();
	if ( lua_toboolean(l,3) )
		pBitStream->ResetWritePointer();
	return 0;
}

///Debug print bitstream as hex value
// @param bitstream userdata
static int raknet_bitstream_print_hex(lua_State *l)
{
	assert(lua_gettop(l) > 0);
	char Buffer[DRaknetBitStreamPrintsBuffer];
	RAKBITSTREAM_CHECK(l, 1)->PrintHex(Buffer);
	lua_pushstring(l,Buffer);
	return 1;
}

///Debug print bitstream as bit values
// @param bitstream userdata
static int raknet_bitstream_print_bits(lua_State *l)
{
	assert(lua_gettop(l) > 0);
	char Buffer[DRaknetBitStreamPrintsBuffer];
	RAKBITSTREAM_CHECK(l, 1)->PrintBits(Buffer);
	lua_pushstring(l,Buffer);
	return 1;
}

///Igrnore bytes
// @param bitstream userdata
// @param int, size
static int raknet_bitstream_ignore_bytes(lua_State *l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER);
	RAKBITSTREAM_CHECK(l, 1)->IgnoreBytes( lua_tointeger(l,2));
	return 0;
}

///Igrnore bits
// @param bitstream userdata
// @param int, size
static int raknet_bitstream_ignore_bits(lua_State *l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER);
	RAKBITSTREAM_CHECK(l, 1)->IgnoreBits( lua_tointeger(l,2));
	return 0;
}

///Set current write offset
// @param bitstream userdata
// @param write offset
static int raknet_bitstream_set_write_offset(lua_State *l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER);
	RAKBITSTREAM_CHECK(l, 1)->SetWriteOffset( ( RakNet::BitSize_t) lua_tointeger(l,2));
	return 0;
}

///Get current write offset
// @param bitstream userdata
static int raknet_bitstream_get_write_offset(lua_State *l)
{
	assert(lua_gettop(l) > 0 );
	lua_pushnumber(l, RAKBITSTREAM_CHECK(l, 1)->GetWriteOffset() );
	return 1;
}

///Set current read offset
// @param bitstream userdata
// @param read offset
static int raknet_bitstream_set_read_offset(lua_State *l)
{
	assert(lua_gettop(l) > 1 && lua_type(l,2) == LUA_TNUMBER);
	RAKBITSTREAM_CHECK(l, 1)->SetReadOffset( ( RakNet::BitSize_t) lua_tointeger(l,2));
	return 0;
}

///Get current read offset
// @param bitstream userdata
static int raknet_bitstream_get_read_offset(lua_State *l)
{
	assert(lua_gettop(l) > 0 );
	lua_pushnumber(l, RAKBITSTREAM_CHECK(l, 1)->GetReadOffset() );
	return 1;
}

///Get number of bits used
// @param bitstream userdata
static int raknet_bitstream_get_number_of_bits_used(lua_State *l)
{
	assert(lua_gettop(l) > 0 );
	lua_pushnumber(l, RAKBITSTREAM_CHECK(l, 1)->GetNumberOfBitsUsed());
	return 1;
}

///Get number of bytes used
// @param bitstream userdata
static int raknet_bitstream_get_number_of_bytes_used(lua_State *l)
{
	assert(lua_gettop(l) > 0 );
	lua_pushnumber(l, RAKBITSTREAM_CHECK(l, 1)->GetNumberOfBytesUsed() );
	return 1;
}

///Get number of unread bytes
// @param bitstream userdata
static int raknet_bitstream_get_unread_bytes(lua_State *l)
{
	assert(lua_gettop(0) > 1);
	lua_pushnumber(l, BITS_TO_BYTES( RAKBITSTREAM_CHECK(l, 1)->GetNumberOfUnreadBits()) );
	return 1;
}

///Get number of unread bits
// @param bitstream userdata
static int raknet_bitstream_get_unread_bits(lua_State *l)
{
	lua_pushnumber(l, RAKBITSTREAM_CHECK(l, 1)->GetNumberOfUnreadBits() );
	return 1;
}

///Swap endian
// @param bitstream userdata
// @param int, offset
// @param int, size
static int raknet_bitstream_endian_swap(lua_State *l)
{
	assert(lua_gettop(l) > 2 && lua_type(l,2) == LUA_TNUMBER && lua_type(l,3) == LUA_TNUMBER );
	RAKBITSTREAM_CHECK(l, 1)->EndianSwapBytes( lua_tointeger(l,2), lua_tointeger(l, 3));
	return 0;
}

///Align write to byte boundary
// @param bitstream userdata
static int raknet_bitstream_align_write_byte_b(lua_State *l)
{
	RAKBITSTREAM_CHECK(l, 1)->AlignWriteToByteBoundary();
	return 0;
}

///Align read to byte boundary
// @param bitstream userdata
static int raknet_bitstream_align_read_byte_b(lua_State *l)
{
	RAKBITSTREAM_CHECK(l, 1)->AlignReadToByteBoundary();
	return 0;
}

///Get allocated bits size
// @param bitstream userdata
// @param allocated memory in bits
static int raknet_bitstream_get_alloc_bits(lua_State *l)
{
	lua_pushnumber( l, RAKBITSTREAM_CHECK(l, 1)->GetNumberOfBitsAllocated());
	return 1;
}

///Get allocated memory in bytes
// @param bitstream userdata
// @param allocated memory in bytes
static int raknet_bitstream_get_alloc_bytes(lua_State *l)
{
	lua_pushnumber( l, BITS_TO_BYTES( RAKBITSTREAM_CHECK(l, 1)->GetNumberOfBitsAllocated()) );
	return 1;
}

/************************************************************************************/

///GC Bitstream
// @param bitstream userdata
static int raknet_bitstream_gc(lua_State *l)
{
	RakNet::BitStream* pBitStream = RAKBITSTREAM_CHECK(l, 1);
	assert(pBitStream);
	delete pBitStream;
	return 0;
}

static const struct luaL_Reg raknet_bitstream_meta[] = {
	{ "reset", raknet_bitstream_reset },
	{ "resize", raknet_bitstream_resize },
	{ "write_direct", raknet_bitstream_command },
	{ "read_direct", raknet_bitstream_read_command },
	{ "reset_pointers", raknet_bitstream_reset_pointer },
	{ "print_hex", raknet_bitstream_print_hex },
	{ "print_bits", raknet_bitstream_print_bits },
	{ "ignore_bits", raknet_bitstream_ignore_bits },
	{ "ignore_bytes", raknet_bitstream_ignore_bytes },
	{ "set_write_offset", raknet_bitstream_set_write_offset },
	{ "get_write_offset", raknet_bitstream_get_write_offset },
	{ "set_read_offset", raknet_bitstream_set_read_offset },
	{ "get_read_offset", raknet_bitstream_get_read_offset },
	{ "get_used_bits", raknet_bitstream_get_number_of_bits_used },
	{ "get_used_bytes", raknet_bitstream_get_number_of_bytes_used },
	{ "get_unread_bytes", raknet_bitstream_get_unread_bytes },
	{ "get_unread_bits", raknet_bitstream_get_unread_bits },
	{ "endian_swap_bytes", raknet_bitstream_endian_swap},
	{ "align_write_byte", raknet_bitstream_align_write_byte_b },
	{ "align_read_byte", raknet_bitstream_align_read_byte_b },
	{ "get_allocated_bits", raknet_bitstream_get_alloc_bits },
	{ "get_allocated_bytes", raknet_bitstream_get_alloc_bytes },
	{ "write", raknet_bitstream_write },
	{ "read", raknet_bitstream_read },
	{ NULL, NULL }
};


static int luaopen_bitstream_const(lua_State *l)
{
	// write mode

	DSET_TABLE_NUMBER( "m_n" , SLuaBitstream::EMode::m_normal) // normal write
	DSET_TABLE_NUMBER( "m_c" , SLuaBitstream::EMode::m_compressed) // compressed write
	DSET_TABLE_NUMBER( "m_c_d" , SLuaBitstream::EMode::m_compressed_delta) // compressed delta write

	// data types
	DSET_TABLE_NUMBER( "t_bit" , SLuaBitstream::EType::t_bit)
	DSET_TABLE_NUMBER( "t_bool" , SLuaBitstream::EType::t_bool)
	
	DSET_TABLE_NUMBER( "t_byte" , SLuaBitstream::EType::t_byte)
	DSET_TABLE_NUMBER( "t_short" , SLuaBitstream::EType::t_short)
	DSET_TABLE_NUMBER( "t_int" , SLuaBitstream::EType::t_int)
	DSET_TABLE_NUMBER( "t_uint" , SLuaBitstream::EType::t_uint)

	DSET_TABLE_NUMBER( "t_double" , SLuaBitstream::EType::t_double)
	DSET_TABLE_NUMBER( "t_float" , SLuaBitstream::EType::t_float )
	DSET_TABLE_NUMBER( "t_string" , SLuaBitstream::EType::t_string)
	
	DSET_TABLE_NUMBER( "t_vector" , SLuaBitstream::EType::t_vector)
	DSET_TABLE_NUMBER( "t_normal_vector" , SLuaBitstream::EType::t_normal_vector)
	DSET_TABLE_NUMBER( "t_sa" , SLuaBitstream::EType::t_system_addr)
	DSET_TABLE_NUMBER( "t_guid" , SLuaBitstream::EType::t_guid)
	DSET_TABLE_NUMBER( "t_bs" , SLuaBitstream::EType::t_bitstream)
	DSET_TABLE_NUMBER( "t_table", SLuaBitstream::EType::t_table )
	return 1;
}

int luaopen_raknet_bitstream(lua_State *l)
{
	luaL_newmetatable(l, DRaknetBitStreamMeta);
	lua_newtable(l);
	luaL_register(l, nullptr, raknet_bitstream_meta);
	lua_setfield(l, -2, "__index");
	lua_pushcfunction(l, raknet_bitstream_gc);
	lua_setfield(l, -2, "__gc");
	
	lua_newtable( l );
	luaopen_bitstream_const( l );
	lua_setglobal( l, DRaknetBitStreamConst );

	return 1;
}