// Copyright 2011-2022, Molecular Matters GmbH <office@molecular-matters.com>
// See LICENSE.txt for licensing details (2-clause BSD License: https://opensource.org/licenses/BSD-2-Clause)

#pragma once

#include "Foundation/PDB_Macros.h"
#include "Foundation/PDB_DisableWarningsPush.h"
#include <cstdint>
#include "Foundation/PDB_DisableWarningsPop.h"


namespace PDB
{
	namespace IPI
	{
		// https://llvm.org/docs/PDB/TpiStream.html#tpi-header
		struct StreamHeader
		{
			enum class PDB_NO_DISCARD Version : uint32_t
			{
				V40 = 19950410u,
				V41 = 19951122u,
				V50 = 19961031u,
				V70 = 19990903u,
				V80 = 20040203u
			};

			Version version;
			uint32_t headerSize;
			uint32_t typeIndexBegin;
			uint32_t typeIndexEnd;
			uint32_t typeRecordBytes;
			uint16_t hashStreamIndex;
			uint16_t hashAuxStreamIndex;
			uint32_t hashKeySize;
			uint32_t hashBucketCount;
			uint32_t hashValueBufferOffset;
			uint32_t hashValueBufferLength;
			uint32_t indexOffsetBufferOffset;
			uint32_t indexOffsetBufferLength;
			uint32_t hashAdjBufferOffset;
			uint32_t hashAdjBufferLength;
		};
	}


	namespace CodeView
	{
		namespace IPI
		{
			// code view type records that can appear in an IPI stream
			// https://llvm.org/docs/PDB/CodeViewTypes.html
			// https://llvm.org/docs/PDB/TpiStream.html#tpi-vs-ipi-stream
			enum class PDB_NO_DISCARD TypeRecordKind : uint16_t
			{
				LF_FUNC_ID = 0x1601u,					// global function ID
				LF_MFUNC_ID = 0x1602u,					// member function ID
				LF_BUILDINFO = 0x1603u,					// build information
				LF_SUBSTR_LIST = 0x1604u,				// similar to LF_ARGLIST for a list of substrings
				LF_STRING_ID = 0x1605u,					// string ID
				LF_UDT_SRC_LINE = 0x1606u,				// source and line on where an UDT is defined, generated by the compiler
				LF_UDT_MOD_SRC_LINE = 0x1607u			// module, source and line on where an UDT is defined, generated by the linker
			};

			// https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L1715
			enum class PDB_NO_DISCARD BuildInfoType : uint8_t
			{
				CurrentDirectory,		// compiler working directory
				BuildTool,				// tool path
				SourceFile,				// path to source file, relative or absolute
				TypeServerPDB,			// path to PDB file
				CommandLine				// command-line used to build the source file
			};

			struct RecordHeader
			{
				uint16_t size;					// record length, not including this 2-byte field
				TypeRecordKind kind;			// record kind
			};

			// all CodeView records are stored as a header, followed by variable-length data.
			// internal Record structs such as S_PUB32, S_GDATA32, etc. correspond to the data layout of a CodeView record of that kind.
			struct Record
			{
				RecordHeader header;
				union Data
				{
#pragma pack(push, 1)
					// https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L1694
					struct
					{
						uint32_t id;	// ID to list of sub-string IDs
						PDB_FLEXIBLE_ARRAY_MEMBER(char, name);
					} LF_STRING_ID;

					// https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L2043
					struct
					{
						uint32_t count;
						PDB_FLEXIBLE_ARRAY_MEMBER(uint32_t, typeIndices);
					} LF_SUBSTR_LIST;

					// https://github.com/microsoft/microsoft-pdb/blob/master/include/cvinfo.h#L1726

					struct
					{
						uint16_t count;
						PDB_FLEXIBLE_ARRAY_MEMBER(uint32_t, typeIndices);
					} LF_BUILDINFO;
#pragma pack(pop)
				} data;
			};
		}
	}
}
