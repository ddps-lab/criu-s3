/*
 * mem.h — minimal subset of zstd internal mem.h for seekable_format.
 *
 * The upstream zstd seekable_format implementation #includes zstd's internal
 * `mem.h` for little-endian read/write helpers and primitive type aliases.
 * Since libzstd-dev only ships public headers (zstd.h, zdict.h, zstd_errors.h),
 * we provide the symbols it actually uses here.
 *
 * Only the symbols referenced by zstdseek_compress.c / zstdseek_decompress.c
 * are defined.
 */

#ifndef MEM_H_MODULE
#define MEM_H_MODULE

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t  BYTE;
typedef uint16_t U16;
typedef int16_t  S16;
typedef uint32_t U32;
typedef int32_t  S32;
typedef uint64_t U64;
typedef int64_t  S64;

/* Little-endian read helpers (unaligned) */
static inline U16 MEM_readLE16(const void *memPtr)
{
	const BYTE *p = (const BYTE *)memPtr;
	return (U16)((U16)p[0] | ((U16)p[1] << 8));
}

static inline U32 MEM_readLE32(const void *memPtr)
{
	const BYTE *p = (const BYTE *)memPtr;
	return (U32)p[0] | ((U32)p[1] << 8) | ((U32)p[2] << 16) | ((U32)p[3] << 24);
}

static inline U64 MEM_readLE64(const void *memPtr)
{
	const BYTE *p = (const BYTE *)memPtr;
	return (U64)p[0] | ((U64)p[1] << 8) | ((U64)p[2] << 16) | ((U64)p[3] << 24) |
	       ((U64)p[4] << 32) | ((U64)p[5] << 40) | ((U64)p[6] << 48) | ((U64)p[7] << 56);
}

static inline void MEM_writeLE16(void *memPtr, U16 value)
{
	BYTE *p = (BYTE *)memPtr;
	p[0] = (BYTE)(value & 0xff);
	p[1] = (BYTE)((value >> 8) & 0xff);
}

static inline void MEM_writeLE32(void *memPtr, U32 value)
{
	BYTE *p = (BYTE *)memPtr;
	p[0] = (BYTE)(value & 0xff);
	p[1] = (BYTE)((value >> 8) & 0xff);
	p[2] = (BYTE)((value >> 16) & 0xff);
	p[3] = (BYTE)((value >> 24) & 0xff);
}

static inline void MEM_writeLE64(void *memPtr, U64 value)
{
	BYTE *p = (BYTE *)memPtr;
	p[0] = (BYTE)(value & 0xff);
	p[1] = (BYTE)((value >> 8) & 0xff);
	p[2] = (BYTE)((value >> 16) & 0xff);
	p[3] = (BYTE)((value >> 24) & 0xff);
	p[4] = (BYTE)((value >> 32) & 0xff);
	p[5] = (BYTE)((value >> 40) & 0xff);
	p[6] = (BYTE)((value >> 48) & 0xff);
	p[7] = (BYTE)((value >> 56) & 0xff);
}

#endif /* MEM_H_MODULE */
