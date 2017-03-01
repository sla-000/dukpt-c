//------------------------------------------------------------------------
#pragma once
//------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
//------------------------------------------------------------------------
//------------------------------------------------------------------------

typedef unsigned __int128 		u128;
typedef uint64_t			u64;
typedef uint32_t			u32;
typedef uint16_t			u16;
typedef uint8_t				u8;

typedef signed __int128 		s128;
typedef int64_t				s64;
typedef int32_t				s32;
typedef int16_t				s16;
typedef int8_t				s8;

//------------------------------------------------------------------------

typedef uint_least32_t		lu32;
typedef uint_least16_t		lu16;
typedef uint_least8_t		lu8;

typedef int_least32_t		ls32;
typedef int_least16_t		ls16;
typedef int_least8_t		ls8;

//------------------------------------------------------------------------

typedef int_fast64_t		fs64;
typedef int_fast32_t		fs32;
typedef int_fast16_t		fs16;
typedef int_fast8_t			fs8;

typedef uint_fast64_t		fu64;
typedef uint_fast32_t		fu32;
typedef uint_fast16_t		fu16;
typedef uint_fast8_t		fu8;

//------------------------------------------------------------------------

typedef uint8_t				BOOL8;
typedef uint32_t			BOOLX;

#ifndef TRUE
#define TRUE				1
#endif

#ifndef FALSE
#define FALSE				0
#endif

#define Bit(x)				( (u32) (1 << (x)) )

//------------------------------------------------------------------------

/// Function parameters - IN
#define _IN                 const
/// Function parameters - OUT
#define _OUT
/// Function parameters - OUT
#define _IO

//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
//------------------------------------------------------------------------
