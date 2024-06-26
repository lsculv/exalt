#pragma once

typedef _Bool bool;
#define true 1
#define false 0

// Should be used for streams of raw bytes that are not assumed to be text
typedef char byte;

// Supported integral types
typedef signed char i8;
typedef unsigned char u8;
typedef signed short int i16;
typedef unsigned short int u16;
typedef signed int i32;
typedef unsigned int u32;
typedef signed long int i64;
typedef unsigned long int u64;

// Size types
typedef signed long int isize;
typedef unsigned long int usize;

// Maximums and minimums of integral types.
#define I8_MIN (-128)
#define I16_MIN (-32767 - 1)
#define I32_MIN (-2147483647 - 1)
#define I64_MIN (-9223372036854775807L - 1)

#define I8_MAX (127)
#define I16_MAX (32767)
#define I32_MAX (2147483647)
#define I64_MAX (9223372036854775807L)

#define U8_MAX (255)
#define U16_MAX (65535)
#define U32_MAX (4294967295U)
#define U64_MAX (18446744073709551615UL)
