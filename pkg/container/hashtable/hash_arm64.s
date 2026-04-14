// Copyright 2021 Matrix Origin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "textflag.h"

// func crc32Int64BatchHash(data *uint64, hashes *uint64, length int)
// Requires: CRC32
TEXT ·crc32Int64BatchHash(SB), NOSPLIT, $0-24
	MOVD data+0(FP), R0
	MOVD hashes+8(FP), R1
	MOVD length+16(FP), R2

loop:
	SUBS $8, R2
	BLT  tail

	VLD1 (R0), [V0.B16, V1.B16, V2.B16, V3.B16]
	VST1 [V0.B16, V1.B16, V2.B16, V3.B16], (R1)

	MOVD $-1, R3
	MOVD $-1, R4
	MOVD $-1, R5
	MOVD $-1, R6
	MOVD $-1, R7
	MOVD $-1, R8
	MOVD $-1, R9
	MOVD $-1, R10

	LDP.P 16(R0), (R11, R12)
	LDP.P 16(R0), (R13, R14)
	LDP.P 16(R0), (R15, R16)
	LDP.P 16(R0), (R17, R19)

	CRC32CX R11, R3
	CRC32CX R12, R4
	CRC32CX R13, R5
	CRC32CX R14, R6
	CRC32CX R15, R7
	CRC32CX R16, R8
	CRC32CX R17, R9
	CRC32CX R19, R10

	MOVW.P R3, 8(R1)
	MOVW.P R4, 8(R1)
	MOVW.P R5, 8(R1)
	MOVW.P R6, 8(R1)
	MOVW.P R7, 8(R1)
	MOVW.P R8, 8(R1)
	MOVW.P R9, 8(R1)
	MOVW.P R10, 8(R1)

	JMP loop

tail:
	ADDS $8, R2
	BEQ  done

tailLoop:
	MOVD    $-1, R3
	MOVD    (R0), R5
	MOVD.P  8(R0), R4
	CRC32CX R4, R3
	MOVD    R5, (R1)
	MOVW.P  R3, 8(R1)

	SUBS $1, R2
	BNE  tailLoop

done:
	RET

////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////

DATA Pi<>+0x00(SB)/8, $0x3243f6a8885a308d
DATA Pi<>+0x08(SB)/8, $0x313198a2e0370734
DATA Pi<>+0x10(SB)/8, $0x4a4093822299f31d
DATA Pi<>+0x18(SB)/8, $0x0082efa98ec4e6c8
DATA Pi<>+0x20(SB)/8, $0x9452821e638d0137
DATA Pi<>+0x28(SB)/8, $0x7be5466cf34e90c6
DATA Pi<>+0x30(SB)/8, $0xcc0ac29b7c97c50d
DATA Pi<>+0x38(SB)/8, $0xd3f84d5b5b547091
DATA Pi<>+0x40(SB)/8, $0x79216d5d98979fb1
DATA Pi<>+0x48(SB)/8, $0xbd1310ba698dfb5a
DATA Pi<>+0x50(SB)/8, $0xc2ffd72dbd01adfb
DATA Pi<>+0x58(SB)/8, $0x7b8e1afed6a267e9
DATA Pi<>+0x60(SB)/8, $0x6ba7c9045f12c7f9
DATA Pi<>+0x68(SB)/8, $0x924a19947b3916cf
DATA Pi<>+0x70(SB)/8, $0x70801f2e2858efc1
DATA Pi<>+0x78(SB)/8, $0x6636920d871574e6
GLOBL Pi<>(SB), (NOPTR+RODATA), $0x80

DATA CryptedPi<>+0x00(SB)/8, $0x822233b93c11087c
DATA CryptedPi<>+0x08(SB)/8, $0xd2b32f4adde873da
DATA CryptedPi<>+0x10(SB)/8, $0xae9c2fc7dd17bcdb
DATA CryptedPi<>+0x18(SB)/8, $0x859110441a1569fc
DATA CryptedPi<>+0x20(SB)/8, $0x47087d794fffb5c9
DATA CryptedPi<>+0x28(SB)/8, $0xb7b6c8f565414445
DATA CryptedPi<>+0x30(SB)/8, $0xfd260edabb308f8d
DATA CryptedPi<>+0x38(SB)/8, $0x3ddefc67bc565a13
DATA CryptedPi<>+0x40(SB)/8, $0xe4c1d50223544f10
DATA CryptedPi<>+0x48(SB)/8, $0xaf40e05725c3192b
DATA CryptedPi<>+0x50(SB)/8, $0x281d8ab9a16382e9
DATA CryptedPi<>+0x58(SB)/8, $0xddc10c903b63a6cf
DATA CryptedPi<>+0x60(SB)/8, $0x852d3ad603e8df72
DATA CryptedPi<>+0x68(SB)/8, $0xa6642b57d1011deb
DATA CryptedPi<>+0x70(SB)/8, $0x5063d25a1cb7b6b9
DATA CryptedPi<>+0x78(SB)/8, $0xb2623e6241e8e46e
GLOBL CryptedPi<>(SB), (NOPTR+RODATA), $0x80

// func aesBytesBatchGenHashStates(data *[]byte, states *[3]uint64, length int)
// Requires: AES
TEXT ·aesBytesBatchGenHashStates(SB), NOSPLIT, $0-24
	MOVD data+0(FP), R0
	MOVD states+8(FP), R1
	MOVD length+16(FP), R2

	MOVD $CryptedPi<>(SB), R3
	VLD1.P 64(R3), [V0.B16, V1.B16, V2.B16, V3.B16]
	VLD1 (R3), [V4.B16, V5.B16, V6.B16, V7.B16]
	VEOR V31.B16, V31.B16, V31.B16

loop:
	LDP.P 24(R0), (R4, R5)
	MOVD  R5, R6

	ADD R4, R5
	SUB $0x40, R5

	VMOV V0.B16, V8.B16
	VMOV V1.B16, V9.B16
	VMOV V2.B16, V10.B16
	VMOV V3.B16, V11.B16
	VMOV V4.B16, V12.B16
	VMOV V5.B16, V13.B16
	VMOV V6.B16, V14.B16
	VMOV V7.B16, V15.B16

innerLoop:
	CMP R4, R5
	BLE tail

	VLD1.P 0x40(R4), [V16.B16, V17.B16, V18.B16, V19.B16]

	AESE  V31.B16, V8.B16
	AESMC V8.B16, V8.B16
	VEOR  V16.B16, V8.B16, V8.B16

	AESE  V31.B16, V12.B16
	AESMC V12.B16, V12.B16
	VEOR  V16.B16, V12.B16, V12.B16

	AESE  V31.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V17.B16, V9.B16, V9.B16

	AESE  V31.B16, V13.B16
	AESMC V13.B16, V13.B16
	VEOR  V17.B16, V13.B16, V13.B16

	AESE  V31.B16, V10.B16
	AESMC V10.B16, V10.B16
	VEOR  V18.B16, V10.B16, V10.B16

	AESE  V31.B16, V14.B16
	AESMC V14.B16, V14.B16
	VEOR  V18.B16, V14.B16, V14.B16

	AESE  V31.B16, V11.B16
	AESMC V11.B16, V11.B16
	VEOR  V19.B16, V11.B16, V11.B16

	AESE  V31.B16, V15.B16
	AESMC V15.B16, V15.B16
	VEOR  V19.B16, V15.B16, V15.B16

	JMP innerLoop

tail:
	ADD $0x30, R5
	CMP R4, R5
	BLE done

	VLD1.P 0x10(R4), [V16.B16]

	AESE  V31.B16, V8.B16
	AESMC V8.B16, V8.B16
	VEOR  V16.B16, V8.B16, V8.B16

	AESE  V31.B16, V12.B16
	AESMC V12.B16, V12.B16
	VEOR  V16.B16, V12.B16, V12.B16

	CMP R4, R5
	BLE done

	VLD1.P 0x10(R4), [V17.B16]

	AESE  V31.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V17.B16, V9.B16, V9.B16

	AESE  V31.B16, V13.B16
	AESMC V13.B16, V13.B16
	VEOR  V17.B16, V13.B16, V13.B16

	CMP R4, R5
	BLE done

	VLD1 (R4), [V18.B16]

	AESE  V31.B16, V10.B16
	AESMC V10.B16, V10.B16
	VEOR  V18.B16, V10.B16, V10.B16

	AESE  V31.B16, V14.B16
	AESMC V14.B16, V14.B16
	VEOR  V18.B16, V14.B16, V14.B16

done:
	VLD1  (R5), [V19.B16]

	AESE  V31.B16, V11.B16
	AESMC V11.B16, V11.B16
	VEOR  V19.B16, V11.B16, V11.B16

	AESE  V31.B16, V15.B16
	AESMC V15.B16, V15.B16
	VEOR  V19.B16, V15.B16, V15.B16

	AESE  V31.B16, V8.B16
	AESMC V8.B16, V8.B16
	VEOR  V9.B16, V8.B16, V8.B16

	AESE  V31.B16, V11.B16
	AESMC V11.B16, V11.B16

	AESE  V10.B16, V11.B16
	AESMC V11.B16, V11.B16
	VEOR  V8.B16, V11.B16, V9.B16

	AESE  V8.B16, V11.B16
	AESMC V11.B16, V11.B16
	VEOR  V9.B16, V11.B16, V10.B16

	AESE  V9.B16, V11.B16
	AESMC V11.B16, V11.B16
	VEOR  V10.B16, V11.B16, V8.B16

	AESE  V10.B16, V11.B16
	AESMC V11.B16, V11.B16
	VEOR  V8.B16, V11.B16, V11.B16

	AESE  V31.B16, V12.B16
	AESMC V12.B16, V12.B16

	AESE  V31.B16, V13.B16
	AESMC V13.B16, V13.B16
	VEOR  V14.B16, V13.B16, V13.B16

	AESE  V15.B16, V12.B16
	AESMC V12.B16, V12.B16
	VEOR  V13.B16, V12.B16, V12.B16

	VMOV V11.D[0], R7
	VMOV V11.D[1], R8
	EOR  R8, R7
	EOR  R6, R7

	MOVD.P R7, 8(R1)
	VST1.P [V12.B16], 16(R1)

	SUBS $1, R2
	BNE  loop

	RET

// func aesInt192BatchGenHashStates(data *[3]uint64, states *[3]uint64, length int)
// Requires: AES
TEXT ·aesInt192BatchGenHashStates(SB), NOSPLIT, $0-24
	MOVD data+0(FP), R0
	MOVD states+8(FP), R1
	MOVD length+16(FP), R2

	MOVD $CryptedPi<>(SB), R3
	VLD1.P 64(R3), [V0.B16, V1.B16, V2.B16, V3.B16]
	VLD1 (R3), [V4.B16, V5.B16, V6.B16, V7.B16]
	VEOR V31.B16, V31.B16, V31.B16

	VMOV V0.B16, V30.B16

	AESE  V31.B16, V0.B16
	AESMC V0.B16, V0.B16

	AESE  V31.B16, V1.B16
	AESMC V1.B16, V1.B16

	AESE  V31.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR  V2.B16, V3.B16, V3.B16

	AESE  V31.B16, V4.B16
	AESMC V4.B16, V4.B16

	AESE  V31.B16, V5.B16
	AESMC V5.B16, V5.B16

	AESE  V31.B16, V6.B16
	AESMC V6.B16, V6.B16
	VEOR  V7.B16, V6.B16, V6.B16

loop:
	VLD1   (R0), [V8.B16]
	ADD    $0x08, R0
	VLD1.P 0x10(R0), [V9.B16]

	VEOR V0.B16, V8.B16, V10.B16
	VEOR V5.B16, V9.B16, V11.B16

	AESE  V1.B16, V9.B16
	AESMC V9.B16, V9.B16

	AESE  V10.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V3.B16, V9.B16, V10.B16

	AESE  V3.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V10.B16, V9.B16, V12.B16

	AESE  V10.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V12.B16, V9.B16, V9.B16

	VMOV  V9.D[0], R4
	VMOV  V9.D[1], R5
	EOR   R5, R4

	AESE  V4.B16, V8.B16
	AESMC V8.B16, V8.B16

	AESE  V11.B16, V8.B16
	AESMC V8.B16, V8.B16
	VEOR  V6.B16, V8.B16, V8.B16

	MOVD.P R4, 0x08(R1)
	VST1.P [V8.B16], 0x10(R1)

	SUBS $1, R2
	BNE  loop

done:
	RET

// func aesInt256BatchGenHashStates(data *[4]uint64, states *[3]uint64, length int)
// Requires: AES
TEXT ·aesInt256BatchGenHashStates(SB), NOSPLIT, $0-24
	MOVD data+0(FP), R0
	MOVD states+8(FP), R1
	MOVD length+16(FP), R2

	MOVD $CryptedPi<>(SB), R3
	VLD1.P 64(R3), [V0.B16, V1.B16, V2.B16, V3.B16]
	VLD1 (R3), [V4.B16, V5.B16, V6.B16, V7.B16]
	VEOR V31.B16, V31.B16, V31.B16

	VMOV V0.B16, V30.B16

	AESE  V31.B16, V0.B16
	AESMC V0.B16, V0.B16

	AESE  V31.B16, V1.B16
	AESMC V1.B16, V1.B16

	AESE  V31.B16, V3.B16
	AESMC V3.B16, V3.B16
	VEOR  V2.B16, V3.B16, V3.B16

	AESE  V31.B16, V4.B16
	AESMC V4.B16, V4.B16

	AESE  V31.B16, V5.B16
	AESMC V5.B16, V5.B16

	AESE  V31.B16, V6.B16
	AESMC V6.B16, V6.B16
	VEOR  V7.B16, V6.B16, V6.B16

loop:
	VLD1.P 0x20(R0), [V8.B16, V9.B16]

	VEOR V0.B16, V8.B16, V10.B16
	VEOR V5.B16, V9.B16, V11.B16

	AESE  V1.B16, V9.B16
	AESMC V9.B16, V9.B16

	AESE  V10.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V3.B16, V9.B16, V10.B16

	AESE  V3.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V10.B16, V9.B16, V12.B16

	AESE  V10.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V12.B16, V9.B16, V9.B16

	VMOV  V9.D[0], R4
	VMOV  V9.D[1], R5
	EOR   R5, R4

	AESE  V4.B16, V8.B16
	AESMC V8.B16, V8.B16

	AESE  V11.B16, V8.B16
	AESMC V8.B16, V8.B16
	VEOR  V6.B16, V8.B16, V8.B16

	MOVD.P R4, 0x08(R1)
	VST1.P [V8.B16], 0x10(R1)

	SUBS $1, R2
	BNE  loop

done:
	RET

// func aesInt320BatchGenHashStates(data *[5]uint64, states *[3]uint64, length int)
// Requires: AES
TEXT ·aesInt320BatchGenHashStates(SB), NOSPLIT, $0-24
	MOVD data+0(FP), R0
	MOVD states+8(FP), R1
	MOVD length+16(FP), R2

	MOVD $CryptedPi<>(SB), R3
	VLD1.P 64(R3), [V0.B16, V1.B16, V2.B16, V3.B16]
	VLD1 (R3), [V4.B16, V5.B16, V6.B16, V7.B16]
	VEOR V31.B16, V31.B16, V31.B16

	AESE  V31.B16, V0.B16
	AESMC V0.B16, V0.B16

	AESE  V31.B16, V1.B16
	AESMC V1.B16, V1.B16

	AESE  V31.B16, V3.B16
	AESMC V3.B16, V3.B16

	AESE  V31.B16, V4.B16
	AESMC V4.B16, V4.B16

	AESE  V31.B16, V5.B16
	AESMC V5.B16, V5.B16

	AESE  V31.B16, V6.B16
	AESMC V6.B16, V6.B16

loop:
	VLD1 (R0), [V8.B16, V9.B16]
	ADD  $0x18, R0
	VLD1.P 0x10(R0), [V10.B16]

	VEOR V4.B16, V8.B16, V11.B16
	VEOR V5.B16, V9.B16, V12.B16

	VEOR V3.B16, V10.B16, V13.B16

	AESE  V0.B16, V8.B16
	AESMC V8.B16, V8.B16

	AESE  V1.B16, V9.B16
	AESMC V9.B16, V9.B16
	VEOR  V2.B16, V9.B16, V9.B16

	AESE  V13.B16, V8.B16
	AESMC V8.B16, V8.B16
	VEOR  V9.B16, V8.B16, V13.B16

	AESE  V9.B16, V8.B16
	AESMC V8.B16, V8.B16
	VEOR  V13.B16, V8.B16, V9.B16

	AESE  V13.B16, V8.B16
	AESMC V8.B16, V8.B16
	VEOR  V9.B16, V8.B16, V8.B16

	VMOV  V8.D[0], R4
	VMOV  V8.D[1], R5
	EOR   R5, R4

	AESE  V31.B16, V11.B16
	AESMC V11.B16, V11.B16

	AESE  V6.B16, V10.B16
	AESMC V10.B16, V10.B16
	VEOR  V7.B16, V10.B16, V10.B16

	AESE  V12.B16, V11.B16
	AESMC V11.B16, V11.B16
	VEOR  V10.B16, V11.B16, V11.B16

	MOVD.P R4, 0x08(R1)
	VST1.P [V11.B16], 0x10(R1)

	SUBS $1, R2
	BNE  loop

done:
	RET

////////////////////////////////////////////////////////////////
// Software prefetch functions for batch hash probing
////////////////////////////////////////////////////////////////

// func prefetchInt64Cells(hashes *uint64, count int, cellBase unsafe.Pointer, mask uint64)
// For each hash: PRFM PLDL1KEEP at cellBase + ((hash & mask) << 4).
TEXT ·prefetchInt64Cells(SB), NOSPLIT, $0-32
	MOVD hashes+0(FP), R0
	MOVD count+8(FP), R1
	MOVD cellBase+16(FP), R2
	MOVD mask+24(FP), R3

pf64_loop8:
	SUBS $8, R1
	BLT  pf64_tail

	LDP  0(R0), (R4, R5)
	LDP  16(R0), (R6, R7)
	LDP  32(R0), (R8, R9)
	LDP  48(R0), (R10, R11)
	ADD  $64, R0

	AND R3, R4;  LSL $4, R4;  ADD R2, R4;  PRFM (R4)
	AND R3, R5;  LSL $4, R5;  ADD R2, R5;  PRFM (R5)
	AND R3, R6;  LSL $4, R6;  ADD R2, R6;  PRFM (R6)
	AND R3, R7;  LSL $4, R7;  ADD R2, R7;  PRFM (R7)
	AND R3, R8;  LSL $4, R8;  ADD R2, R8;  PRFM (R8)
	AND R3, R9;  LSL $4, R9;  ADD R2, R9;  PRFM (R9)
	AND R3, R10; LSL $4, R10; ADD R2, R10; PRFM (R10)
	AND R3, R11; LSL $4, R11; ADD R2, R11; PRFM (R11)

	B pf64_loop8

pf64_tail:
	ADDS $8, R1
	BEQ  pf64_done
pf64_tailLoop:
	MOVD (R0), R4
	ADD  $8, R0
	AND R3, R4; LSL $4, R4; ADD R2, R4; PRFM (R4)
	SUBS $1, R1
	BNE  pf64_tailLoop
pf64_done:
	RET

// func prefetchStringCells(states *[3]uint64, count int, cellBase unsafe.Pointer, mask uint64)
// Uses state[0] (stride 24 bytes). PRFM PLDL1KEEP at cellBase + ((state[0] & mask) << 5).
TEXT ·prefetchStringCells(SB), NOSPLIT, $0-32
	MOVD states+0(FP), R0
	MOVD count+8(FP), R1
	MOVD cellBase+16(FP), R2
	MOVD mask+24(FP), R3

pfstr_loop8:
	SUBS $8, R1
	BLT  pfstr_tail

	MOVD 0(R0), R4;   MOVD 24(R0), R5;  MOVD 48(R0), R6;  MOVD 72(R0), R7
	MOVD 96(R0), R8;  MOVD 120(R0), R9; MOVD 144(R0), R10; MOVD 168(R0), R11
	ADD  $192, R0

	AND R3, R4;  LSL $5, R4;  ADD R2, R4;  PRFM (R4)
	AND R3, R5;  LSL $5, R5;  ADD R2, R5;  PRFM (R5)
	AND R3, R6;  LSL $5, R6;  ADD R2, R6;  PRFM (R6)
	AND R3, R7;  LSL $5, R7;  ADD R2, R7;  PRFM (R7)
	AND R3, R8;  LSL $5, R8;  ADD R2, R8;  PRFM (R8)
	AND R3, R9;  LSL $5, R9;  ADD R2, R9;  PRFM (R9)
	AND R3, R10; LSL $5, R10; ADD R2, R10; PRFM (R10)
	AND R3, R11; LSL $5, R11; ADD R2, R11; PRFM (R11)

	B pfstr_loop8

pfstr_tail:
	ADDS $8, R1
	BEQ  pfstr_done
pfstr_tailLoop:
	MOVD (R0), R4
	ADD  $24, R0
	AND R3, R4; LSL $5, R4; ADD R2, R4; PRFM (R4)
	SUBS $1, R1
	BNE  pfstr_tailLoop
pfstr_done:
	RET

// func prefetchRehashInt64Cells(cells *Int64HashMapCell, count int, cellBase unsafe.Pointer, mask uint64)
// Reads Key from each 16-byte cell, prefetches target slot in new table.
TEXT ·prefetchRehashInt64Cells(SB), NOSPLIT, $0-32
	MOVD cells+0(FP), R0
	MOVD count+8(FP), R1
	MOVD cellBase+16(FP), R2
	MOVD mask+24(FP), R3

rhi64_loop8:
	SUBS $8, R1
	BLT  rhi64_tail

	MOVD 0(R0), R4;  MOVD 16(R0), R5;  MOVD 32(R0), R6;  MOVD 48(R0), R7
	MOVD 64(R0), R8; MOVD 80(R0), R9;  MOVD 96(R0), R10; MOVD 112(R0), R11
	ADD  $128, R0

	AND R3, R4;  LSL $4, R4;  ADD R2, R4;  PRFM (R4)
	AND R3, R5;  LSL $4, R5;  ADD R2, R5;  PRFM (R5)
	AND R3, R6;  LSL $4, R6;  ADD R2, R6;  PRFM (R6)
	AND R3, R7;  LSL $4, R7;  ADD R2, R7;  PRFM (R7)
	AND R3, R8;  LSL $4, R8;  ADD R2, R8;  PRFM (R8)
	AND R3, R9;  LSL $4, R9;  ADD R2, R9;  PRFM (R9)
	AND R3, R10; LSL $4, R10; ADD R2, R10; PRFM (R10)
	AND R3, R11; LSL $4, R11; ADD R2, R11; PRFM (R11)

	B rhi64_loop8

rhi64_tail:
	ADDS $8, R1
	BEQ  rhi64_done
rhi64_tailLoop:
	MOVD (R0), R4
	ADD  $16, R0
	AND R3, R4; LSL $4, R4; ADD R2, R4; PRFM (R4)
	SUBS $1, R1
	BNE  rhi64_tailLoop
rhi64_done:
	RET

// func prefetchRehashStringCells(cells *StringHashMapCell, count int, cellBase unsafe.Pointer, mask uint64)
// Reads HashState[0] from each 32-byte cell, prefetches target slot in new table.
TEXT ·prefetchRehashStringCells(SB), NOSPLIT, $0-32
	MOVD cells+0(FP), R0
	MOVD count+8(FP), R1
	MOVD cellBase+16(FP), R2
	MOVD mask+24(FP), R3

rhstr_loop8:
	SUBS $8, R1
	BLT  rhstr_tail

	MOVD 0(R0), R4;   MOVD 32(R0), R5;  MOVD 64(R0), R6;  MOVD 96(R0), R7
	MOVD 128(R0), R8; MOVD 160(R0), R9; MOVD 192(R0), R10; MOVD 224(R0), R11
	ADD  $256, R0

	AND R3, R4;  LSL $5, R4;  ADD R2, R4;  PRFM (R4)
	AND R3, R5;  LSL $5, R5;  ADD R2, R5;  PRFM (R5)
	AND R3, R6;  LSL $5, R6;  ADD R2, R6;  PRFM (R6)
	AND R3, R7;  LSL $5, R7;  ADD R2, R7;  PRFM (R7)
	AND R3, R8;  LSL $5, R8;  ADD R2, R8;  PRFM (R8)
	AND R3, R9;  LSL $5, R9;  ADD R2, R9;  PRFM (R9)
	AND R3, R10; LSL $5, R10; ADD R2, R10; PRFM (R10)
	AND R3, R11; LSL $5, R11; ADD R2, R11; PRFM (R11)

	B rhstr_loop8

rhstr_tail:
	ADDS $8, R1
	BEQ  rhstr_done
rhstr_tailLoop:
	MOVD (R0), R4
	ADD  $32, R0
	AND R3, R4; LSL $5, R4; ADD R2, R4; PRFM (R4)
	SUBS $1, R1
	BNE  rhstr_tailLoop
rhstr_done:
	RET
