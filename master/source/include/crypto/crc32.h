#ifndef __INCLUDE_CRYPTO_CRC32_H
#define __INCLUDE_CRYPTO_CRC32_H

DWORD
(* Crc32SumBuffer)(
    IN PVOID  pBuffer,
    IN SIZE_T cbBuffer
    );

DWORD
FastCrc32SumBuffer(
    IN PVOID  pBuffer,
    IN SIZE_T cbBuffer
    );

DWORD
SlowCrc32SumBuffer(
    IN PVOID  pBuffer,
    IN SIZE_T cbBuffer
    );

#endif
