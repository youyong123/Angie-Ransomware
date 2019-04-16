#ifndef __INCLUDE_CRYPTO_LZO1_H
#define __INCLUDE_CRYPTO_LZO1_H

VOID
Lzo1Decompress(
    IN  PVOID   Source,
    IN  SIZE_T  cbSource,
    OUT PVOID   Destination
    );

#endif
