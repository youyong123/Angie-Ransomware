
VOID
AesEncryptBlock(
    IO PVOID PlainText,
    IN PVOID Key
    )
{
    M128I xwBlock = _mm_load_si128((PM128I)PlainText);
    xwBlock = _mm_xor_si128       (xwBlock, ((PM128I)Key)[ 0]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 1]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 2]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 3]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 4]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 5]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 6]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 7]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 8]);
    xwBlock = _mm_aesenc_si128    (xwBlock, ((PM128I)Key)[ 9]);
    xwBlock = _mm_aesenclast_si128(xwBlock, ((PM128I)Key)[10]);
    _mm_stream_si128((PM128I)PlainText, xwBlock);
}

VOID
AesDecryptBlock(
    IO PVOID CipherText,
    IN PVOID Key
    )
{
    M128I xwBlock = _mm_load_si128((PM128I)CipherText);
    xwBlock = _mm_xor_si128       (xwBlock, ((PM128I)Key)[10]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[11]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[12]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[13]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[14]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[15]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[16]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[17]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[18]);
    xwBlock = _mm_aesdec_si128    (xwBlock, ((PM128I)Key)[19]);
    xwBlock = _mm_aesdeclast_si128(xwBlock, ((PM128I)Key)[ 0]);
    _mm_stream_si128((PM128I)CipherText, xwBlock);
}

static
M128I
FORCEINLINE
KeyExpansion(
    IN M128I xwKey,
    IN M128I xwKeyGenerated
    )
{
    xwKeyGenerated = _mm_shuffle_epi32(xwKeyGenerated, _MM_SHUFFLE(3, 3, 3, 3));
    xwKey = _mm_xor_si128(xwKey, _mm_slli_si128(xwKey, 4));
    xwKey = _mm_xor_si128(xwKey, _mm_slli_si128(xwKey, 4));
    xwKey = _mm_xor_si128(xwKey, _mm_slli_si128(xwKey, 4));

    return _mm_xor_si128(xwKey, xwKeyGenerated);
}

VOID
AesSetEncryptionKey(
    IN  PVOID Key,
    OUT PVOID ExpandedKey
    )
{
    PM128I KeySchedule = ExpandedKey;
    KeySchedule[ 0] = _mm_load_si128((PM128I)Key);
    KeySchedule[ 1] = KeyExpansion(KeySchedule[0], _mm_aeskeygenassist_si128(KeySchedule[0], 0x01));
    KeySchedule[ 2] = KeyExpansion(KeySchedule[1], _mm_aeskeygenassist_si128(KeySchedule[1], 0x02));
    KeySchedule[ 3] = KeyExpansion(KeySchedule[2], _mm_aeskeygenassist_si128(KeySchedule[2], 0x04));
    KeySchedule[ 4] = KeyExpansion(KeySchedule[3], _mm_aeskeygenassist_si128(KeySchedule[3], 0x08));
    KeySchedule[ 5] = KeyExpansion(KeySchedule[4], _mm_aeskeygenassist_si128(KeySchedule[4], 0x10));
    KeySchedule[ 6] = KeyExpansion(KeySchedule[5], _mm_aeskeygenassist_si128(KeySchedule[5], 0x20));
    KeySchedule[ 7] = KeyExpansion(KeySchedule[6], _mm_aeskeygenassist_si128(KeySchedule[6], 0x40));
    KeySchedule[ 8] = KeyExpansion(KeySchedule[7], _mm_aeskeygenassist_si128(KeySchedule[7], 0x80));
    KeySchedule[ 9] = KeyExpansion(KeySchedule[8], _mm_aeskeygenassist_si128(KeySchedule[8], 0x1B));
    KeySchedule[10] = KeyExpansion(KeySchedule[9], _mm_aeskeygenassist_si128(KeySchedule[9], 0x36));

    KeySchedule[11] = _mm_aesimc_si128(KeySchedule[9]);
    KeySchedule[12] = _mm_aesimc_si128(KeySchedule[8]);
    KeySchedule[13] = _mm_aesimc_si128(KeySchedule[7]);
    KeySchedule[14] = _mm_aesimc_si128(KeySchedule[6]);
    KeySchedule[15] = _mm_aesimc_si128(KeySchedule[5]);
    KeySchedule[16] = _mm_aesimc_si128(KeySchedule[4]);
    KeySchedule[17] = _mm_aesimc_si128(KeySchedule[3]);
    KeySchedule[18] = _mm_aesimc_si128(KeySchedule[2]);
    KeySchedule[19] = _mm_aesimc_si128(KeySchedule[1]);
}
