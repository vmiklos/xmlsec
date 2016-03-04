/**
 * XMLSec library
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 *
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#include "globals.h"

#include <string.h>

#include <nss.h>
#include <pk11func.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>

#include <xmlsec/nss/ciphers.h>

/**************************************************************************
 *
 * Internal Nss Block Cipher Context
 * This context is designed for repositing a block cipher for transform
 *
 *****************************************************************************/
typedef struct _xmlSecNssBlockCipherCtx                xmlSecNssBlockCipherCtx ;
typedef struct _xmlSecNssBlockCipherCtx*       xmlSecNssBlockCipherCtxPtr ;

struct _xmlSecNssBlockCipherCtx {
    CK_MECHANISM_TYPE   cipher;
    PK11SymKey*         symkey ;
    PK11Context*        cipherCtx;
    xmlSecKeyDataId     keyId;
};

#define xmlSecNssBlockCipherSize       \
       ( sizeof( xmlSecTransform ) + sizeof( xmlSecNssBlockCipherCtx ) )

#define xmlSecNssBlockCipherGetCtx( transform ) \
       ( ( xmlSecNssBlockCipherCtxPtr )( ( ( xmlSecByte* )( transform ) ) + sizeof( xmlSecTransform ) ) )

static int
xmlSecNssBlockCipherCheckId(
       xmlSecTransformPtr transform
) {
       #ifndef XMLSEC_NO_DES
       if( xmlSecTransformCheckId( transform, xmlSecNssTransformDes3CbcId ) ) {
               return 1 ;
       }
       #endif /* XMLSEC_NO_DES */

       #ifndef XMLSEC_NO_AES
       if( xmlSecTransformCheckId( transform, xmlSecNssTransformAes128CbcId ) ||
               xmlSecTransformCheckId( transform, xmlSecNssTransformAes192CbcId ) ||
               xmlSecTransformCheckId( transform, xmlSecNssTransformAes256CbcId ) ) {

               return 1 ;
    }
       #endif /* XMLSEC_NO_AES */
    
    return 0 ;
}

static int
xmlSecNssBlockCipherFetchCtx(
       xmlSecNssBlockCipherCtxPtr              context ,
       xmlSecTransformId                               id
) {
       xmlSecAssert2( context != NULL, -1 ) ;

       #ifndef XMLSEC_NO_DES
       if( id == xmlSecNssTransformDes3CbcId ) {
               context->cipher = CKM_DES3_CBC ;
               context->keyId = xmlSecNssKeyDataDesId ;
       } else
       #endif          /* XMLSEC_NO_DES */

       #ifndef XMLSEC_NO_AES
       if( id == xmlSecNssTransformAes128CbcId ) {
               context->cipher = CKM_AES_CBC ;
               context->keyId = xmlSecNssKeyDataAesId ;
       } else
       if( id == xmlSecNssTransformAes192CbcId ) {
               context->cipher = CKM_AES_CBC ;
               context->keyId = xmlSecNssKeyDataAesId ;
       } else
       if( id == xmlSecNssTransformAes256CbcId ) {
               context->cipher = CKM_AES_CBC ;
               context->keyId = xmlSecNssKeyDataAesId ;
       } else
       #endif          /* XMLSEC_NO_AES */

       if( 1 ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                   NULL ,
                   NULL ,
                   XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                   XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;    
       }

       return 0 ;
}

/**
 * xmlSecTransformInitializeMethod:
 * @transform:                 the pointer to transform object.
 *
 * The transform specific initialization method.
 *
 * Returns 0 on success or a negative value otherwise.
 */
static int
xmlSecNssBlockCipherInitialize(
       xmlSecTransformPtr transform
) {
       xmlSecNssBlockCipherCtxPtr context = NULL ;

       xmlSecAssert2( xmlSecNssBlockCipherCheckId( transform ), -1 ) ;
       xmlSecAssert2( xmlSecTransformCheckSize( transform, xmlSecNssBlockCipherSize ), -1 ) ;

       context = xmlSecNssBlockCipherGetCtx( transform ) ;
       if( context == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                   xmlSecErrorsSafeString( xmlSecTransformGetName( transform ) ) ,
                   "xmlSecNssBlockCipherGetCtx" ,
                   XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                   XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;    
       }

       if( xmlSecNssBlockCipherFetchCtx( context , transform->id ) < 0 ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                   xmlSecErrorsSafeString( xmlSecTransformGetName( transform ) ) ,
                   "xmlSecNssBlockCipherFetchCtx" ,
                   XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                   XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;    
       }

       context->symkey = NULL ;
       context->cipherCtx = NULL ;

       return 0 ;
}

/**
 * xmlSecTransformFinalizeMethod:
 * @transform:                 the pointer to transform object.
 *
 * The transform specific destroy method.
 */
static void 
xmlSecNssBlockCipherFinalize(
       xmlSecTransformPtr transform
) {
       xmlSecNssBlockCipherCtxPtr context = NULL ;

       xmlSecAssert( xmlSecNssBlockCipherCheckId( transform ) ) ;
       xmlSecAssert( xmlSecTransformCheckSize( transform, xmlSecNssBlockCipherSize ) ) ;

       context = xmlSecNssBlockCipherGetCtx( transform ) ;
       if( context == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                   xmlSecErrorsSafeString( xmlSecTransformGetName( transform ) ) ,
                   "xmlSecNssBlockCipherGetCtx" ,
                   XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                   XMLSEC_ERRORS_NO_MESSAGE ) ;
               return ;    
       }

       if( context->cipherCtx != NULL ) {
               PK11_DestroyContext( context->cipherCtx, PR_TRUE ) ;
               context->cipherCtx = NULL ;
       }

       if( context->symkey != NULL ) {
               PK11_FreeSymKey( context->symkey ) ;
               context->symkey = NULL ;
       }

       context->cipher = CKM_INVALID_MECHANISM ;
       context->keyId = NULL ;
}

/**
 * xmlSecTransformSetKeyRequirementsMethod:
 * @transform:                 the pointer to transform object.
 * @keyReq:                            the pointer to key requirements structure.
 *
 * Transform specific method to set transform's key requirements.
 * 
 * Returns 0 on success or a negative value otherwise.
 */
static int  
xmlSecNssBlockCipherSetKeyReq(
       xmlSecTransformPtr transform ,
       xmlSecKeyReqPtr keyReq
) {
       xmlSecNssBlockCipherCtxPtr context = NULL ;
       xmlSecSize cipherSize = 0 ;

       xmlSecAssert2( xmlSecNssBlockCipherCheckId( transform ), -1 ) ;
       xmlSecAssert2( xmlSecTransformCheckSize( transform, xmlSecNssBlockCipherSize ), -1 ) ;
       xmlSecAssert2( keyReq != NULL , -1 ) ;
       xmlSecAssert2( ( transform->operation == xmlSecTransformOperationEncrypt ) || ( transform->operation == xmlSecTransformOperationDecrypt ), -1 ) ;

       context = xmlSecNssBlockCipherGetCtx( transform ) ;
       if( context == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                   xmlSecErrorsSafeString( xmlSecTransformGetName( transform ) ) ,
                   "xmlSecNssBlockCipherGetCtx" ,
                   XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                   XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;    
       }

       keyReq->keyId = context->keyId ;
       keyReq->keyType = xmlSecKeyDataTypeSymmetric ;

       if( transform->operation == xmlSecTransformOperationEncrypt ) {
               keyReq->keyUsage = xmlSecKeyUsageEncrypt ;
       } else {
               keyReq->keyUsage = xmlSecKeyUsageDecrypt ;
       }

       /*
       if( context->symkey != NULL )
               cipherSize = PK11_GetKeyLength( context->symkey ) ; 

       keyReq->keyBitsSize = cipherSize * 8 ;
       */

       return 0 ;
}

/**
 * xmlSecTransformSetKeyMethod:
 * @transform:                 the pointer to transform object.
 * @key:                               the pointer to key.
 *
 * The transform specific method to set the key for use.
 * 
 * Returns 0 on success or a negative value otherwise.
 */
static int
xmlSecNssBlockCipherSetKey(
       xmlSecTransformPtr transform ,
       xmlSecKeyPtr key
) {
       xmlSecNssBlockCipherCtxPtr context = NULL ;
       xmlSecKeyDataPtr        keyData = NULL ;
       PK11SymKey*                     symkey = NULL ;
       CK_ATTRIBUTE_TYPE       operation ;
       int                                     ivLen ;

       xmlSecAssert2( xmlSecNssBlockCipherCheckId( transform ), -1 ) ;
       xmlSecAssert2( xmlSecTransformCheckSize( transform, xmlSecNssBlockCipherSize ), -1 ) ;
       xmlSecAssert2( key != NULL , -1 ) ;
    xmlSecAssert2( ( transform->operation == xmlSecTransformOperationEncrypt ) || ( transform->operation == xmlSecTransformOperationDecrypt ), -1 ) ;

       context = xmlSecNssBlockCipherGetCtx( transform ) ;
       if( context == NULL || context->keyId == NULL || context->symkey != NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                   xmlSecErrorsSafeString( xmlSecTransformGetName( transform ) ) ,
                   "xmlSecNssBlockCipherGetCtx" ,
                   XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                   XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;    
       }
       xmlSecAssert2( xmlSecKeyCheckId( key, context->keyId ), -1 ) ;

       keyData = xmlSecKeyGetValue( key ) ;
       if( keyData == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                   xmlSecErrorsSafeString( xmlSecKeyGetName( key ) ) ,
                   "xmlSecKeyGetValue" ,
                   XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                   XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;    
       }

       if( ( symkey = xmlSecNssSymKeyDataGetKey( keyData ) ) == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                   xmlSecErrorsSafeString( xmlSecKeyDataGetName( keyData ) ) ,
                   "xmlSecNssSymKeyDataGetKey" ,
                   XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                   XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;    
       }

       context->symkey = symkey ;

       return 0 ;
}

static int
xmlSecNssBlockCipherCtxInit(xmlSecNssBlockCipherCtxPtr ctx,
                                xmlSecBufferPtr in, xmlSecBufferPtr out,
                                int encrypt,
                                const xmlChar* cipherName,
                                xmlSecTransformCtxPtr transformCtx) {
    SECItem ivItem;
    SECItem* secParam = NULL ;
    xmlSecBufferPtr ivBuf = NULL ;
    int ivLen;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2( ctx->cipher != CKM_INVALID_MECHANISM , -1 ) ;
    xmlSecAssert2( ctx->symkey != NULL , -1 ) ;
    xmlSecAssert2(ctx->cipherCtx == NULL, -1);
    xmlSecAssert2( ctx->keyId != NULL , -1 ) ;
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    ivLen = PK11_GetIVLength(ctx->cipher);
    if( ivLen < 0 ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                    NULL ,
                    "PK11_GetIVLength" ,
                    XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                    XMLSEC_ERRORS_NO_MESSAGE ) ;
            return -1 ;    
    }

    if( ( ivBuf = xmlSecBufferCreate( ivLen ) ) == NULL ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                    NULL ,
                    "xmlSecBufferCreate" ,
                    XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                    XMLSEC_ERRORS_NO_MESSAGE ) ;
            return -1 ;    
    }

    if(encrypt) {
        if( PK11_GenerateRandom( ivBuf->data , ivLen ) != SECSuccess ) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(cipherName),
                        "PK11_GenerateRandom",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecBufferDestroy( ivBuf ) ;
            return(-1);
        }
        if( xmlSecBufferSetSize( ivBuf , ivLen ) < 0 ) {
                xmlSecError( XMLSEC_ERRORS_HERE ,
                        NULL ,
                        "xmlSecBufferSetSize" ,
                        XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                        XMLSEC_ERRORS_NO_MESSAGE ) ;
                xmlSecBufferDestroy( ivBuf ) ;
                return -1 ;  
        }

       if( xmlSecBufferAppend( out , ivBuf->data , ivLen ) < 0 ) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(cipherName),
                        "xmlSecBufferAppend",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecBufferDestroy( ivBuf ) ;
            return(-1);
        }

    } else {
	    if( xmlSecBufferSetData( ivBuf , in->data , ivLen ) < 0 ) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(cipherName),
                        "xmlSecBufferSetData",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecBufferDestroy( ivBuf ) ;
            return(-1);
        }
    }

    if( xmlSecBufferRemoveHead( in , ivLen ) < 0 ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "xmlSecBufferRemoveHead",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferDestroy( ivBuf ) ;
        return(-1);
    }

    ivItem.data = xmlSecBufferGetData( ivBuf ) ;
    ivItem.len = xmlSecBufferGetSize( ivBuf ) ;
    if( ( secParam = PK11_ParamFromIV( ctx->cipher , &ivItem ) ) == NULL ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "PK11_ParamFromIV",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
	xmlSecBufferDestroy( ivBuf ) ;
        return(-1);
    }

    ctx->cipherCtx = PK11_CreateContextBySymKey(ctx->cipher,
                        (encrypt) ? CKA_ENCRYPT : CKA_DECRYPT,
                        ctx->symkey, secParam);
    if(ctx->cipherCtx == NULL) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "xmlSecBufferRemoveHead",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
	SECITEM_FreeItem( secParam , PR_TRUE ) ;
	xmlSecBufferDestroy( ivBuf ) ;
        return(-1);
    }

    SECITEM_FreeItem( secParam , PR_TRUE ) ;
    xmlSecBufferDestroy( ivBuf ) ;
    return(0);
}

/**
 * Block cipher transform update
 */
static int
xmlSecNssBlockCipherCtxUpdate(xmlSecNssBlockCipherCtxPtr ctx,
                                  xmlSecBufferPtr in, xmlSecBufferPtr out,
                                  int encrypt,
                                  const xmlChar* cipherName,
                                  xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize inSize, inBlocks, outSize;
    int blockSize;
    int outLen = 0;
    xmlSecByte* outBuf;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2( ctx->cipher != CKM_INVALID_MECHANISM , -1 ) ;
    xmlSecAssert2( ctx->symkey != NULL , -1 ) ;
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2( ctx->keyId != NULL , -1 ) ;
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if( ( blockSize = PK11_GetBlockSize( ctx->cipher , NULL ) ) < 0 ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString( cipherName ) ,
            "PK11_GetBlockSize" ,
            XMLSEC_ERRORS_R_CRYPTO_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;
        return -1 ;    
    }

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);
    
    inBlocks = ( encrypt != 0 ? inSize : ( inSize - 1 ) ) / blockSize ;
    inSize = inBlocks * blockSize ;

    if( inSize < blockSize ) {
        return 0 ;
    }

    if( xmlSecBufferSetMaxSize( out , outSize + inSize + blockSize ) < 0 ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "xmlSecBufferSetMaxSize",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;

    if(PK11_CipherOp( ctx->cipherCtx , outBuf , &outLen , inSize + blockSize , xmlSecBufferGetData( in ) , inSize ) != SECSuccess ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "PK11_CipherOp",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    if( xmlSecBufferSetSize( out , outSize + outLen ) < 0 ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "xmlSecBufferSetSize",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    if( xmlSecBufferRemoveHead( in , inSize ) < 0 ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "xmlSecBufferRemoveHead",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    return(0);
}

static int
xmlSecNssBlockCipherCtxFinal(xmlSecNssBlockCipherCtxPtr ctx,
                                 xmlSecBufferPtr in,
                                 xmlSecBufferPtr out,
                                 int encrypt,
                                 const xmlChar* cipherName,
                                 xmlSecTransformCtxPtr transformCtx) {
    xmlSecSize inSize, outSize;
    int blockSize, outLen = 0;
    xmlSecByte* inBuf;
    xmlSecByte* outBuf;

    xmlSecAssert2(ctx != NULL, -1);
    xmlSecAssert2( ctx->cipher != CKM_INVALID_MECHANISM , -1 ) ;
    xmlSecAssert2( ctx->symkey != NULL , -1 ) ;
    xmlSecAssert2(ctx->cipherCtx != NULL, -1);
    xmlSecAssert2( ctx->keyId != NULL , -1 ) ;
    xmlSecAssert2(in != NULL, -1);
    xmlSecAssert2(out != NULL, -1);
    xmlSecAssert2(transformCtx != NULL, -1);

    if( ( blockSize = PK11_GetBlockSize( ctx->cipher , NULL ) ) < 0 ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString( cipherName ) ,
            "PK11_GetBlockSize" ,
            XMLSEC_ERRORS_R_CRYPTO_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;
        return -1 ;    
    }

    inSize = xmlSecBufferGetSize(in);
    outSize = xmlSecBufferGetSize(out);

    /******************************************************************/
    if(encrypt != 0) {
        xmlSecAssert2( inSize < blockSize, -1 ) ;

        /* create padding */
	if( xmlSecBufferSetMaxSize( in , blockSize ) < 0 ) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(cipherName),
                        "xmlSecBufferSetMaxSize",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
        inBuf = xmlSecBufferGetData(in);

	/* generate random */
	if( blockSize > ( inSize + 1 ) ) {
	    if( PK11_GenerateRandom( inBuf + inSize, blockSize - inSize - 1 ) != SECSuccess ) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(cipherName),
                            "PK11_GenerateRandom",
                            XMLSEC_ERRORS_R_CRYPTO_FAILED,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        }
	inBuf[blockSize-1] = blockSize - inSize ;
	inSize = blockSize ;
    } else {
        if( inSize != blockSize ) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(cipherName),
                        NULL,
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
    }

    /* process the last block */
    if( xmlSecBufferSetMaxSize( out , outSize + inSize + blockSize ) < 0 ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "xmlSecBufferSetMaxSize",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }
    outBuf = xmlSecBufferGetData(out) + outSize;

    if( PK11_CipherOp( ctx->cipherCtx , outBuf , &outLen , inSize + blockSize , xmlSecBufferGetData( in ) , inSize ) != SECSuccess ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "PK11_CipherOp",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    if(encrypt == 0) {
        /* check padding */
	if( outLen < outBuf[blockSize-1] ) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(cipherName),
                        NULL,
			XMLSEC_ERRORS_R_CRYPTO_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
            return(-1);
        }
	outLen -= outBuf[blockSize-1] ;
    }

    /******************************************************************/

    /******************************************************************
    if( xmlSecBufferSetMaxSize( out , outSize + blockSize ) < 0 ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(cipherName),
                    "xmlSecBufferSetMaxSize",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
                    XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    outBuf = xmlSecBufferGetData( out ) + outSize ;
    if( PK11_DigestFinal( ctx->cipherCtx , outBuf , &outLen , blockSize ) != SECSuccess ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                    xmlSecErrorsSafeString( cipherName ) ,
                    "PK11_DigestFinal" ,
                    XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                    XMLSEC_ERRORS_NO_MESSAGE ) ;
            return -1 ;    
    }
    ******************************************************************/

    if( xmlSecBufferSetSize( out , outSize + outLen ) < 0 ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                    xmlSecErrorsSafeString( cipherName ) ,
                    "xmlSecBufferSetSize" ,
                    XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                    XMLSEC_ERRORS_NO_MESSAGE ) ;
            return -1 ;    
    }
    if( xmlSecBufferRemoveHead( in , inSize ) < 0 ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                    xmlSecErrorsSafeString( cipherName ) ,
                    "xmlSecBufferRemoveHead" ,
                    XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                    XMLSEC_ERRORS_NO_MESSAGE ) ;
            return -1 ;    
    }
/*    PK11_Finalize( ctx->cipherCtx ) ;*/
    PK11_DestroyContext(ctx->cipherCtx, PR_TRUE);
    ctx->cipherCtx = NULL ;

    return(0);
}

/**
 * xmlSecTransformExecuteMethod:
 * @transform:                 the pointer to transform object.
 * @last:                      the flag: if set to 1 then it's the last data chunk.
 * @transformCtx:              the pointer to transform context object.
 *
 * Transform specific method to process a chunk of data.
 *
 * Returns 0 on success or a negative value otherwise.
 */
xmlSecNssBlockCipherExecute(
    xmlSecTransformPtr transform ,
    int last ,
    xmlSecTransformCtxPtr transformCtx
) {
    xmlSecNssBlockCipherCtxPtr context = NULL ;
    xmlSecBufferPtr inBuf = NULL ;
    xmlSecBufferPtr outBuf = NULL ;
    const xmlChar* cipherName ;
    int operation ;
    int rtv ;

    xmlSecAssert2(xmlSecNssBlockCipherCheckId(transform), -1);
    xmlSecAssert2(xmlSecTransformCheckSize(transform, xmlSecNssBlockCipherSize), -1);

    xmlSecAssert2( ( transform->operation == xmlSecTransformOperationEncrypt ) || ( transform->operation == xmlSecTransformOperationDecrypt ), -1 ) ;
    xmlSecAssert2( transformCtx != NULL , -1 ) ;

    context = xmlSecNssBlockCipherGetCtx( transform ) ;
    if( context == NULL ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
		    "xmlSecNssBlockCipherGetCtx" ,
		    XMLSEC_ERRORS_R_CRYPTO_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
    }


    inBuf = &( transform->inBuf ) ;
    outBuf = &( transform->outBuf ) ;

    if(transform->status == xmlSecTransformStatusNone) {
        transform->status = xmlSecTransformStatusWorking;
    }

    operation = ( transform->operation == xmlSecTransformOperationEncrypt ) ? 1 : 0 ;
    cipherName = xmlSecTransformGetName( transform ) ;

    if(transform->status == xmlSecTransformStatusWorking) {
        if( context->cipherCtx == NULL ) {
	    rtv = xmlSecNssBlockCipherCtxInit( context, inBuf , outBuf , operation , cipherName , transformCtx ) ;
	    if( rtv < 0 ) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecNssBlockCipherCtxInit",
                            XMLSEC_ERRORS_R_INVALID_STATUS,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        }
	if( context->cipherCtx == NULL && last != 0 ) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                        NULL,
                        XMLSEC_ERRORS_R_INVALID_STATUS,
                        "not enough data to initialize transform");
            return(-1);
        }

	if( context->cipherCtx != NULL ) {
	    rtv = xmlSecNssBlockCipherCtxUpdate( context, inBuf , outBuf , operation , cipherName , transformCtx ) ;
	    if( rtv < 0 ) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecNssBlockCipherCtxUpdate",
                            XMLSEC_ERRORS_R_INVALID_STATUS,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
        }

        if(last) {
	    rtv = xmlSecNssBlockCipherCtxFinal( context, inBuf , outBuf , operation , cipherName , transformCtx ) ;
	    if( rtv < 0 ) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                            xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                            "xmlSecNssBlockCipherCtxFinal",
                            XMLSEC_ERRORS_R_INVALID_STATUS,
                            XMLSEC_ERRORS_NO_MESSAGE);
                return(-1);
            }
            transform->status = xmlSecTransformStatusFinished;
        }
    } else if(transform->status == xmlSecTransformStatusFinished) {
        if( xmlSecBufferGetSize( inBuf ) != 0 ) {
            xmlSecError( XMLSEC_ERRORS_HERE , 
                    xmlSecErrorsSafeString( xmlSecTransformGetName( transform ) ) ,
                    NULL ,
                    XMLSEC_ERRORS_R_INVALID_STATUS ,
                    "status=%d", transform->status ) ;
            return -1 ;
        }
    } else {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecTransformGetName(transform)),
                    NULL,
                    XMLSEC_ERRORS_R_INVALID_STATUS,
                    "status=%d", transform->status);
        return(-1);
    }

    return(0);
}


#ifndef XMLSEC_NO_AES
/*********************************************************************
 *
 * AES CBC cipher transforms
 *
 ********************************************************************/
static xmlSecTransformKlass xmlSecNssAes128CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssBlockCipherSize,           /* xmlSecSize objSize */

    xmlSecNameAes128Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes128Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssBlockCipherInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssBlockCipherFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssBlockCipherSetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssBlockCipherSetKey,         /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssBlockCipherExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformAes128CbcGetKlass:
 *
 * AES 128 CBC encryption transform klass.
 *
 * Returns: pointer to AES 128 CBC encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes128CbcGetKlass(void) {
    return(&xmlSecNssAes128CbcKlass);
}

static xmlSecTransformKlass xmlSecNssAes192CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssBlockCipherSize,           /* xmlSecSize objSize */

    xmlSecNameAes192Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes192Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssBlockCipherInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssBlockCipherFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssBlockCipherSetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssBlockCipherSetKey,         /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssBlockCipherExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformAes192CbcGetKlass:
 *
 * AES 192 CBC encryption transform klass.
 *
 * Returns: pointer to AES 192 CBC encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes192CbcGetKlass(void) {
    return(&xmlSecNssAes192CbcKlass);
}

static xmlSecTransformKlass xmlSecNssAes256CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssBlockCipherSize,           /* xmlSecSize objSize */

    xmlSecNameAes256Cbc,                        /* const xmlChar* name; */
    xmlSecHrefAes256Cbc,                        /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssBlockCipherInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssBlockCipherFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssBlockCipherSetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssBlockCipherSetKey,         /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssBlockCipherExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformAes256CbcGetKlass:
 *
 * AES 256 CBC encryption transform klass.
 *
 * Returns: pointer to AES 256 CBC encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformAes256CbcGetKlass(void) {
    return(&xmlSecNssAes256CbcKlass);
}

#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
static xmlSecTransformKlass xmlSecNssDes3CbcKlass = {
    /* klass/object sizes */
    sizeof(xmlSecTransformKlass),               /* xmlSecSize klassSize */
    xmlSecNssBlockCipherSize,           /* xmlSecSize objSize */

    xmlSecNameDes3Cbc,                          /* const xmlChar* name; */
    xmlSecHrefDes3Cbc,                          /* const xmlChar* href; */
    xmlSecTransformUsageEncryptionMethod,       /* xmlSecAlgorithmUsage usage; */

    xmlSecNssBlockCipherInitialize,             /* xmlSecTransformInitializeMethod initialize; */
    xmlSecNssBlockCipherFinalize,               /* xmlSecTransformFinalizeMethod finalize; */
    NULL,                                       /* xmlSecTransformNodeReadMethod readNode; */
    NULL,                                       /* xmlSecTransformNodeWriteMethod writeNode; */
    xmlSecNssBlockCipherSetKeyReq,              /* xmlSecTransformSetKeyMethod setKeyReq; */
    xmlSecNssBlockCipherSetKey,         /* xmlSecTransformSetKeyMethod setKey; */
    NULL,                                       /* xmlSecTransformValidateMethod validate; */
    xmlSecTransformDefaultGetDataType,          /* xmlSecTransformGetDataTypeMethod getDataType; */
    xmlSecTransformDefaultPushBin,              /* xmlSecTransformPushBinMethod pushBin; */
    xmlSecTransformDefaultPopBin,               /* xmlSecTransformPopBinMethod popBin; */
    NULL,                                       /* xmlSecTransformPushXmlMethod pushXml; */
    NULL,                                       /* xmlSecTransformPopXmlMethod popXml; */
    xmlSecNssBlockCipherExecute,                /* xmlSecTransformExecuteMethod execute; */

    NULL,                                       /* void* reserved0; */
    NULL,                                       /* void* reserved1; */
};

/**
 * xmlSecNssTransformDes3CbcGetKlass:
 *
 * Triple DES CBC encryption transform klass.
 *
 * Returns: pointer to Triple DES encryption transform.
 */
xmlSecTransformId
xmlSecNssTransformDes3CbcGetKlass(void) {
    return(&xmlSecNssDes3CbcKlass);
}
#endif /* XMLSEC_NO_DES */

