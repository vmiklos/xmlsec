/** 
 *
 * XMLSec library
 * 
 * DES Algorithm support
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pk11func.h>
#include <nss.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/transforms.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/ciphers.h>
#include <xmlsec/nss/tokens.h>

/*****************************************************************************
 * 
 * Symmetic (binary) keys - a wrapper over slot information and PK11SymKey
 *
 ****************************************************************************/
typedef struct _xmlSecNssSymKeyDataCtx      xmlSecNssSymKeyDataCtx ;
typedef struct _xmlSecNssSymKeyDataCtx*     xmlSecNssSymKeyDataCtxPtr ;

struct _xmlSecNssSymKeyDataCtx {
    CK_MECHANISM_TYPE       cipher ;    /* the symmetic key mechanism */
    PK11SlotInfo*           slot ;      /* the key resident slot */
    PK11SymKey*             symkey ;    /* the symmetic key */
} ;

#define xmlSecNssSymKeyDataSize \
    ( sizeof( xmlSecKeyData ) + sizeof( xmlSecNssSymKeyDataCtx ) )

#define xmlSecNssSymKeyDataGetCtx( data ) \
    ( ( xmlSecNssSymKeyDataCtxPtr )( ( ( xmlSecByte* )( data ) ) + sizeof( xmlSecKeyData ) ) )

static int	xmlSecNssSymKeyDataInitialize		(xmlSecKeyDataPtr data);
static int	xmlSecNssSymKeyDataDuplicate		(xmlSecKeyDataPtr dst,
							 xmlSecKeyDataPtr src);
static void	xmlSecNssSymKeyDataFinalize		(xmlSecKeyDataPtr data);
static int	xmlSecNssSymKeyDataXmlRead		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlNodePtr node,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecNssSymKeyDataXmlWrite		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlNodePtr node,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecNssSymKeyDataBinRead		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 const xmlSecByte* buf,
							 xmlSecSize bufSize,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecNssSymKeyDataBinWrite		(xmlSecKeyDataId id,
							 xmlSecKeyPtr key,
							 xmlSecByte** buf,
							 xmlSecSize* bufSize,
							 xmlSecKeyInfoCtxPtr keyInfoCtx);
static int	xmlSecNssSymKeyDataGenerate		(xmlSecKeyDataPtr data,
							 xmlSecSize sizeBits,
							 xmlSecKeyDataType type);

static xmlSecKeyDataType xmlSecNssSymKeyDataGetType	(xmlSecKeyDataPtr data);
static xmlSecSize	xmlSecNssSymKeyDataGetSize		(xmlSecKeyDataPtr data);
static void	xmlSecNssSymKeyDataDebugDump	(xmlSecKeyDataPtr data,
							 FILE* output);
static void	xmlSecNssSymKeyDataDebugXmlDump	(xmlSecKeyDataPtr data,
							 FILE* output);
static int	xmlSecNssSymKeyDataKlassCheck	(xmlSecKeyDataKlass* klass);

#define xmlSecNssSymKeyDataCheckId(data) \
    (xmlSecKeyDataIsValid((data)) && \
     xmlSecNssSymKeyDataKlassCheck((data)->id))

/**
 * xmlSecNssSymKeyDataAdoptKey:
 * @data:                              the pointer to symmetric key data.
 * @symkey:                            the symmetric key
 *
 * Set the value of symmetric key data.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssSymKeyDataAdoptKey(
       xmlSecKeyDataPtr data ,
       PK11SymKey* symkey
) {
       xmlSecNssSymKeyDataCtxPtr context = NULL ;

       xmlSecAssert2( xmlSecNssSymKeyDataCheckId( data ), -1 ) ;
       xmlSecAssert2( xmlSecKeyDataCheckSize( data, xmlSecNssSymKeyDataSize ), -1 ) ;
       xmlSecAssert2( symkey != NULL, -1 ) ;

       context = xmlSecNssSymKeyDataGetCtx( data ) ;
       xmlSecAssert2(context != NULL, -1);

       context->cipher = PK11_GetMechanism( symkey ) ;

       if( context->slot != NULL ) {
               PK11_FreeSlot( context->slot ) ;
               context->slot = NULL ;
       }
       context->slot = PK11_GetSlotFromKey( symkey ) ;

       if( context->symkey != NULL ) {
               PK11_FreeSymKey( context->symkey ) ;
               context->symkey = NULL ;
       }
       context->symkey = PK11_ReferenceSymKey( symkey ) ;

       return 0 ;
}

xmlSecKeyDataPtr xmlSecNssSymKeyDataKeyAdopt(
    PK11SymKey*     symKey
) {
       xmlSecKeyDataPtr        data = NULL ;
       CK_MECHANISM_TYPE       mechanism = CKM_INVALID_MECHANISM ;

       xmlSecAssert2( symKey != NULL , NULL ) ;

       mechanism = PK11_GetMechanism( symKey ) ;
       switch( mechanism ) {
               case CKM_DES3_KEY_GEN :
               case CKM_DES3_CBC :
               case CKM_DES3_MAC :
                       data = xmlSecKeyDataCreate( xmlSecNssKeyDataDesId ) ;
                       if( data == NULL ) {
                               xmlSecError( XMLSEC_ERRORS_HERE ,
                                       NULL ,
                                       "xmlSecKeyDataCreate" ,
                                       XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                                       "xmlSecNssKeyDataDesId" ) ;
                               return NULL ;
                       }
                       break ;
               case CKM_AES_KEY_GEN :
               case CKM_AES_CBC :
               case CKM_AES_MAC :
                       data = xmlSecKeyDataCreate( xmlSecNssKeyDataAesId ) ;
                       if( data == NULL ) {
                               xmlSecError( XMLSEC_ERRORS_HERE ,
                                       NULL ,
                                       "xmlSecKeyDataCreate" ,
                                       XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                                       "xmlSecNssKeyDataDesId" ) ;
                               return NULL ;
                       }
                       break ;
               default :
                       xmlSecError( XMLSEC_ERRORS_HERE ,
                               NULL ,
                               NULL ,
                               XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                               "Unsupported mechanism" ) ;
                       return NULL ;
       }

       if( xmlSecNssSymKeyDataAdoptKey( data , symKey ) < 0 ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       NULL ,
                       "xmlSecNssSymKeyDataAdoptKey" ,
                       XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;

               xmlSecKeyDataDestroy( data ) ;
               return NULL ;
       }

       return data ;
}


PK11SymKey*
xmlSecNssSymKeyDataGetKey(
    xmlSecKeyDataPtr data
) {
    xmlSecNssSymKeyDataCtxPtr ctx;
    PK11SymKey* symkey ;

    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), NULL);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecNssSymKeyDataSize), NULL);

    ctx = xmlSecNssSymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, NULL);

    if( ctx->symkey != NULL ) {
        symkey = PK11_ReferenceSymKey( ctx->symkey ) ;
    } else {
        symkey = NULL ;
    }

    return(symkey);
}

static int
xmlSecNssSymKeyDataInitialize(xmlSecKeyDataPtr data) {
    xmlSecNssSymKeyDataCtxPtr ctx;

    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(data, xmlSecNssSymKeyDataSize), -1);

    ctx = xmlSecNssSymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    memset( ctx, 0, sizeof(xmlSecNssSymKeyDataCtx));

    /* Set the block cipher mechanism */
#ifndef XMLSEC_NO_DES
    if(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDesId)) {
        ctx->cipher = CKM_DES3_KEY_GEN;
    } else
#endif  /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDesId)) {
        ctx->cipher = CKM_AES_KEY_GEN;
    } else
#endif  /* XMLSEC_NO_AES */

    if(1) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
            NULL ,
            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
            "Unsupported block cipher" ) ;
        return(-1) ;
    }

    return(0);
}

static int
xmlSecNssSymKeyDataDuplicate(xmlSecKeyDataPtr dst, xmlSecKeyDataPtr src) {
    xmlSecNssSymKeyDataCtxPtr ctxDst;
    xmlSecNssSymKeyDataCtxPtr ctxSrc;

    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(dst), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(dst, xmlSecNssSymKeyDataSize), -1);
    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(src), -1);
    xmlSecAssert2(xmlSecKeyDataCheckSize(src, xmlSecNssSymKeyDataSize), -1);
    xmlSecAssert2(dst->id == src->id, -1);

    ctxDst = xmlSecNssSymKeyDataGetCtx(dst);
    xmlSecAssert2(ctxDst != NULL, -1);

    ctxSrc = xmlSecNssSymKeyDataGetCtx(src);
    xmlSecAssert2(ctxSrc != NULL, -1);

    ctxDst->cipher = ctxSrc->cipher ;

    if( ctxSrc->slot != NULL ) {
        if( ctxDst->slot != NULL && ctxDst->slot != ctxSrc->slot ) {
            PK11_FreeSlot( ctxDst->slot ) ;
            ctxDst->slot = NULL ;
        }

        if( ctxDst->slot == NULL && ctxSrc->slot != NULL )
            ctxDst->slot = PK11_ReferenceSlot( ctxSrc->slot ) ;
    } else {
        if( ctxDst->slot != NULL ) {
            PK11_FreeSlot( ctxDst->slot ) ;
            ctxDst->slot = NULL ;
        }
    }

    if( ctxSrc->symkey != NULL ) {
        if( ctxDst->symkey != NULL && ctxDst->symkey != ctxSrc->symkey ) {
            PK11_FreeSymKey( ctxDst->symkey ) ;
            ctxDst->symkey = NULL ;
        }

        if( ctxDst->symkey == NULL && ctxSrc->symkey != NULL )
            ctxDst->symkey = PK11_ReferenceSymKey( ctxSrc->symkey ) ;
    } else {
        if( ctxDst->symkey != NULL ) {
            PK11_FreeSymKey( ctxDst->symkey ) ;
            ctxDst->symkey = NULL ;
        }
    }

    return(0);
}

static void
xmlSecNssSymKeyDataFinalize(xmlSecKeyDataPtr data) {
    xmlSecNssSymKeyDataCtxPtr ctx;

    xmlSecAssert(xmlSecNssSymKeyDataCheckId(data));
    xmlSecAssert(xmlSecKeyDataCheckSize(data, xmlSecNssSymKeyDataSize));

    ctx = xmlSecNssSymKeyDataGetCtx(data);
    xmlSecAssert(ctx != NULL);

    if( ctx->slot != NULL ) {
        PK11_FreeSlot( ctx->slot ) ;
        ctx->slot = NULL ;
    }

    if( ctx->symkey != NULL ) {
        PK11_FreeSymKey( ctx->symkey ) ;
        ctx->symkey = NULL ;
    }

    ctx->cipher = CKM_INVALID_MECHANISM ;
}

static int
xmlSecNssSymKeyDataXmlRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
			       xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    PK11SymKey* symKey ;
    PK11SlotInfo* slot ;
    xmlSecBufferPtr keyBuf;
    xmlSecSize len;
    xmlSecKeyDataPtr data;
    xmlSecNssSymKeyDataCtxPtr ctx;
    SECItem keyItem ;
    int ret;
    
    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* Create a new KeyData from a id */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecKeyDataCreate",
            XMLSEC_ERRORS_R_XMLSEC_FAILED,
            XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ctx = xmlSecNssSymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* Create a buffer for raw symmetric key value */
    if( ( keyBuf = xmlSecBufferCreate( 128 ) ) == NULL ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecBufferCreate" ,
            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;
               xmlSecKeyDataDestroy( data ) ;
        return(-1) ;
    }

    /* Read the raw key value */
    if( xmlSecBufferBase64NodeContentRead( keyBuf , node ) < 0 ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            xmlSecErrorsSafeString(xmlSecNodeGetName(node)),
            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;

        xmlSecBufferDestroy( keyBuf ) ;
               xmlSecKeyDataDestroy( data ) ;
        return(-1) ;
    }

    /* Get slot */
    slot = xmlSecNssSlotGet(ctx->cipher);
    if( slot == NULL ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecNssSlotGet" ,
            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;

        xmlSecBufferDestroy( keyBuf ) ;
               xmlSecKeyDataDestroy( data ) ;
        return(-1) ;
    }

    /* Wrap the raw key value SECItem */
    keyItem.type = siBuffer ;
    keyItem.data = xmlSecBufferGetData( keyBuf ) ;
    keyItem.len = xmlSecBufferGetSize( keyBuf ) ;

    /* Import the raw key into slot temporalily and get the key handler*/
    symKey = PK11_ImportSymKey(slot, ctx->cipher, PK11_OriginGenerated, CKA_VALUE, &keyItem, NULL ) ;
    if( symKey == NULL ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "PK11_ImportSymKey" ,
            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;

               PK11_FreeSlot( slot ) ;
        xmlSecBufferDestroy( keyBuf ) ;
               xmlSecKeyDataDestroy( data ) ;
        return(-1) ;
    }
       PK11_FreeSlot( slot ) ;

    /* raw key material has been copied into symKey, it isn't used any more */
    xmlSecBufferDestroy( keyBuf ) ;
    
    /* Adopt the symmetric key into key data */
    ret = xmlSecNssSymKeyDataAdoptKey(data, symKey);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecKeyDataBinaryValueSetBuffer",
            XMLSEC_ERRORS_R_XMLSEC_FAILED,
            XMLSEC_ERRORS_NO_MESSAGE);
        PK11_FreeSymKey( symKey ) ;
               xmlSecKeyDataDestroy( data ) ;
        return(-1);
    }
    /* symKey has been duplicated into data, it isn't used any more */
    PK11_FreeSymKey( symKey ) ;

    /* Check value */
    if(xmlSecKeyReqMatchKeyValue(&(keyInfoCtx->keyReq), data) != 1) {
        xmlSecError(XMLSEC_ERRORS_HERE,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecKeyReqMatchKeyValue",
            XMLSEC_ERRORS_R_XMLSEC_FAILED,
            XMLSEC_ERRORS_NO_MESSAGE);
               xmlSecKeyDataDestroy( data ) ;
        return(0);
    }
    
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecKeySetValue",
            XMLSEC_ERRORS_R_XMLSEC_FAILED,
            XMLSEC_ERRORS_NO_MESSAGE);
               xmlSecKeyDataDestroy( data ) ;
        return(-1);
    }

    return(0);
}

static int 
xmlSecNssSymKeyDataXmlWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlNodePtr node, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    PK11SymKey* symKey ;

    xmlSecAssert2(xmlSecNssSymKeyDataKlassCheck(id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(node != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

       /* Get symmetric key from "key" */
    symKey = xmlSecNssSymKeyDataGetKey(xmlSecKeyGetValue(key)); 
    if( symKey != NULL ) {
        SECItem* keyItem ;
               xmlSecBufferPtr keyBuf ;

               /* Extract raw key data from symmetric key */
               if( PK11_ExtractKeyValue( symKey ) != SECSuccess ) {
               xmlSecError(XMLSEC_ERRORS_HERE,
               xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
               "PK11_ExtractKeyValue",
               XMLSEC_ERRORS_R_XMLSEC_FAILED,
               XMLSEC_ERRORS_NO_MESSAGE);
                       PK11_FreeSymKey( symKey ) ;
               return(-1);
               }

               /* Get raw key data from "symKey" */
        keyItem = PK11_GetKeyData( symKey ) ;
           if(keyItem == NULL) {
               xmlSecError(XMLSEC_ERRORS_HERE,
               xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
               "PK11_GetKeyData",
               XMLSEC_ERRORS_R_XMLSEC_FAILED,
               XMLSEC_ERRORS_NO_MESSAGE);
                       PK11_FreeSymKey( symKey ) ;
               return(-1);
       }

               /* Create key data buffer with raw kwy material */
               keyBuf = xmlSecBufferCreate(keyItem->len) ;
           if(keyBuf == NULL) {
               xmlSecError(XMLSEC_ERRORS_HERE,
               xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
               "xmlSecBufferCreate",
               XMLSEC_ERRORS_R_XMLSEC_FAILED,
               XMLSEC_ERRORS_NO_MESSAGE);
                       PK11_FreeSymKey( symKey ) ;
               return(-1);
       }

               xmlSecBufferSetData( keyBuf , keyItem->data , keyItem->len ) ;

               /* Write raw key material into current xml node */
               if( xmlSecBufferBase64NodeContentWrite( keyBuf, node, XMLSEC_BASE64_LINESIZE ) < 0 ) {
               xmlSecError(XMLSEC_ERRORS_HERE,
               xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
               "xmlSecBufferBase64NodeContentWrite",
               XMLSEC_ERRORS_R_XMLSEC_FAILED,
               XMLSEC_ERRORS_NO_MESSAGE);
                       xmlSecBufferDestroy(keyBuf);
                       PK11_FreeSymKey( symKey ) ;
               return(-1);
               }
               xmlSecBufferDestroy(keyBuf);
               PK11_FreeSymKey( symKey ) ;
    }

    return 0 ;
}

static int
xmlSecNssSymKeyDataBinRead(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    const xmlSecByte* buf, xmlSecSize bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    PK11SymKey* symKey ;
    PK11SlotInfo* slot ;
    xmlSecKeyDataPtr data;
    xmlSecNssSymKeyDataCtxPtr ctx;
    SECItem keyItem ;
    int ret;

    xmlSecAssert2(id != xmlSecKeyDataIdUnknown, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize != 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    /* Create a new KeyData from a id */
    data = xmlSecKeyDataCreate(id);
    if(data == NULL ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecKeyDataCreate",
            XMLSEC_ERRORS_R_XMLSEC_FAILED,
            XMLSEC_ERRORS_NO_MESSAGE);
        return(-1);
    }

    ctx = xmlSecNssSymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    /* Get slot */
    slot = xmlSecNssSlotGet(ctx->cipher);
    if( slot == NULL ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecNssSlotGet" ,
            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;
               xmlSecKeyDataDestroy( data ) ;
        return(-1) ;
    }

    /* Wrap the raw key value SECItem */
    keyItem.type = siBuffer ;
    keyItem.data = buf ;
    keyItem.len = bufSize ;

    /* Import the raw key into slot temporalily and get the key handler*/
    symKey = PK11_ImportSymKey(slot, ctx->cipher, PK11_OriginGenerated, CKA_VALUE, &keyItem, NULL ) ;
    if( symKey == NULL ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "PK11_ImportSymKey" ,
            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;
               PK11_FreeSlot( slot ) ;
               xmlSecKeyDataDestroy( data ) ;
        return(-1) ;
    }

    /* Adopt the symmetric key into key data */
    ret = xmlSecNssSymKeyDataAdoptKey(data, symKey);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecKeyDataBinaryValueSetBuffer",
            XMLSEC_ERRORS_R_XMLSEC_FAILED,
            XMLSEC_ERRORS_NO_MESSAGE ) ;
        PK11_FreeSymKey( symKey ) ;
               PK11_FreeSlot( slot ) ;
               xmlSecKeyDataDestroy( data ) ;
        return(-1);
    }
    /* symKey has been duplicated into data, it isn't used any more */
    PK11_FreeSymKey( symKey ) ;
       PK11_FreeSlot( slot ) ;

    /* Check value */
    if(xmlSecKeyReqMatchKeyValue(&(keyInfoCtx->keyReq), data) != 1) {
        xmlSecError(XMLSEC_ERRORS_HERE,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecKeyReqMatchKeyValue",
            XMLSEC_ERRORS_R_XMLSEC_FAILED,
            XMLSEC_ERRORS_NO_MESSAGE);
               xmlSecKeyDataDestroy( data ) ;
        return(0);
    }
    
    ret = xmlSecKeySetValue(key, data);
    if(ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
            xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
            "xmlSecKeySetValue",
            XMLSEC_ERRORS_R_XMLSEC_FAILED,
            XMLSEC_ERRORS_NO_MESSAGE);
               xmlSecKeyDataDestroy( data ) ;
        return(-1);
    }

    return(0);
}

static int
xmlSecNssSymKeyDataBinWrite(xmlSecKeyDataId id, xmlSecKeyPtr key,
				    xmlSecByte** buf, xmlSecSize* bufSize,
				    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    PK11SymKey* symKey ;

    xmlSecAssert2(xmlSecNssSymKeyDataKlassCheck(id), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize != 0, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

       /* Get symmetric key from "key" */
    symKey = xmlSecNssSymKeyDataGetKey(xmlSecKeyGetValue(key)); 
    if( symKey != NULL ) {
        SECItem* keyItem ;

               /* Extract raw key data from symmetric key */
               if( PK11_ExtractKeyValue( symKey ) != SECSuccess ) {
               xmlSecError(XMLSEC_ERRORS_HERE,
               xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
               "PK11_ExtractKeyValue",
               XMLSEC_ERRORS_R_XMLSEC_FAILED,
               XMLSEC_ERRORS_NO_MESSAGE);
                       PK11_FreeSymKey( symKey ) ;
               return(-1);
               }

               /* Get raw key data from "symKey" */
        keyItem = PK11_GetKeyData( symKey ) ;
           if(keyItem == NULL) {
               xmlSecError(XMLSEC_ERRORS_HERE,
               xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
               "PK11_GetKeyData",
               XMLSEC_ERRORS_R_XMLSEC_FAILED,
                       XMLSEC_ERRORS_NO_MESSAGE);
                       PK11_FreeSymKey( symKey ) ;
               return(-1);
       }

               *bufSize = keyItem->len;
               *buf = ( xmlSecByte* )xmlMalloc( *bufSize );
               if( *buf == NULL ) {
               xmlSecError(XMLSEC_ERRORS_HERE,
               xmlSecErrorsSafeString(xmlSecKeyDataKlassGetName(id)),
               NULL,
               XMLSEC_ERRORS_R_XMLSEC_FAILED,
               XMLSEC_ERRORS_NO_MESSAGE);
                       PK11_FreeSymKey( symKey ) ;
               return(-1);
       }

       memcpy((*buf), keyItem->data, (*bufSize));
       PK11_FreeSymKey( symKey ) ;
    }
    
    return 0 ;
}

static int
xmlSecNssSymKeyDataGenerate(xmlSecKeyDataPtr data, xmlSecSize sizeBits, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    PK11SymKey* symkey ;
    PK11SlotInfo* slot ;
    xmlSecNssSymKeyDataCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), -1);
    xmlSecAssert2(sizeBits > 0, -1);

    ctx = xmlSecNssSymKeyDataGetCtx(data);
    xmlSecAssert2(ctx != NULL, -1);

    if( sizeBits % 8 != 0 ) {
            xmlSecError(XMLSEC_ERRORS_HERE,
         xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
         NULL,
         XMLSEC_ERRORS_R_XMLSEC_FAILED,
         "Symmetric key size must be octuple");
     return(-1);
    }

    /* Get slot */
    slot = xmlSecNssSlotGet(ctx->cipher);
    if( slot == NULL ) {
        xmlSecError( XMLSEC_ERRORS_HERE ,
            xmlSecErrorsSafeString(xmlSecKeyDataGetName(data)),
            "xmlSecNssSlotGet" ,
            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
            XMLSEC_ERRORS_NO_MESSAGE ) ;
        return(-1) ;
    }

    if( PK11_Authenticate( slot, PR_FALSE , NULL ) != SECSuccess ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                xmlSecErrorsSafeString( xmlSecKeyDataGetName( data ) ) ,
                "PK11_Authenticate" ,
                XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                XMLSEC_ERRORS_NO_MESSAGE ) ;
            PK11_FreeSlot( slot ) ;
            return -1 ;
    }

    symkey = PK11_KeyGen( slot , ctx->cipher , NULL , sizeBits/8 , NULL ) ;
    if( symkey == NULL ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                xmlSecErrorsSafeString( xmlSecKeyDataGetName( data ) ) ,
                "PK11_KeyGen" ,
                XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                XMLSEC_ERRORS_NO_MESSAGE ) ;
            PK11_FreeSlot( slot ) ;
            return -1 ;
    }

    if( ctx->slot != NULL ) {
            PK11_FreeSlot( ctx->slot ) ;
            ctx->slot = NULL ;
    }
    ctx->slot = slot ;

    if( ctx->symkey != NULL ) {
            PK11_FreeSymKey( ctx->symkey ) ;
            ctx->symkey = NULL ;
    }
    ctx->symkey = symkey ;

    return 0;
}

static xmlSecKeyDataType
xmlSecNssSymKeyDataGetType(xmlSecKeyDataPtr data) {
    xmlSecNssSymKeyDataCtxPtr context = NULL ;
    xmlSecKeyDataType type = xmlSecKeyDataTypeUnknown ;

    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), xmlSecKeyDataTypeUnknown);
    xmlSecAssert2( xmlSecKeyDataCheckSize( data, xmlSecNssSymKeyDataSize ), xmlSecKeyDataTypeUnknown ) ;

    context = xmlSecNssSymKeyDataGetCtx( data ) ;
    if( context == NULL ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                xmlSecErrorsSafeString( xmlSecKeyDataGetName( data ) ) ,
                "xmlSecNssSymKeyDataGetCtx" ,
                XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                XMLSEC_ERRORS_NO_MESSAGE ) ;
            return xmlSecKeyDataTypeUnknown ;
    }

    if( context->symkey != NULL ) {
            type |= xmlSecKeyDataTypeSymmetric ;
    } else {
            type |= xmlSecKeyDataTypeUnknown ;
    }

    return type ;
}

static xmlSecSize 
xmlSecNssSymKeyDataGetSize(xmlSecKeyDataPtr data) {
    xmlSecNssSymKeyDataCtxPtr context ;
    unsigned int    length = 0 ;

    xmlSecAssert2(xmlSecNssSymKeyDataCheckId(data), 0);
    xmlSecAssert2( xmlSecKeyDataCheckSize( data, xmlSecNssSymKeyDataSize ), 0 ) ;
    context = xmlSecNssSymKeyDataGetCtx( data ) ;
    if( context == NULL ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                xmlSecErrorsSafeString( xmlSecKeyDataGetName( data ) ) ,
                "xmlSecNssSymKeyDataGetCtx" ,
                XMLSEC_ERRORS_R_CRYPTO_FAILED ,
                XMLSEC_ERRORS_NO_MESSAGE ) ;
            return 0 ;
    }

    if( context->symkey != NULL ) {
            length = PK11_GetKeyLength( context->symkey ) ;
            length *= 8 ;
    }
    
    return length ;
}

static void 
xmlSecNssSymKeyDataDebugDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecNssSymKeyDataCheckId(data));
    
    /* print only size, everything else is sensitive */
    fprintf( output , "=== %s: size=%d\n" , data->id->dataNodeName ,
        xmlSecKeyDataGetSize(data)) ;
}

static void
xmlSecNssSymKeyDataDebugXmlDump(xmlSecKeyDataPtr data, FILE* output) {
    xmlSecAssert(xmlSecNssSymKeyDataCheckId(data));

    /* print only size, everything else is sensitive */
    fprintf( output , "<%s size=\"%d\" />\n" , data->id->dataNodeName ,
        xmlSecKeyDataGetSize(data)) ;
}

static int 
xmlSecNssSymKeyDataKlassCheck(xmlSecKeyDataKlass* klass) {    
#ifndef XMLSEC_NO_DES
    if(klass == xmlSecNssKeyDataDesId) {
	return(1);
    }
#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_AES
    if(klass == xmlSecNssKeyDataAesId) {
	return(1);
    }
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_HMAC
    if(klass == xmlSecNssKeyDataHmacId) {
	return(1);
    }
#endif /* XMLSEC_NO_HMAC */

    return(0);
}

#ifndef XMLSEC_NO_AES
/**************************************************************************
 *
 * <xmlsec:AESKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataKlass xmlSecNssKeyDataAesKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecNssSymKeyDataSize,

    /* data */
    xmlSecNameAESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefAESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeAESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecNssSymKeyDataInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecNssSymKeyDataDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecNssSymKeyDataFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecNssSymKeyDataGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecNssSymKeyDataGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecNssSymKeyDataGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecNssSymKeyDataXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecNssSymKeyDataXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecNssSymKeyDataBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecNssSymKeyDataBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecNssSymKeyDataDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecNssSymKeyDataDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecNssKeyDataAesGetKlass:
 * 
 * The AES key data klass.
 *
 * Returns: AES key data klass.
 */
xmlSecKeyDataId 
xmlSecNssKeyDataAesGetKlass(void) {
    return(&xmlSecNssKeyDataAesKlass);
}

/**
 * xmlSecNssKeyDataAesSet:
 * @data:		the pointer to AES key data.
 * @buf:		the pointer to key value.
 * @bufSize:		the key value size (in bytes).
 *
 * Sets the value of AES key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataAesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataAesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}
#endif /* XMLSEC_NO_AES */

#ifndef XMLSEC_NO_DES
/**************************************************************************
 *
 * <xmlsec:DESKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataKlass xmlSecNssKeyDataDesKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecNssSymKeyDataSize,

    /* data */
    xmlSecNameDESKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefDESKeyValue,			/* const xmlChar* href; */
    xmlSecNodeDESKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecNssSymKeyDataInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecNssSymKeyDataDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecNssSymKeyDataFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecNssSymKeyDataGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecNssSymKeyDataGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecNssSymKeyDataGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecNssSymKeyDataXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecNssSymKeyDataXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecNssSymKeyDataBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecNssSymKeyDataBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecNssSymKeyDataDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecNssSymKeyDataDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecNssKeyDataDesGetKlass:
 * 
 * The DES key data klass.
 *
 * Returns: DES key data klass.
 */
xmlSecKeyDataId 
xmlSecNssKeyDataDesGetKlass(void) {
    return(&xmlSecNssKeyDataDesKlass);
}

/**
 * xmlSecNssKeyDataDesSet:
 * @data:		the pointer to DES key data.
 * @buf:		the pointer to key value.
 * @bufSize:		the key value size (in bytes).
 *
 * Sets the value of DES key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataDesSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataDesId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_DES */

#ifndef XMLSEC_NO_HMAC
/**************************************************************************
 *
 * <xmlsec:HMACKeyValue> processing
 *
 *************************************************************************/
static xmlSecKeyDataKlass xmlSecNssKeyDataHmacKlass = {
    sizeof(xmlSecKeyDataKlass),
    xmlSecNssSymKeyDataSize,

    /* data */
    xmlSecNameHMACKeyValue,
    xmlSecKeyDataUsageKeyValueNode | xmlSecKeyDataUsageRetrievalMethodNodeXml, 
						/* xmlSecKeyDataUsage usage; */
    xmlSecHrefHMACKeyValue,			/* const xmlChar* href; */
    xmlSecNodeHMACKeyValue,			/* const xmlChar* dataNodeName; */
    xmlSecNs,					/* const xmlChar* dataNodeNs; */
    
    /* constructors/destructor */
    xmlSecNssSymKeyDataInitialize,		/* xmlSecKeyDataInitializeMethod initialize; */
    xmlSecNssSymKeyDataDuplicate,		/* xmlSecKeyDataDuplicateMethod duplicate; */
    xmlSecNssSymKeyDataFinalize,		/* xmlSecKeyDataFinalizeMethod finalize; */
    xmlSecNssSymKeyDataGenerate,		/* xmlSecKeyDataGenerateMethod generate; */
    
    /* get info */
    xmlSecNssSymKeyDataGetType, 		/* xmlSecKeyDataGetTypeMethod getType; */
    xmlSecNssSymKeyDataGetSize,		/* xmlSecKeyDataGetSizeMethod getSize; */
    NULL,					/* xmlSecKeyDataGetIdentifier getIdentifier; */

    /* read/write */
    xmlSecNssSymKeyDataXmlRead,		/* xmlSecKeyDataXmlReadMethod xmlRead; */
    xmlSecNssSymKeyDataXmlWrite,		/* xmlSecKeyDataXmlWriteMethod xmlWrite; */
    xmlSecNssSymKeyDataBinRead,		/* xmlSecKeyDataBinReadMethod binRead; */
    xmlSecNssSymKeyDataBinWrite,		/* xmlSecKeyDataBinWriteMethod binWrite; */

    /* debug */
    xmlSecNssSymKeyDataDebugDump,		/* xmlSecKeyDataDebugDumpMethod debugDump; */
    xmlSecNssSymKeyDataDebugXmlDump, 	/* xmlSecKeyDataDebugDumpMethod debugXmlDump; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/** 
 * xmlSecNssKeyDataHmacGetKlass:
 * 
 * The HMAC key data klass.
 *
 * Returns: HMAC key data klass.
 */
xmlSecKeyDataId 
xmlSecNssKeyDataHmacGetKlass(void) {
    return(&xmlSecNssKeyDataHmacKlass);
}

/**
 * xmlSecNssKeyDataHmacSet:
 * @data:		the pointer to HMAC key data.
 * @buf:		the pointer to key value.
 * @bufSize:		the key value size (in bytes).
 *
 * Sets the value of HMAC key data.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeyDataHmacSet(xmlSecKeyDataPtr data, const xmlSecByte* buf, xmlSecSize bufSize) {
    xmlSecBufferPtr buffer;
    
    xmlSecAssert2(xmlSecKeyDataCheckId(data, xmlSecNssKeyDataHmacId), -1);
    xmlSecAssert2(buf != NULL, -1);
    xmlSecAssert2(bufSize > 0, -1);
    
    buffer = xmlSecKeyDataBinaryValueGetBuffer(data);
    xmlSecAssert2(buffer != NULL, -1);
    
    return(xmlSecBufferSetData(buffer, buf, bufSize));
}

#endif /* XMLSEC_NO_HMAC */

