/*
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * This is free software; see Copyright file in the source
 * distribution for precise wording.
 *
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */

/**
 * NSS key store uses a key list and a slot list as the key repository. NSS slot
 * list is a backup repository for the finding keys. If a key is not found from
 * the key list, the NSS slot list is looked up.
 *
 * Any key in the key list will not save to pkcs11 slot. When a store to called
 * to adopt a key, the key is resident in the key list; While a store to called
 * to set a is resident in the key list; While a store to called to set a slot 
 * list, which means that the keys in the listed slot can be used for xml sign-
 * nature or encryption.
 *
 * Then, a user can adjust slot list to effect the crypto behaviors of xmlSec.
 *
 * The framework will decrease the user interfaces to administrate xmlSec crypto
 * engine. He can only focus on NSS layer functions. For examples, after the
 * user set up a slot list handler to the keys store, he do not need to do any
 * other work atop xmlSec interfaces, his action on the slot list handler, such
 * as add a token to, delete a token from the list, will directly effect the key
 * store behaviors.
 *
 * For example, a scenariio:
 * 0. Create a slot list;( NSS interfaces )
 * 1. Create a keys store;( xmlSec interfaces )
 * 2. Set slot list with the keys store;( xmlSec Interfaces )
 * 3. Add a slot to the slot list;( NSS interfaces )
 * 4. Perform xml signature; ( xmlSec Interfaces )
 * 5. Deleter a slot from the slot list;( NSS interfaces )
 * 6. Perform xml encryption; ( xmlSec Interfaces )
 * 7. Perform xml signature;( xmlSec Interfaces )
 * 8. Destroy the keys store;( xmlSec Interfaces )
 * 8. Destroy the slot list.( NSS Interfaces )
 */
#include "globals.h"

#include <stdlib.h>
#include <string.h>

#include <nss.h>
#include <pk11func.h>
#include <prinit.h>
#include <keyhi.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/keys.h>
#include <xmlsec/errors.h>
#include <xmlsec/xmltree.h>

#include <xmlsec/keysmngr.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/keysstore.h>
#include <xmlsec/nss/tokens.h>
#include <xmlsec/nss/ciphers.h>
#include <xmlsec/nss/pkikeys.h>

/****************************************************************************
 *
 * Internal NSS key store context
 *
 * This context is located after xmlSecKeyStore
 *
 ***************************************************************************/
typedef struct _xmlSecNssKeysStoreCtx  xmlSecNssKeysStoreCtx ;
typedef struct _xmlSecNssKeysStoreCtx* xmlSecNssKeysStoreCtxPtr ;

struct _xmlSecNssKeysStoreCtx {
       xmlSecPtrListPtr                keyList ;
       xmlSecPtrListPtr                slotList ;
} ;

#define xmlSecNssKeysStoreSize \
       ( sizeof( xmlSecKeyStore ) + sizeof( xmlSecNssKeysStoreCtx ) )

#define xmlSecNssKeysStoreGetCtx( data ) \
       ( ( xmlSecNssKeysStoreCtxPtr )( ( ( xmlSecByte* )( data ) ) + sizeof( xmlSecKeyStore ) ) )

int xmlSecNssKeysStoreAdoptKeySlot(
       xmlSecKeyStorePtr               store ,
       xmlSecNssKeySlotPtr             keySlot
) {
       xmlSecNssKeysStoreCtxPtr context = NULL ;

       xmlSecAssert2( xmlSecKeyStoreCheckId( store , xmlSecNssKeysStoreId ) , -1 ) ;
       xmlSecAssert2( xmlSecKeyStoreCheckSize( store , xmlSecNssKeysStoreSize ) , -1 ) ;
       context = xmlSecNssKeysStoreGetCtx( store ) ;
       if( context == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                       "xmlSecNssKeysStoreGetCtx" ,
                       XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;
       }

       if( context->slotList == NULL ) {
               if( ( context->slotList = xmlSecPtrListCreate( xmlSecNssKeySlotListId ) ) == NULL ) {
                       xmlSecError( XMLSEC_ERRORS_HERE ,
                               xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                               "xmlSecPtrListCreate" ,
                               XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                               XMLSEC_ERRORS_NO_MESSAGE ) ;
                       return -1 ;
               }
       }

       if( !xmlSecPtrListCheckId( context->slotList , xmlSecNssKeySlotListId ) ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                       "xmlSecPtrListCheckId" ,
                       XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;
       }

       if( xmlSecPtrListAdd( context->slotList , keySlot ) < 0 ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                       "xmlSecPtrListAdd" ,
                       XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;
       }
       return 0 ;
}

int xmlSecNssKeysStoreAdoptKey(
       xmlSecKeyStorePtr       store ,
       xmlSecKeyPtr            key
) {
       xmlSecNssKeysStoreCtxPtr context = NULL ;

       xmlSecAssert2( xmlSecKeyStoreCheckId( store , xmlSecNssKeysStoreId ) , -1 ) ;
       xmlSecAssert2( xmlSecKeyStoreCheckSize( store , xmlSecNssKeysStoreSize ) , -1 ) ;

       context = xmlSecNssKeysStoreGetCtx( store ) ;
       if( context == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                       "xmlSecNssKeysStoreGetCtx" ,
                       XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;
       }

       if( context->keyList == NULL ) {
               if( ( context->keyList = xmlSecPtrListCreate( xmlSecKeyPtrListId ) ) == NULL ) {
                       xmlSecError( XMLSEC_ERRORS_HERE ,
                               xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                               "xmlSecPtrListCreate" ,
                               XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                               XMLSEC_ERRORS_NO_MESSAGE ) ;
                       return -1 ;
               }
       }

       if( !xmlSecPtrListCheckId( context->keyList , xmlSecKeyPtrListId ) ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                       "xmlSecPtrListCheckId" ,
                       XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;
       }

       if( xmlSecPtrListAdd( context->keyList , key ) < 0 ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                       "xmlSecPtrListAdd" ,
                       XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;
       }

       return 0 ;
}

/*
 * xmlSecKeyStoreInitializeMethod:
 * @store:             the store.
 *
 * Keys store specific initialization method.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
static int
xmlSecNssKeysStoreInitialize(
       xmlSecKeyStorePtr store
) {
       xmlSecNssKeysStoreCtxPtr context = NULL ;

       xmlSecAssert2( xmlSecKeyStoreCheckId( store , xmlSecNssKeysStoreId ) , -1 ) ;
       xmlSecAssert2( xmlSecKeyStoreCheckSize( store , xmlSecNssKeysStoreSize ) , -1 ) ;

       context = xmlSecNssKeysStoreGetCtx( store ) ;
       if( context == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                       "xmlSecNssKeysStoreGetCtx" ,
                       XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;
               return -1 ;
       }

       context->keyList = NULL ;
       context->slotList = NULL ;

       return 0 ;
}

/**
 *
 * xmlSecKeyStoreFinalizeMethod:
 * @store:             the store.
 *
 * Keys store specific finalization (destroy) method.
 */
void
xmlSecNssKeysStoreFinalize(
       xmlSecKeyStorePtr store
) {
       xmlSecNssKeysStoreCtxPtr context = NULL ;

       xmlSecAssert( xmlSecKeyStoreCheckId( store , xmlSecNssKeysStoreId ) ) ;
       xmlSecAssert( xmlSecKeyStoreCheckSize( store , xmlSecNssKeysStoreSize ) ) ;

       context = xmlSecNssKeysStoreGetCtx( store ) ;
       if( context == NULL ) {
               xmlSecError( XMLSEC_ERRORS_HERE ,
                       xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                       "xmlSecNssKeysStoreGetCtx" ,
                       XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                       XMLSEC_ERRORS_NO_MESSAGE ) ;
               return ;
       }

       if( context->keyList != NULL ) {
               xmlSecPtrListDestroy( context->keyList ) ;
               context->keyList = NULL ;
       }

       if( context->slotList != NULL ) {
               xmlSecPtrListDestroy( context->slotList ) ;
               context->slotList = NULL ;
       }
}

xmlSecKeyPtr
xmlSecNssKeysStoreFindKeyFromSlot(
       PK11SlotInfo* slot,
       const xmlChar* name,
       xmlSecKeyInfoCtxPtr keyInfoCtx
) {
       xmlSecKeyPtr            key = NULL ;
       xmlSecKeyDataPtr        data = NULL ;
       int                                     length ;

       xmlSecAssert2( slot != NULL , NULL ) ;
       xmlSecAssert2( name != NULL , NULL ) ;
       xmlSecAssert2( keyInfoCtx != NULL , NULL ) ;

       if( ( keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypeSymmetric ) == xmlSecKeyDataTypeSymmetric ) {
               PK11SymKey*                     symKey ;
               PK11SymKey*                     curKey ;

               /* Find symmetric key from the slot by name */
               symKey = PK11_ListFixedKeysInSlot( slot , ( char* )name , NULL ) ;
               for( curKey = symKey ; curKey != NULL ; curKey = PK11_GetNextSymKey( curKey ) ) {
                       /* Check the key request */
                       length = PK11_GetKeyLength( curKey ) ;
                       length *= 8 ;
                       if( ( keyInfoCtx->keyReq.keyBitsSize > 0 ) &&
                               ( length > 0 ) &&
                               ( length < keyInfoCtx->keyReq.keyBitsSize ) )
                               continue ;

                       /* We find a eligible key */
                       data = xmlSecNssSymKeyDataKeyAdopt( curKey ) ;
                       if( data == NULL ) {
                               /* Do nothing */
                       }
                       break ;
               }

               /* Destroy the sym key list */
               for( curKey = symKey ; curKey != NULL ; ) {
                       symKey = curKey ;
                       curKey = PK11_GetNextSymKey( symKey ) ;
                       PK11_FreeSymKey( symKey ) ;
               }
       } else if( ( keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePublic ) == xmlSecKeyDataTypePublic ) {
               SECKEYPublicKeyList*            pubKeyList ;
               SECKEYPublicKey*                        pubKey ;
               SECKEYPublicKeyListNode*        curPub ;

               /* Find asymmetric key from the slot by name */
               pubKeyList = PK11_ListPublicKeysInSlot( slot , ( char* )name ) ;
               pubKey = NULL ;
               curPub = PUBKEY_LIST_HEAD(pubKeyList);
               for( ; !PUBKEY_LIST_END(curPub, pubKeyList) ; curPub = PUBKEY_LIST_NEXT( curPub ) ) {
                       /* Check the key request */
                       length = SECKEY_PublicKeyStrength( curPub->key ) ;
                       length *= 8 ;
                       if( ( keyInfoCtx->keyReq.keyBitsSize > 0 ) &&
                               ( length > 0 ) &&
                               ( length < keyInfoCtx->keyReq.keyBitsSize ) )
                               continue ;

                       /* We find a eligible key */
                       pubKey = curPub->key ;
                       break ;
               }

               if( pubKey != NULL ) {
                       data = xmlSecNssPKIAdoptKey( NULL, pubKey ) ;
                       if( data == NULL ) {
                               /* Do nothing */
                       }
               }

               /* Destroy the public key list */
               SECKEY_DestroyPublicKeyList( pubKeyList ) ;
       } else if( ( keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypePrivate ) == xmlSecKeyDataTypePrivate ) {
               SECKEYPrivateKeyList*           priKeyList = NULL ;
               SECKEYPrivateKey*                       priKey = NULL ;
               SECKEYPrivateKeyListNode*       curPri ;

               /* Find asymmetric key from the slot by name */
               priKeyList = PK11_ListPrivKeysInSlot( slot , ( char* )name , NULL ) ;
               priKey = NULL ;
               curPri = PRIVKEY_LIST_HEAD(priKeyList);
               for( ; !PRIVKEY_LIST_END(curPri, priKeyList) ; curPri = PRIVKEY_LIST_NEXT( curPri ) ) {
                       /* Check the key request */
                       length = PK11_SignatureLen( curPri->key ) ;
                       length *= 8 ;
                       if( ( keyInfoCtx->keyReq.keyBitsSize > 0 ) &&
                               ( length > 0 ) &&
                               ( length < keyInfoCtx->keyReq.keyBitsSize ) )
                               continue ;

                       /* We find a eligible key */
                       priKey = curPri->key ;
                       break ;
               }

               if( priKey != NULL ) {
                       data = xmlSecNssPKIAdoptKey( priKey, NULL ) ;
                       if( data == NULL ) {
                               /* Do nothing */
                       }
               }

               /* Destroy the private key list */
               SECKEY_DestroyPrivateKeyList( priKeyList ) ;
       }

       /* If we have gotten the key value */
       if( data != NULL ) {
               if( ( key = xmlSecKeyCreate() ) == NULL ) {
                       xmlSecError( XMLSEC_ERRORS_HERE ,
                               NULL ,
                               "xmlSecKeyCreate" ,
                               XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                               XMLSEC_ERRORS_NO_MESSAGE ) ;

                       xmlSecKeyDataDestroy( data ) ;
                       return NULL ;
               }

               if( xmlSecKeySetValue( key , data ) < 0 ) {
                       xmlSecError( XMLSEC_ERRORS_HERE ,
                               NULL ,
                               "xmlSecKeySetValue" ,
                               XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                               XMLSEC_ERRORS_NO_MESSAGE ) ;

                       xmlSecKeyDestroy( key ) ;
                       xmlSecKeyDataDestroy( data ) ;
                       return NULL ;
               }
       }

    return(key);
}

/** 
 * xmlSecKeyStoreFindKeyMethod:
 * @store:             the store.
 * @name:              the desired key name.
 * @keyInfoCtx:        the pointer to key info context.
 *
 * Keys store specific find method. The caller is responsible for destroying 
 * the returned key using #xmlSecKeyDestroy method.
 *
 * Returns the pointer to a key or NULL if key is not found or an error occurs.
 */
static xmlSecKeyPtr
xmlSecNssKeysStoreFindKey(
       xmlSecKeyStorePtr store ,
       const xmlChar* name ,
       xmlSecKeyInfoCtxPtr keyInfoCtx
) {
    xmlSecNssKeysStoreCtxPtr context = NULL ;
    xmlSecKeyPtr    key = NULL ;
    xmlSecNssKeySlotPtr     keySlot = NULL ;
    xmlSecSize              pos ;
    xmlSecSize              size ;

    xmlSecAssert2( xmlSecKeyStoreCheckId( store , xmlSecNssKeysStoreId ) , NULL ) ;
    xmlSecAssert2( xmlSecKeyStoreCheckSize( store , xmlSecNssKeysStoreSize ) , NULL ) ;
    xmlSecAssert2( keyInfoCtx != NULL , NULL ) ;

    context = xmlSecNssKeysStoreGetCtx( store ) ;
    if( context == NULL ) {
            xmlSecError( XMLSEC_ERRORS_HERE ,
                    xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                    "xmlSecNssKeysStoreGetCtx" ,
                    XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                    XMLSEC_ERRORS_NO_MESSAGE ) ;
            return NULL ;
    }

    /*-
     * Look for key at keyList at first.
     */
    if( context->keyList != NULL ) {
            size = xmlSecPtrListGetSize( context->keyList ) ;
            for( pos = 0 ; pos < size ; pos ++ ) {
                    key = ( xmlSecKeyPtr )xmlSecPtrListGetItem( context->keyList , pos ) ;
                    if( key != NULL && xmlSecKeyMatch( key , name , &( keyInfoCtx->keyReq ) ) ) {
                            return xmlSecKeyDuplicate( key ) ;
                    }
            }
    }

    /*-
     * Find the key from slotList
     */
    if( context->slotList != NULL ) {
            PK11SlotInfo*                   slot = NULL ;

            size = xmlSecPtrListGetSize( context->slotList ) ;
            for( pos = 0 ; pos < size ; pos ++ ) {
                    keySlot = ( xmlSecNssKeySlotPtr )xmlSecPtrListGetItem( context->slotList , pos ) ;
                    slot = xmlSecNssKeySlotGetSlot( keySlot ) ;
                    if( slot == NULL ) {
                            continue ;
                    } else {
                            key = xmlSecNssKeysStoreFindKeyFromSlot( slot, name, keyInfoCtx ) ;
                            if( key == NULL ) {
                                    continue ;
                            } else {
                                    return( key ) ;
                            }
                    }
            }
    }

    /*-
     * Create a session key if we can not find the key from keyList and slotList
     */
    if( ( keyInfoCtx->keyReq.keyType & xmlSecKeyDataTypeSession ) == xmlSecKeyDataTypeSession ) {
            key = xmlSecKeyGenerate( keyInfoCtx->keyReq.keyId , keyInfoCtx->keyReq.keyBitsSize , xmlSecKeyDataTypeSession ) ;
            if( key == NULL ) {
                    xmlSecError( XMLSEC_ERRORS_HERE ,
                            xmlSecErrorsSafeString( xmlSecKeyStoreGetName( store ) ) ,
                            "xmlSecKeySetValue" ,
                            XMLSEC_ERRORS_R_XMLSEC_FAILED ,
                            XMLSEC_ERRORS_NO_MESSAGE ) ;
                    return NULL ;
            }

            return key ;
    }
 
   /**
    * We have no way to find the key any more.
    */
    return NULL ;
}

static xmlSecKeyStoreKlass xmlSecNssKeysStoreKlass = {
       sizeof( xmlSecKeyStoreKlass ) ,
       xmlSecNssKeysStoreSize ,
       BAD_CAST "implicit_nss_keys_store" ,
       xmlSecNssKeysStoreInitialize ,
       xmlSecNssKeysStoreFinalize ,
       xmlSecNssKeysStoreFindKey ,
       NULL ,
       NULL
} ;

/**
 * xmlSecNssKeysStoreGetKlass:
 *
 * The simple list based keys store klass.
 *
 */
xmlSecKeyStoreId
xmlSecNssKeysStoreGetKlass( void ) {
    return &xmlSecNssKeysStoreKlass ;
}

/**************************
 * Application routines
 */

/**
 * xmlSecNssKeysStoreLoad:
 * @store:              the pointer to Nss keys store.
 * @uri:                the filename.
 * @keysMngr:           the pointer to associated keys manager.
 *
 * Reads keys from an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri,
                            xmlSecKeysMngrPtr keysMngr) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlSecKeyPtr key;
    xmlSecKeyInfoCtx keyInfoCtx;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecNssKeysStoreId), -1);
    xmlSecAssert2((uri != NULL), -1);

    doc = xmlParseFile(uri);
    if(doc == NULL) {
        xmlSecXmlError2("xmlParseFile", xmlSecKeyStoreGetName(store),
                        "uri=%s", xmlSecErrorsSafeString(uri));
        return(-1);
    }

    root = xmlDocGetRootElement(doc);
    if(!xmlSecCheckNodeName(root, BAD_CAST "Keys", xmlSecNs)) {
        xmlSecInvalidNodeError(root, BAD_CAST "Keys", xmlSecKeyStoreGetName(store));
        xmlFreeDoc(doc);
        return(-1);
    }

    cur = xmlSecGetNextElementNode(root->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, xmlSecNodeKeyInfo, xmlSecDSigNs)) {
        key = xmlSecKeyCreate();
        if(key == NULL) {
            xmlSecInternalError("xmlSecKeyCreate",
                                xmlSecKeyStoreGetName(store));
            xmlFreeDoc(doc);
            return(-1);
        }

        ret = xmlSecKeyInfoCtxInitialize(&keyInfoCtx, NULL);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyInfoCtxInitialize",
                                xmlSecKeyStoreGetName(store));
            xmlSecKeyDestroy(key);
            xmlFreeDoc(doc);
            return(-1);
        }

        keyInfoCtx.mode           = xmlSecKeyInfoModeRead;
        keyInfoCtx.keysMngr       = keysMngr;
        keyInfoCtx.flags          = XMLSEC_KEYINFO_FLAGS_DONT_STOP_ON_KEY_FOUND |
                                    XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;
        keyInfoCtx.keyReq.keyId   = xmlSecKeyDataIdUnknown;
        keyInfoCtx.keyReq.keyType = xmlSecKeyDataTypeAny;
        keyInfoCtx.keyReq.keyUsage= xmlSecKeyDataUsageAny;

        ret = xmlSecKeyInfoNodeRead(cur, key, &keyInfoCtx);
        if(ret < 0) {
            xmlSecInternalError("xmlSecKeyInfoNodeRead",
                                xmlSecKeyStoreGetName(store));
            xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
            xmlSecKeyDestroy(key);
            xmlFreeDoc(doc);
            return(-1);
        }
        xmlSecKeyInfoCtxFinalize(&keyInfoCtx);

        if(xmlSecKeyIsValid(key)) {
            ret = xmlSecNssKeysStoreAdoptKey(store, key);
            if(ret < 0) {
                xmlSecInternalError("xmlSecNssKeysStoreAdoptKey",
                                    xmlSecKeyStoreGetName(store));
                xmlSecKeyDestroy(key);
                xmlFreeDoc(doc);
                return(-1);
            }
        } else {
            /* we have an unknown key in our file, just ignore it */
            xmlSecKeyDestroy(key);
        }
        cur = xmlSecGetNextElementNode(cur->next);
    }

    if(cur != NULL) {
        xmlSecUnexpectedNodeError(cur, xmlSecKeyStoreGetName(store));
        xmlFreeDoc(doc);
        return(-1);
    }

    xmlFreeDoc(doc);
    return(0);
}

/**
 * xmlSecNssKeysStoreSave:
 * @store:              the pointer to Nss keys store.
 * @filename:           the filename.
 * @type:               the saved keys type (public, private, ...).
 *
 * Writes keys from @store to an XML file.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssKeysStoreSave(xmlSecKeyStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecKeyInfoCtx keyInfoCtx;
    xmlSecNssKeysStoreCtxPtr context ;
    xmlSecPtrListPtr list;
    xmlSecKeyPtr key;
    xmlSecSize i, keysSize;    
    xmlDocPtr doc;
    xmlNodePtr cur;
    xmlSecKeyDataPtr data;
    xmlSecPtrListPtr idsList;
    xmlSecKeyDataId dataId;
    xmlSecSize idsSize, j;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecNssKeysStoreId), -1);
    xmlSecAssert2( xmlSecKeyStoreCheckSize( store , xmlSecNssKeysStoreSize ), -1 ) ;
    xmlSecAssert2(filename != NULL, -1);   

    context = xmlSecNssKeysStoreGetCtx( store ) ;
    xmlSecAssert2( context != NULL, -1 );

    list = context->keyList ;
       xmlSecAssert2( list != NULL, -1 );
    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyPtrListId), -1);

    /* create doc */
    doc = xmlSecCreateTree(BAD_CAST "Keys", xmlSecNs);
    if(doc == NULL) {
        xmlSecInternalError("xmlSecKeyStoreCreate(xmlSecSimpleKeysStoreId)",
                            xmlSecKeyStoreGetName(store));
        return(-1);
    }

    idsList = xmlSecKeyDataIdsGet();   
    xmlSecAssert2(idsList != NULL, -1);

    keysSize = xmlSecPtrListGetSize(list);
    idsSize = xmlSecPtrListGetSize(idsList);
    for(i = 0; i < keysSize; ++i) {
        key = (xmlSecKeyPtr)xmlSecPtrListGetItem(list, i);
        xmlSecAssert2(key != NULL, -1);

        cur = xmlSecAddChild(xmlDocGetRootElement(doc), xmlSecNodeKeyInfo, xmlSecDSigNs);
        if(cur == NULL) {
            xmlSecInternalError("xmlSecAddChild",
                                xmlSecKeyStoreGetName(store));
            xmlFreeDoc(doc); 
            return(-1);
        }

        /* special data key name */
        if(xmlSecKeyGetName(key) != NULL) {
            if(xmlSecAddChild(cur, xmlSecNodeKeyName, xmlSecDSigNs) == NULL) {
                xmlSecInternalError("xmlSecAddChild",
                                    xmlSecKeyStoreGetName(store));
            xmlFreeDoc(doc); 
            return(-1);
            }
        }

        /* create nodes for other keys data */
        for(j = 0; j < idsSize; ++j) {
            dataId = (xmlSecKeyDataId)xmlSecPtrListGetItem(idsList, j);
            xmlSecAssert2(dataId != xmlSecKeyDataIdUnknown, -1);

            if(dataId->dataNodeName == NULL) {
                continue;
            }

            data = xmlSecKeyGetData(key, dataId);
            if(data == NULL) {
                continue;
           }

            if(xmlSecAddChild(cur, dataId->dataNodeName, dataId->dataNodeNs) == NULL) {
                xmlSecInternalError("xmlSecAddChild",
                                    xmlSecKeyStoreGetName(store));
                xmlFreeDoc(doc); 
                return(-1);
           }
        }

        ret = xmlSecKeyInfoCtxInitialize(&keyInfoCtx, NULL);
        if (ret < 0) {
            xmlSecInternalError("xmlSecKeyInfoCtxInitialize",
                                xmlSecKeyStoreGetName(store));
            xmlFreeDoc(doc);
            return(-1);
        }

        keyInfoCtx.mode                 = xmlSecKeyInfoModeWrite;
        keyInfoCtx.keyReq.keyId         = xmlSecKeyDataIdUnknown;
        keyInfoCtx.keyReq.keyType       = type;
        keyInfoCtx.keyReq.keyUsage      = xmlSecKeyDataUsageAny;

        /* finally write key in the node */
        ret = xmlSecKeyInfoNodeWrite(cur, key, &keyInfoCtx);
        if (ret < 0) {
            xmlSecInternalError("xmlSecKeyInfoNodeWrite",
                                xmlSecKeyStoreGetName(store));
        xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
        xmlFreeDoc(doc); 
        return(-1);
        }

        xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
    }

    /* now write result */
    ret = xmlSaveFormatFile(filename, doc, 1);
    if (ret < 0) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
            "xmlSaveFormatFile",
            XMLSEC_ERRORS_R_XML_FAILED,
            "filename=%s", 
            xmlSecErrorsSafeString(filename));
        xmlFreeDoc(doc); 
        return(-1);
    }

    xmlFreeDoc(doc);
    return(0);
}
