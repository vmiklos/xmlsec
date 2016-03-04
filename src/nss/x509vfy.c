/** 
 * XMLSec library
 *
 * X509 support
 *
 *
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyright (c) 2003 America Online, Inc.  All rights reserved.
 */
#include "globals.h"

#ifndef XMLSEC_NO_X509

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <cert.h>
#include <secerr.h>

#include <libxml/tree.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/keys.h>
#include <xmlsec/keyinfo.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/errors.h>

#include <xmlsec/nss/crypto.h>
#include <xmlsec/nss/x509.h>

/**************************************************************************
 *
 * Internal NSS X509 store CTX
 *
 *************************************************************************/
typedef struct _xmlSecNssX509StoreCtx		xmlSecNssX509StoreCtx, 
						*xmlSecNssX509StoreCtxPtr;
struct _xmlSecNssX509StoreCtx {
    CERTCertList* certsList; /* just keeping a reference to destroy later */
};	    

/****************************************************************************
 *
 * xmlSecNssKeyDataStoreX509Id:
 *
 * xmlSecNssX509StoreCtx is located after xmlSecTransform
 *
 ***************************************************************************/
#define xmlSecNssX509StoreGetCtx(store) \
    ((xmlSecNssX509StoreCtxPtr)(((xmlSecByte*)(store)) + \
				    sizeof(xmlSecKeyDataStoreKlass)))
#define xmlSecNssX509StoreSize	\
    (sizeof(xmlSecKeyDataStoreKlass) + sizeof(xmlSecNssX509StoreCtx))
 
static int		xmlSecNssX509StoreInitialize	(xmlSecKeyDataStorePtr store);
static void		xmlSecNssX509StoreFinalize	(xmlSecKeyDataStorePtr store);
static int		xmlSecNssIntegerToItem( const xmlChar* integer , SECItem *it ) ;

static xmlSecKeyDataStoreKlass xmlSecNssX509StoreKlass = {
    sizeof(xmlSecKeyDataStoreKlass),
    xmlSecNssX509StoreSize,

    /* data */
    xmlSecNameX509Store,			/* const xmlChar* name; */ 
        
    /* constructors/destructor */
    xmlSecNssX509StoreInitialize,		/* xmlSecKeyDataStoreInitializeMethod initialize; */
    xmlSecNssX509StoreFinalize,			/* xmlSecKeyDataStoreFinalizeMethod finalize; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

static CERTCertificate*		xmlSecNssX509FindCert(xmlChar *subjectName,
						      xmlChar *issuerName,
						      xmlChar *issuerSerial,
						      xmlChar *ski);


/** 
 * xmlSecNssX509StoreGetKlass:
 * 
 * The NSS X509 certificates key data store klass.
 *
 * Returns: pointer to NSS X509 certificates key data store klass.
 */
xmlSecKeyDataStoreId 
xmlSecNssX509StoreGetKlass(void) {
    return(&xmlSecNssX509StoreKlass);
}

/**
 * xmlSecNssX509StoreFindCert:
 * @store:		the pointer to X509 key data store klass.
 * @subjectName:	the desired certificate name.
 * @issuerName:		the desired certificate issuer name.
 * @issuerSerial:	the desired certificate issuer serial number.
 * @ski:		the desired certificate SKI.
 * @keyInfoCtx:		the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Searches @store for a certificate that matches given criteria.
 *
 * Returns: pointer to found certificate or NULL if certificate is not found
 * or an error occurs.
 */
CERTCertificate *
xmlSecNssX509StoreFindCert(xmlSecKeyDataStorePtr store, xmlChar *subjectName,
				xmlChar *issuerName, xmlChar *issuerSerial,
				xmlChar *ski, xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecNssX509StoreCtxPtr ctx;
    
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    return(xmlSecNssX509FindCert(subjectName, issuerName, issuerSerial, ski));
}

/**
 * xmlSecNssX509StoreVerify:
 * @store:		the pointer to X509 key data store klass.
 * @certs:		the untrusted certificates stack.
 * @keyInfoCtx:		the pointer to <dsig:KeyInfo/> element processing context.
 *
 * Verifies @certs list.
 *
 * Returns: pointer to the first verified certificate from @certs.
 */ 
CERTCertificate * 	
xmlSecNssX509StoreVerify(xmlSecKeyDataStorePtr store, CERTCertList* certs,
			     xmlSecKeyInfoCtx* keyInfoCtx) {
    xmlSecNssX509StoreCtxPtr ctx;
    CERTCertListNode*       head;
    CERTCertificate*       cert = NULL;
    CERTCertListNode*       head1;
    CERTCertificate*       cert1 = NULL;
    SECStatus status = SECFailure;
    int64 timeboundary;
    int64 tmp1, tmp2;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), NULL);
    xmlSecAssert2(certs != NULL, NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, NULL);

    for (head = CERT_LIST_HEAD(certs);
         !CERT_LIST_END(head, certs);
         head = CERT_LIST_NEXT(head)) {
        cert = head->cert;
	if(keyInfoCtx->certsVerificationTime > 0) {
	    /* convert the time since epoch in seconds to microseconds */
	    LL_UI2L(timeboundary, keyInfoCtx->certsVerificationTime);
	    tmp1 = (int64)PR_USEC_PER_SEC;
	    tmp2 = timeboundary;
	    LL_MUL(timeboundary, tmp1, tmp2);
	} else {
	    timeboundary = PR_Now();
	}

	/* if cert is the issuer of any other cert in the list, then it is 
	 * to be skipped */
	for (head1 = CERT_LIST_HEAD(certs); 
	     !CERT_LIST_END(head1, certs);
	     head1 = CERT_LIST_NEXT(head1)) {

	    cert1 = head1->cert;
	    if (cert1 == cert) {
		continue;
	    }

	    if (SECITEM_CompareItem(&cert1->derIssuer, &cert->derSubject)
	                              == SECEqual) {
		break;
	    }
	}

	if (!CERT_LIST_END(head1, certs)) {
	    continue;
	}


	/*
      JL: OpenOffice.org implements its own certificate verification routine. 
      The goal is to separate validation of the signature
      and the certificate. For example, OOo could show that the document signature is valid,
      but the certificate could not be verified. If we do not prevent the verification of
      the certificate by libxmlsec and the verification fails, then the XML signature may not be 
      verified. This would happen, for example, if the root certificate is not installed.
      
      status = CERT_VerifyCertificate(CERT_GetDefaultCertDB(), 
          cert, PR_FALSE, 
          (SECCertificateUsage)0,
          timeboundary , NULL, NULL, NULL);
      if (status == SECSuccess) {
         break;
      }
	 
    */
	status = SECSuccess;
	break;

    }

    if (status == SECSuccess) {
	return (cert);
    }
    
    switch(PORT_GetError()) {
	case SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE:
	case SEC_ERROR_CA_CERT_INVALID:
	case SEC_ERROR_UNKNOWN_SIGNER:
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        NULL,
                        XMLSEC_ERRORS_R_CERT_ISSUER_FAILED,
                        "cert with subject name %s could not be verified because the issuer's cert is expired/invalid or not found",
                        cert->subjectName);
	    break;
	case SEC_ERROR_EXPIRED_CERTIFICATE:
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        NULL,
                        XMLSEC_ERRORS_R_CERT_HAS_EXPIRED,
                        "cert with subject name %s has expired",
                        cert->subjectName);
	    break;
	case SEC_ERROR_REVOKED_CERTIFICATE:
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        NULL,
                        XMLSEC_ERRORS_R_CERT_REVOKED,
                        "cert with subject name %s has been revoked",
                        cert->subjectName);
	    break;
	default:
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        NULL,
                        XMLSEC_ERRORS_R_CERT_VERIFY_FAILED,
						"cert with subject name %s could not be verified, errcode %d",
						cert->subjectName,
			PORT_GetError());
	    break;
    }
   
    return (NULL);
}

/**
 * xmlSecNssX509StoreAdoptCert:
 * @store:              the pointer to X509 key data store klass.
 * @cert:               the pointer to NSS X509 certificate.
 * @type:               the certificate type (trusted/untrusted).
 *
 * Adds trusted (root) or untrusted certificate to the store.
 *
 * Returns: 0 on success or a negative value if an error occurs.
 */
int
xmlSecNssX509StoreAdoptCert(xmlSecKeyDataStorePtr store, CERTCertificate* cert, xmlSecKeyDataType type ATTRIBUTE_UNUSED) {
    xmlSecNssX509StoreCtxPtr ctx;
    int ret;

    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), -1);
    xmlSecAssert2(cert != NULL, -1);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    if(ctx->certsList == NULL) {
        ctx->certsList = CERT_NewCertList();
        if(ctx->certsList == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                        "CERT_NewCertList",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
						"error code=%d", PORT_GetError());
            return(-1);
        }
    }

    ret = CERT_AddCertToListTail(ctx->certsList, cert);
    if(ret != SECSuccess) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                    xmlSecErrorsSafeString(xmlSecKeyDataStoreGetName(store)),
                    "CERT_AddCertToListTail",
                    XMLSEC_ERRORS_R_CRYPTO_FAILED,
					"error code=%d", PORT_GetError());
        return(-1);
    }

    return(0);
}

static int
xmlSecNssX509StoreInitialize(xmlSecKeyDataStorePtr store) {
    xmlSecNssX509StoreCtxPtr ctx;
    xmlSecAssert2(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId), -1);

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert2(ctx != NULL, -1);

    memset(ctx, 0, sizeof(xmlSecNssX509StoreCtx));

    return(0);    
}

static void
xmlSecNssX509StoreFinalize(xmlSecKeyDataStorePtr store) {
    xmlSecNssX509StoreCtxPtr ctx;
    xmlSecAssert(xmlSecKeyDataStoreCheckId(store, xmlSecNssX509StoreId));

    ctx = xmlSecNssX509StoreGetCtx(store);
    xmlSecAssert(ctx != NULL);
    
    if (ctx->certsList) {
	CERT_DestroyCertList(ctx->certsList);
	ctx->certsList = NULL;
    }

    memset(ctx, 0, sizeof(xmlSecNssX509StoreCtx));
}


/*****************************************************************************
 *
 * Low-level x509 functions
 *
 *****************************************************************************/
static CERTCertificate*		
xmlSecNssX509FindCert(xmlChar *subjectName, xmlChar *issuerName, 
		      xmlChar *issuerSerial, xmlChar *ski) {
    CERTCertificate *cert = NULL;
    CERTName *name = NULL;
    SECItem *nameitem = NULL;
    PRArenaPool *arena = NULL;

    if (subjectName != NULL) {
	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "PORT_NewArena",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        "error code=%d", PORT_GetError());
	    goto done;
	}

	name = CERT_AsciiToName((char*)subjectName);
	if (name == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "CERT_AsciiToName",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "error code=%d", PORT_GetError());
	    goto done;
	}

	nameitem = SEC_ASN1EncodeItem(arena, NULL, (void *)name,
				      SEC_ASN1_GET(CERT_NameTemplate));
	if (nameitem == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "SEC_ASN1EncodeItem",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
						"error code=%d", PORT_GetError());
	    goto done;
	}

	cert = CERT_FindCertByName(CERT_GetDefaultCertDB(), nameitem);
	goto done;
    }

    if((issuerName != NULL) && (issuerSerial != NULL)) {
	CERTIssuerAndSN issuerAndSN;

	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "PORT_NewArena",
                        XMLSEC_ERRORS_R_CRYPTO_FAILED,
                        "error code=%d", PORT_GetError());
	    goto done;
	}

	name = CERT_AsciiToName((char*)issuerName);
	if (name == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "CERT_AsciiToName",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "error code=%d", PORT_GetError());
	    goto done;
	}

	nameitem = SEC_ASN1EncodeItem(arena, NULL, (void *)name,
				      SEC_ASN1_GET(CERT_NameTemplate));
	if (nameitem == NULL) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "SEC_ASN1EncodeItem",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
						"error code=%d", PORT_GetError());
	    goto done;
	}

	memset(&issuerAndSN, 0, sizeof(issuerAndSN));

	issuerAndSN.derIssuer.data = nameitem->data;
	issuerAndSN.derIssuer.len = nameitem->len;

        if( xmlSecNssIntegerToItem( issuerSerial, &issuerAndSN.serialNumber ) < 0 ) {
                xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecNssIntegerToItem",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "serial number=%s",
                        xmlSecErrorsSafeString(issuerSerial));
                goto done;
        }

	cert = CERT_FindCertByIssuerAndSN(CERT_GetDefaultCertDB(), 
					  &issuerAndSN);
	SECITEM_FreeItem(&issuerAndSN.serialNumber, PR_FALSE);
	goto done;
    }

    if(ski != NULL) {
	SECItem subjKeyID;
	int len;

	len = xmlSecBase64Decode(ski, (xmlSecByte*)ski, xmlStrlen(ski));
        if(len < 0) {
            xmlSecError(XMLSEC_ERRORS_HERE,
                        NULL,
                        "xmlSecBase64Decode",
                        XMLSEC_ERRORS_R_XMLSEC_FAILED,
                        "ski=%s",
                        xmlSecErrorsSafeString(ski));
	    goto done;
        }

	memset(&subjKeyID, 0, sizeof(subjKeyID));
	subjKeyID.data = ski;
	subjKeyID.len = xmlStrlen(ski);
        cert = CERT_FindCertBySubjectKeyID(CERT_GetDefaultCertDB(), 
					   &subjKeyID);
    }

done:
    if (arena != NULL) {
	PORT_FreeArena(arena, PR_FALSE);
    }
    if (name != NULL) {
	CERT_DestroyName(name);
    }

    return(cert);
}

/* code lifted from NSS */
static void
xmlSecNssNumToItem(SECItem *it, unsigned long ui)
{
    unsigned char bb[5];
    int len;

    bb[0] = 0;
    bb[1] = (unsigned char) (ui >> 24);
    bb[2] = (unsigned char) (ui >> 16);
    bb[3] = (unsigned char) (ui >> 8);
    bb[4] = (unsigned char) (ui);

    /*
    ** Small integers are encoded in a single byte. Larger integers
    ** require progressively more space.
    */
    if (ui > 0x7f) {
        if (ui > 0x7fff) {
            if (ui > 0x7fffffL) {
                if (ui >= 0x80000000L) {
                    len = 5;
                } else {
                    len = 4;
                }
            } else {
                len = 3;
            }
        } else {
            len = 2;
        }
    } else {
        len = 1;
    }

    it->data = (unsigned char *)PORT_Alloc(len);
    if (it->data == NULL) {
        return;
    }

    it->len = len;
    PORT_Memcpy(it->data, bb + (sizeof(bb) - len), len);
}

static int
xmlSecNssIntegerToItem(
       const xmlChar* integer ,
       SECItem *item
) {
    xmlSecBn bn ;
    xmlSecSize i, length ;
    const xmlSecByte* bnInteger ;

    xmlSecAssert2( integer != NULL, -1 ) ;
    xmlSecAssert2( item != NULL, -1 ) ;

    if( xmlSecBnInitialize( &bn, 0 ) < 0 ) {
        xmlSecError(XMLSEC_ERRORS_HERE,
                       NULL,
                       "xmlSecBnInitialize",
                       XMLSEC_ERRORS_R_INVALID_DATA,
                       XMLSEC_ERRORS_NO_MESSAGE);
           return -1 ;
    }

    if( xmlSecBnFromDecString( &bn, integer ) < 0 ) {
                   xmlSecError(XMLSEC_ERRORS_HERE,
                               NULL,
                               "xmlSecBnFromDecString",
                               XMLSEC_ERRORS_R_INVALID_DATA,
                               XMLSEC_ERRORS_NO_MESSAGE);
        xmlSecBnFinalize( &bn ) ;
        return -1 ;
    }

    length = xmlSecBnGetSize( &bn ) ;
    if( length <= 0 ) {
                   xmlSecError(XMLSEC_ERRORS_HERE,
                               NULL,
                               "xmlSecBnGetSize",
                               XMLSEC_ERRORS_R_INVALID_DATA,
                               XMLSEC_ERRORS_NO_MESSAGE);
    }

    bnInteger = xmlSecBnGetData( &bn ) ;
    if( bnInteger == NULL ) {
                   xmlSecError(XMLSEC_ERRORS_HERE,
                               NULL,
                               "xmlSecBnGetData",
                               XMLSEC_ERRORS_R_INVALID_DATA,
                               XMLSEC_ERRORS_NO_MESSAGE ) ;
        xmlSecBnFinalize( &bn ) ;
        return -1 ;
    }

    item->data = ( unsigned char * )PORT_Alloc( length );
    if( item->data == NULL ) {
                   xmlSecError(XMLSEC_ERRORS_HERE,
                               NULL,
                               "PORT_Alloc",
                               XMLSEC_ERRORS_R_INVALID_DATA,
                               XMLSEC_ERRORS_NO_MESSAGE ) ;
        xmlSecBnFinalize( &bn ) ;
        return -1 ;
    }

    item->len = length;
    for( i = 0 ; i < length ; i ++ )
        item->data[i] = *( bnInteger + i ) ;

    xmlSecBnFinalize( &bn ) ;

    return 0 ;
}
#endif /* XMLSEC_NO_X509 */


