/** 
 * XML Security Library (http://www.aleksey.com/xmlsec).
 *
 * Keys Manager
 * 
 * This is free software; see Copyright file in the source
 * distribution for preciese wording.
 * 
 * Copyrigth (C) 2002-2003 Aleksey Sanin <aleksey@aleksey.com>
 */
#include "globals.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/list.h>
#include <xmlsec/keys.h>
#include <xmlsec/transforms.h>
#include <xmlsec/keysmngr.h>
#include <xmlsec/errors.h>

/****************************************************************************
 *
 * Keys Manager
 *
 ***************************************************************************/
/** 
 * xmlSecKeysMngrCreate:
 * 
 * Creates new keys manager. Caller is responsible for freeing it with 
 * #xmlSecKeysMngrDestroy function.
 * 
 * Returns the pointer to newly allocated keys manager or NULL if 
 * an error occurs.
 */
xmlSecKeysMngrPtr 
xmlSecKeysMngrCreate(void) {
    xmlSecKeysMngrPtr mngr;
    int ret;
    
    /* Allocate a new xmlSecKeysMngr and fill the fields. */
    mngr = (xmlSecKeysMngrPtr)xmlMalloc(sizeof(xmlSecKeysMngr));
    if(mngr == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecKeysMngr",
		    "xmlMalloc",
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "sizeof(xmlSecKeysMngr)=%d", 
		    sizeof(xmlSecKeysMngr));
	return(NULL);
    }
    memset(mngr, 0, sizeof(xmlSecKeysMngr));    

    ret = xmlSecPtrListInitialize(&(mngr->storesList), xmlSecKeyDataStorePtrListId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    "xmlSecKeysMngr",
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyDataStorePtrListId");
	return(-1);
    }

    return(mngr);    
}

/** 
 * xmlSecKeysMngrDestroy:
 * @mngr:		the pointer to keys manager.
 *
 * Destroys keys manager created with #xmlSecKeysMngrCreate function.
 */
void
xmlSecKeysMngrDestroy(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert(mngr != NULL);

    /* destroy keys store */
    if(mngr->keysStore != NULL) {
	xmlSecKeyStoreDestroy(mngr->keysStore);
    }
    
    /* destroy other data stores */
    xmlSecPtrListFinalize(&(mngr->storesList));

    memset(mngr, 0, sizeof(xmlSecKeysMngr));    
    xmlFree(mngr);    
}

/**
 * xmlSecKeysMngrFindKey:
 * @mngr:		the pointer to keys manager.
 * @key:		the pointer to destination key.
 * @name:		the desired key name.
 * @keyInfoCtx:		the pointer to <dsig:KeyInfo/> node processing context.
 *
 * Lookups key in the keys manager keys store and copies results to @key. 
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeysMngrFindKey(xmlSecKeysMngrPtr mngr, xmlSecKeyPtr key, 
		     const xmlChar* name, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyStorePtr store;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    
    store = xmlSecKeysMngrGetKeysStore(mngr);
    if(store == NULL) {
	/* no store. is it an error? */
	return(0);
    }
    
    return(xmlSecKeyStoreFind(store, key, name, keyInfoCtx));
}

/**
 * xmlSecKeysMngrAdoptKeysStore:
 * @mngr:		the pointer to keys manager.
 * @store:		the pointer to keys store.
 *
 * Adopts keys store in the keys manager @mngr.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeysMngrAdoptKeysStore(xmlSecKeysMngrPtr mngr, xmlSecKeyStorePtr store) {
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(xmlSecKeyStoreIsValid(store), -1);
    
    if(mngr->keysStore != NULL) {
	xmlSecKeyStoreDestroy(mngr->keysStore);
    }
    mngr->keysStore = store;
    
    return(0);
}

/**
 * xmlSecKeysMngrGetKeysStore:
 * @mngr:		the pointer to keys manager.
 *
 * Gets the keys store.
 *
 * Returns the keys store in the keys manager @mngr or NULL if 
 * there is no store or an error occurs.
 */
xmlSecKeyStorePtr
xmlSecKeysMngrGetKeysStore(xmlSecKeysMngrPtr mngr) {
    xmlSecAssert2(mngr != NULL, NULL);
    
    return(mngr->keysStore);
}

/**
 * xmlSecKeysMngrAdoptDataStore:
 * @mngr:		the pointer to keys manager.
 * @store:		the pointer to data store.
 *
 * Adopts data store in the keys manager.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecKeysMngrAdoptDataStore(xmlSecKeysMngrPtr mngr, xmlSecKeyDataStorePtr store) {
    xmlSecKeyDataStorePtr tmp;
    size_t pos, size;
    
    xmlSecAssert2(mngr != NULL, -1);
    xmlSecAssert2(xmlSecKeyDataStoreIsValid(store), -1);

    size = xmlSecPtrListGetSize(&(mngr->storesList));
    for(pos = 0; pos < size; ++pos) {
	tmp = (xmlSecKeyDataStorePtr)xmlSecPtrListGetItem(&(mngr->storesList), pos);
	if((tmp != NULL) && (tmp->id == store->id)) {	
	    return(xmlSecPtrListSet(&(mngr->storesList), store, pos));
	}
    }
    
    return(xmlSecPtrListAdd(&(mngr->storesList), store));
}


/**
 * xmlSecKeysMngrGetDataStore:
 * @mngr:		the pointer to keys manager.
 * @id:			the desired data store klass.
 *
 * Lookups the data store of given klass @id in the keys manager.
 *
 * Returns pointer to data store or NULL if it is not found or an error
 * occurs.
 */
xmlSecKeyDataStorePtr 
xmlSecKeysMngrGetDataStore(xmlSecKeysMngrPtr mngr, xmlSecKeyDataStoreId id) {
    xmlSecKeyDataStorePtr tmp;
    size_t pos, size;
    
    xmlSecAssert2(mngr != NULL, NULL);
    xmlSecAssert2(id != xmlSecKeyDataStoreIdUnknown, NULL);

    size = xmlSecPtrListGetSize(&(mngr->storesList));
    for(pos = 0; pos < size; ++pos) {
	tmp = (xmlSecKeyDataStorePtr)xmlSecPtrListGetItem(&(mngr->storesList), pos);
	if((tmp != NULL) && (tmp->id == id)) {	
	    return(tmp);
	}
    }
    
    return(NULL);
}

/**************************************************************************
 *
 * xmlSecKeyStore functions
 *
 *************************************************************************/
/**
 * xmlSecKeyStoreCreate:
 * @id: 		the key store klass.
 *
 * Creates new store of the specified klass @klass. Caller is responsible
 * for freeing the returned store by calling #xmlSecKeyStoreDestroy function.
 *
 * Returns the pointer to newly allocated keys store or NULL if an error occurs.
 */
xmlSecKeyStorePtr	
xmlSecKeyStoreCreate(xmlSecKeyStoreId id)  {
    xmlSecKeyStorePtr store;
    int ret;
        
    xmlSecAssert2(id != NULL, NULL);
    xmlSecAssert2(id->objSize > 0, NULL);
        
    /* Allocate a new xmlSecKeyStore and fill the fields. */
    store = (xmlSecKeyStorePtr)xmlMalloc(id->objSize);
    if(store == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreKlassGetName(id)),
		    "xmlMalloc",		    
		    XMLSEC_ERRORS_R_MALLOC_FAILED,
		    "%d", id->objSize); 
	return(NULL);
    }
    memset(store, 0, id->objSize);    
    store->id = id;

    if(id->initialize != NULL) {
	ret = (id->initialize)(store);
        if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyStoreKlassGetName(id)),
			"id->initialize",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyStoreDestroy(store);
	    return(NULL);
	}
    }
    
    return(store);
}

/**
 * xmlSecKeyStoreDestroy:
 * @store: 		the pointer to keys store. 
 *
 * Destroys the store created with #xmlSecKeyStoreCreate function.
 */
void
xmlSecKeyStoreDestroy(xmlSecKeyStorePtr store) {
    xmlSecAssert(xmlSecKeyStoreIsValid(store));    
    xmlSecAssert(store->id->objSize > 0);
    
    if(store->id->finalize != NULL) {  
        (store->id->finalize)(store);
    }
    memset(store, 0, store->id->objSize);
    xmlFree(store);
}

/**
 * xmlSecKeyStoreFind:
 * @store:		the pointer to keys store.
 * @key:		the pointer to destination key.
 * @name:		the desired key name.
 * @keyInfoCtx:		the pointer to <dsig:KeyInfo/> node processing context.
 *
 * Lookups key in the keys manager keys store and copies results to @key. 
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecKeyStoreFind(xmlSecKeyStorePtr store, xmlSecKeyPtr key, const xmlChar* name,
		       xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecAssert2(xmlSecKeyStoreIsValid(store), -1);    
    xmlSecAssert2(store->id->find != NULL, -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);

    return(store->id->find(store, key, name, keyInfoCtx));
}

/****************************************************************************
 *
 * Simple Keys Store
 * 
 * keys list (xmlSecPtrList) is located after xmlSecKeyStore
 *
 ***************************************************************************/
#define xmlSecSimpleKeysStoreSize \
	(sizeof(xmlSecKeyStore) + sizeof(xmlSecPtrList))
#define xmlSecSimpleKeysStoreGetList(store) \
    ((xmlSecKeyStoreCheckSize((store), xmlSecSimpleKeysStoreSize)) ? \
	(xmlSecPtrListPtr)(((unsigned char*)(store)) + sizeof(xmlSecKeyStore)) : \
	(xmlSecPtrListPtr)NULL)

static int			xmlSecSimpleKeysStoreInitialize	(xmlSecKeyStorePtr store);
static void			xmlSecSimpleKeysStoreFinalize	(xmlSecKeyStorePtr store);
static int			xmlSecSimpleKeysStoreFind	(xmlSecKeyStorePtr store,
								 xmlSecKeyPtr key,
								 const xmlChar* name,
								 xmlSecKeyInfoCtxPtr keyInfoCtx);

static xmlSecKeyStoreKlass xmlSecSimpleKeysStoreKlass = {
    sizeof(xmlSecKeyStoreKlass),
    xmlSecSimpleKeysStoreSize,

    /* data */
    BAD_CAST "simple-keys-store",		/* const xmlChar* name; */ 
        
    /* constructors/destructor */
    xmlSecSimpleKeysStoreInitialize,		/* xmlSecKeyStoreInitializeMethod initialize; */
    xmlSecSimpleKeysStoreFinalize,		/* xmlSecKeyStoreFinalizeMethod finalize; */
    xmlSecSimpleKeysStoreFind,			/* xmlSecKeyStoreFindMethod find; */

    /* reserved for the future */
    NULL,					/* void* reserved0; */
    NULL,					/* void* reserved1; */
};

/**
 * xmlSecSimpleKeysStoreGetKlass:
 * 
 * The simple list based keys store klass.
 *
 * Returns simple list based keys store klass.
 */
xmlSecKeyStoreId 
xmlSecSimpleKeysStoreGetKlass(void) {
    return(&xmlSecSimpleKeysStoreKlass);
}

/**
 * xmlSecSimpleKeysStoreAdoptKey:
 * @store:		the pointer to simple keys store.
 * @key:		the pointer to key.
 * 
 * Adds @key to the @store. 
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int 
xmlSecSimpleKeysStoreAdoptKey(xmlSecKeyStorePtr store, xmlSecKeyPtr key) {
    xmlSecPtrListPtr list;
    int ret;
    
    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);
    xmlSecAssert2(key != NULL, -1);

    list = xmlSecSimpleKeysStoreGetList(store);
    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyPtrListId), -1);

    ret = xmlSecPtrListAdd(list, key);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlSecPtrListAdd",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }

    return(0);
}

/**
 * xmlSecSimpleKeysStoreFindKey:
 * @store:		the pointer to simple keys store.
 * @name:		the desired key name.
 * @keyInfoCtx:		the pointer to <dsig:KeyInfo/> node processing context.
 *  
 * Lookups key in the @store.
 *
 * Returns pointer to key or NULL if key not found or an error occurs.
 */
xmlSecKeyPtr 
xmlSecSimpleKeysStoreFindKey(xmlSecKeyStorePtr store, const xmlChar* name, 
			    xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecPtrListPtr list;
    xmlSecKeyPtr key;
    size_t pos, size;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId), NULL);
    xmlSecAssert2(keyInfoCtx != NULL, NULL);

    list = xmlSecSimpleKeysStoreGetList(store);
    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyPtrListId), NULL);

    size = xmlSecPtrListGetSize(list);
    for(pos = 0; pos < size; ++pos) {
	key = (xmlSecKeyPtr)xmlSecPtrListGetItem(list, pos);
	if((key != NULL) && (xmlSecKeyMatch(key, name, &(keyInfoCtx->keyReq)) == 1)) {
	    return(key);
	}
    }
    return(NULL);
}

/** 
 * xmlSecSimpleKeysStoreLoad:
 * @store:		the pointer to simple keys store.
 * @uri:		the filename.
 * @keysMngr:		the pointer to associated keys manager. 
 * 
 * Reads keys from an XML file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecSimpleKeysStoreLoad(xmlSecKeyStorePtr store, const char *uri, 
			    xmlSecKeysMngrPtr keysMngr) {
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlSecKeyPtr key;
    xmlSecKeyInfoCtx keyInfoCtx;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);
    xmlSecAssert2(uri != NULL, -1);    

    doc = xmlParseFile(uri);
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlParseFile",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "uri=\"%s\"", uri);
	return(-1);
    }
    
    root = xmlDocGetRootElement(doc);
    if(!xmlSecCheckNodeName(root, BAD_CAST "Keys", xmlSecNs)) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    xmlSecNodeGetName(root),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "<xmlsec:Keys>");
	xmlFreeDoc(doc);
	return(-1);
    }
        
    cur = xmlSecGetNextElementNode(root->children);
    while((cur != NULL) && xmlSecCheckNodeName(cur, BAD_CAST "KeyInfo", xmlSecDSigNs)) {  
	key = xmlSecKeyCreate();
	if(key == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			xmlSecNodeGetName(cur),
			XMLSEC_ERRORS_R_INVALID_NODE,
			"<dsig:KeyInfo>");
	    xmlFreeDoc(doc);
	    return(-1);
	}

	ret = xmlSecKeyInfoCtxInitialize(&keyInfoCtx, NULL);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		        xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			"xmlSecKeyInfoCtxInitialize",
			XMLSEC_ERRORS_R_INVALID_NODE,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyDestroy(key);
	    xmlFreeDoc(doc);
	    return(-1);
	}
	
	keyInfoCtx.mode 	  = xmlSecKeyInfoModeRead;
	keyInfoCtx.keysMngr	  = keysMngr;
	keyInfoCtx.flags 	  = XMLSEC_KEYINFO_FLAGS_DONT_STOP_ON_KEY_FOUND |
				    XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;
        keyInfoCtx.keyReq.keyId	  = xmlSecKeyDataIdUnknown;
	keyInfoCtx.keyReq.keyType = xmlSecKeyDataTypeAny;
	keyInfoCtx.keyReq.keyUsage= xmlSecKeyDataUsageAny;

	ret = xmlSecKeyInfoNodeRead(cur, key, &keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			"xmlSecKeyInfoNodeRead",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
	    xmlSecKeyDestroy(key);
	    xmlFreeDoc(doc);
	    return(-1);
	}
	xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
	
	if(xmlSecKeyIsValid(key)) {
    	    ret = xmlSecSimpleKeysStoreAdoptKey(store, key);
	    if(ret < 0) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			    "xmlSecSimpleKeysStoreAdoptKey",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    XMLSEC_ERRORS_NO_MESSAGE);
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
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    xmlSecNodeGetName(cur),
		    XMLSEC_ERRORS_R_INVALID_NODE,
		    "no more nodes expected");
	xmlFreeDoc(doc);
	return(-1);	    
    }
    
    xmlFreeDoc(doc);
    return(0);

}

/** 
 * xmlSecSimpleKeysStoreSave:
 * @store:		the pointer to simple keys store.
 * @filename:		the filename.
 * @type:		the saved keys type (public, private, ...).
 * 
 * Writes keys from @store to an XML file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int
xmlSecSimpleKeysStoreSave(xmlSecKeyStorePtr store, const char *filename, xmlSecKeyDataType type) {
    xmlSecKeyInfoCtx keyInfoCtx;
    xmlSecPtrListPtr list;
    xmlSecKeyPtr key;
    size_t i, keysSize;    
    xmlDocPtr doc;
    xmlNodePtr root;
    xmlNodePtr cur;
    xmlSecKeyDataPtr data;
    xmlSecPtrListPtr idsList;
    xmlSecKeyDataId dataId;
    size_t idsSize, j;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);
    xmlSecAssert2(filename != NULL, -1);    

    list = xmlSecSimpleKeysStoreGetList(store);
    xmlSecAssert2(xmlSecPtrListCheckId(list, xmlSecKeyPtrListId), -1);

    /* create doc */
    doc = xmlNewDoc(BAD_CAST "1.0");
    if(doc == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlNewDoc",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    /* create root node "Keys" */
    root = xmlNewDocNode(doc, NULL, BAD_CAST "Keys", NULL); 
    if(root == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlNewDocNode",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "Keys");
	xmlFreeDoc(doc);
	return(-1);
    }
    xmlDocSetRootElement(doc, root);
    if(xmlNewNs(root, xmlSecNs, NULL) == NULL) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlNewNs",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "xmlSecNs");
	xmlFreeDoc(doc); 
	return(-1);
    }
    
    
    idsList = xmlSecKeyDataIdsGet();	
    xmlSecAssert2(idsList != NULL, -1);
	
    keysSize = xmlSecPtrListGetSize(list);
    idsSize = xmlSecPtrListGetSize(idsList);
    for(i = 0; i < keysSize; ++i) {
	key = (xmlSecKeyPtr)xmlSecPtrListGetItem(list, i);
	xmlSecAssert2(key != NULL, -1);
	    
    	cur = xmlSecAddChild(root, BAD_CAST "KeyInfo", xmlSecDSigNs);
	if(cur == NULL) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			"xmlSecAddChild",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			"<dsig:KeyInfo>");
	    xmlFreeDoc(doc); 
	    return(-1);
	}

	/* special data key name */
	if(xmlSecKeyGetName(key) != NULL) {
    	    if(xmlSecAddChild(cur, BAD_CAST "KeyName", xmlSecDSigNs) == NULL) {
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			    "xmlSecAddChild",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "<dsig:KeyName>");
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
		xmlSecError(XMLSEC_ERRORS_HERE,
			    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			    "xmlSecAddChild",
			    XMLSEC_ERRORS_R_XMLSEC_FAILED,
			    "node=\"%s\"", dataId->dataNodeName);
		xmlFreeDoc(doc); 
	        return(-1);
	    }
	}

    	ret = xmlSecKeyInfoCtxInitialize(&keyInfoCtx, NULL);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
		    	xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			"xmlSecKeyInfoCtxInitialize",
			XMLSEC_ERRORS_R_INVALID_NODE,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlFreeDoc(doc);
	    return(-1);
	}

	keyInfoCtx.mode 		= xmlSecKeyInfoModeWrite;
    	keyInfoCtx.keyReq.keyId		= xmlSecKeyDataIdUnknown;
	keyInfoCtx.keyReq.keyType	= type;
	keyInfoCtx.keyReq.keyUsage 	= xmlSecKeyDataUsageAny;

	/* finally write key in the node */
	ret = xmlSecKeyInfoNodeWrite(cur, key, &keyInfoCtx);
	if(ret < 0) {
	    xmlSecError(XMLSEC_ERRORS_HERE,
			xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
			"xmlSecKeyInfoNodeWrite",
			XMLSEC_ERRORS_R_XMLSEC_FAILED,
			XMLSEC_ERRORS_NO_MESSAGE);
	    xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
	    xmlFreeDoc(doc); 
	    return(-1);
	}		
	xmlSecKeyInfoCtxFinalize(&keyInfoCtx);
    }
    
    /* now write result */
    ret = xmlSaveFormatFile(filename, doc, 1);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlSaveFormatFile",
		    XMLSEC_ERRORS_R_XML_FAILED,
		    "filename=\"%s\"", filename);
	xmlFreeDoc(doc); 
	return(-1);
    }	   
    
    xmlFreeDoc(doc);
    return(0);
}

static int
xmlSecSimpleKeysStoreInitialize(xmlSecKeyStorePtr store) {
    xmlSecPtrListPtr list;
    int ret;

    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);

    list = xmlSecSimpleKeysStoreGetList(store);
    xmlSecAssert2(list != NULL, -1);
    
    ret = xmlSecPtrListInitialize(list, xmlSecKeyPtrListId);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlSecPtrListInitialize",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    "xmlSecKeyPtrListId");
	return(-1);
    }

    return(0);    
}

static void
xmlSecSimpleKeysStoreFinalize(xmlSecKeyStorePtr store) {
    xmlSecPtrListPtr list;
    
    xmlSecAssert(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId));
    
    list = xmlSecSimpleKeysStoreGetList(store);
    xmlSecAssert(list != NULL);
    
    xmlSecPtrListFinalize(list);
}

static int
xmlSecSimpleKeysStoreFind(xmlSecKeyStorePtr store,  xmlSecKeyPtr key, 
			const xmlChar* name, xmlSecKeyInfoCtxPtr keyInfoCtx) {
    xmlSecKeyPtr storedKey;
    int ret;
    
    xmlSecAssert2(xmlSecKeyStoreCheckId(store, xmlSecSimpleKeysStoreId), -1);
    xmlSecAssert2(key != NULL, -1);
    xmlSecAssert2(keyInfoCtx != NULL, -1);
    
    storedKey = xmlSecSimpleKeysStoreFindKey(store, name, keyInfoCtx);
    if(storedKey == NULL) {
	/* found nothing */
	return(0);
    }
    
    /* erase any current information in the key */
    xmlSecKeyEmpty(key);
    
    /* and copy the key from keys storage */
    ret = xmlSecKeyCopy(key, storedKey);
    if(ret < 0) {
	xmlSecError(XMLSEC_ERRORS_HERE,
		    xmlSecErrorsSafeString(xmlSecKeyStoreGetName(store)),
		    "xmlSecKeyCopy",
		    XMLSEC_ERRORS_R_XMLSEC_FAILED,
		    XMLSEC_ERRORS_NO_MESSAGE);
	return(-1);
    }
    
    return(0);
}

