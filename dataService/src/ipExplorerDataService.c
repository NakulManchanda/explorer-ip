

/*
  This program and the accompanying materials are
  made available under the terms of the Eclipse Public License v2.0 which accompanies
  this distribution, and is available at https://www.eclipse.org/legal/epl-v20.html

  SPDX-License-Identifier: EPL-2.0

  Copyright Contributors to the Zowe Project.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ezbnmrhc.h>
#include <ezbnmmpc.h>

#include "httpserver.h"
#include "dataservice.h"
#include "json.h"
#include "http.h"
#include "zis/client.h"
#include "zssLogging.h"


#define NMIBUFSIZE 0x1000
#define NOT_ENOUGH_SPACE 1122

uint64 loggingId;

typedef struct NMIBufferType_tag{
  NWMHeader    header;
  NWMFilter    filters[1];  /* the filters exist in an OR of an and of the properties in the Filterr Object */
} NMIBufferType;

/* Build and dispatch a request to the NWM service */

NMIBufferType *buildAndExecuteNWMService(int *bufferResponseLength,
                                CrossMemoryServerName *privilegedServerName,
                                char *tcpip,
                                unsigned short nwmRequestType) {
  int attempts = 0;
  int bufferLength = NMIBUFSIZE;
  
  while (attempts < 2) {
    NMIBufferType *nmiBuffer = (NMIBufferType *)safeMalloc(bufferLength, "NMI buffer");
    if (nmiBuffer == NULL) {
      *bufferResponseLength = 0;
      return NULL;
    }
    *bufferResponseLength = bufferLength;
    /* Fill Header */
    nmiBuffer->header.NWMHeaderIdent=NWMHEADERIDENTIFIER;
    nmiBuffer->header.NWMHeaderLength=sizeof(NWMHeader);
    nmiBuffer->header.NWMVersion=NWMVERSION1;
    
    nmiBuffer->header.NWMType=nwmRequestType; 
    nmiBuffer->header.NWMBytesNeeded=0;
    nmiBuffer->header.NWMInputDataDescriptors.NWMFiltersDesc.NWMTOffset=sizeof(NWMHeader);
    nmiBuffer->header.NWMInputDataDescriptors.NWMFiltersDesc.NWMTLength=sizeof(NWMFilter);
    nmiBuffer->header.NWMInputDataDescriptors.NWMFiltersDesc.NWMTNumber=0; // No filter active
    
    int currTraceLevel = logGetLevel(NULL, loggingId);

    zowelog(NULL, loggingId, ZOWE_LOG_DEBUG2,
            "request buffer:\n");
    zowedump(NULL, loggingId, ZOWE_LOG_DEBUG2,
            (char*)nmiBuffer, sizeof(NWMHeader));

    attempts++;

    ZISNWMJobName jobName;
    memset(jobName.value, 0x40, sizeof(ZISNWMJobName));
    memcpy(jobName.value, tcpip, strlen(tcpip));
    ZISNWMServiceStatus zisStatus = {0};
      

    int zisRC = zisCallNWMService(privilegedServerName,
                                  jobName, (char *)nmiBuffer, bufferLength,
                                  &zisStatus, currTraceLevel);

    zowelog(NULL, loggingId, ZOWE_LOG_DEBUG2,
            "ZIS NWM RC = %d, NWM RV = 0x%X,  RC = %d,  RSN = 0x%X\n", zisRC,
            zisStatus.nmiReturnValue,
            zisStatus.nmiReturnCode,
            zisStatus.nmiReasonCode);
    zowedump(NULL, loggingId, ZOWE_LOG_DEBUG3,
            (char*)nmiBuffer, bufferLength);

    if (zisRC != RC_ZIS_SRVC_OK) {

      bool isNWMError =
          (zisRC == RC_ZIS_SRVC_SERVICE_FAILED) &&
          (zisStatus.baseStatus.serviceRC == RC_ZIS_NWMSRV_NWM_FAILED);

      bool isNotEnoughSpace = (zisStatus.nmiReturnValue == -1) &&
                              (zisStatus.nmiReturnCode == NOT_ENOUGH_SPACE);

      if (isNWMError && isNotEnoughSpace){
        int oldBufferLength = bufferLength;
        bufferLength = nmiBuffer->header.NWMBytesNeeded + 0x1000;

        zowelog(NULL, loggingId, ZOWE_LOG_DEBUG2,
                "NWM retry with more space 0x%x\n", bufferLength);
        zowedump(NULL, loggingId, ZOWE_LOG_DEBUG2,
                (char*)nmiBuffer, 0x100);

        safeFree((char *)nmiBuffer, oldBufferLength);
        nmiBuffer = NULL;
        *bufferResponseLength = 0;

        continue;
      } else {
        /* either ZIS failed or NWM returned an unrecoverable error */
        zowelog(NULL, loggingId, ZOWE_LOG_WARNING,
            "ZIS NWM Request Type = %d, RC = %d, NWM RV = 0x%X,  RC = %d,  RSN = 0x%X\n", nwmRequestType, zisRC,
            zisStatus.nmiReturnValue,
            zisStatus.nmiReturnCode,
            zisStatus.nmiReasonCode);

        safeFree((char *)nmiBuffer, bufferLength);
        nmiBuffer = NULL;
        *bufferResponseLength = 0;
        return NULL; 
      }
    } else {
      return nmiBuffer;
    }
  } 
  return NULL; // this statement should never be reached;
}

int findTrimmedLength(char *str){
    for (int i = 0; i < 8; i++){
      if (str[i] == ' '){
        return i;
        }
    }
  return 8;
}

extractIPaddressAndPort(struct sockaddr_in *src_addr4,
                        struct sockaddr_in6 *src_addr6,
                        char *dest_address, unsigned short *dest_port) {

  if (src_addr4->sin_family == AF_INET) { // IPV4
    inet_ntop(AF_INET, &src_addr4->sin_addr, dest_address, INET6_ADDRSTRLEN);
    *dest_port = src_addr4->sin_port;
  }
  else { // IPV6
    inet_ntop(AF_INET6, &src_addr6->sin6_addr, dest_address, INET6_ADDRSTRLEN);
    *dest_port = src_addr6->sin6_port;
  }
}

char * convertTcpState(int stateCode) {
  switch(stateCode) {
    case 1:
      return "Closed";
    case 2:
      return "Listen";
    case 3:
      return "Syn-sent";
    case 4:
      return "Syn-received";
    case 5:
      return "Established";
    case 6:
      return "Fin-wait-1";
    case 7:
      return "Fin-wait-2";
    case 8:
      return "Close-wait";
    case 9:
      return "Last-ACK";
    case 10:
      return "Closing";
    case 11:
      return "Time-wait";
    case 12:
      return "Delete-TCB";
    default:
      return "Unknown";
  }
}

char * convertUInt64ToString(unsigned long long stck, char * uint64Buffer) {
  sprintf(uint64Buffer, "%llu", stck);
  return uint64Buffer;
}

int processAndRespondConnections(HttpResponse *response, CrossMemoryServerName *privilegedServerName,
                                char *tcpip) {
  int i;
  void *collectionPointer;
  NWMConnEntry *entryPointer;
  unsigned char *family;
  char localAddress[INET6_ADDRSTRLEN], remoteAddress[INET6_ADDRSTRLEN];
  char uint64Buffer[21];
  unsigned short localPort, remotePort;
  NMIBufferType *respBuffer = NULL; // Make sure the memory pointed by the pointer is released.
  int rbl = 0;       // response buffer length; used for safeFree function

  respBuffer = buildAndExecuteNWMService(&rbl, privilegedServerName, strupcase(tcpip), NWMTCPCONNTYPE);
  if (respBuffer == NULL) {
    respondWithJsonError(response, "Check zssServer log for more details", 500, "Internal Server Error");
    return 0;
  }

  unsigned int dataOffset = respBuffer->header.NWMOutputDesc.NWMQOffset;
  unsigned int entryLength = respBuffer->header.NWMOutputDesc.NWMQLength;
  unsigned int totalEntries = respBuffer->header.NWMOutputDesc.NWMQNumber;
  unsigned int filterMatches = respBuffer->header.NWMOutputDesc.NWMQMatch; // not used at this time

  jsonPrinter *p = respondWithJsonPrinter(response);
  setResponseStatus(response, 200, "OK");
  setDefaultJSONRESTHeaders(response);
  writeHeader(response);
  jsonStart(p);
  jsonStartArray(p,"connections");

  for (collectionPointer = (void *)respBuffer + dataOffset, i = 0; i < totalEntries; i++, collectionPointer += entryLength) {

    entryPointer = (NWMConnEntry *) collectionPointer;

    if (entryPointer->NWMConnIdent != NWMTCPCONNIDENTIFIER) { //check eyecatcher "NWMC" for TCP connection response
      zowelog(NULL, loggingId, ZOWE_LOG_DEBUG,
            "NMI TCP Connection response data might be corrupted.\n");
      zowedump(NULL, loggingId, ZOWE_LOG_DEBUG2,
              (char*)collectionPointer - entryLength, 3*entryLength);
      continue;
    }

    extractIPaddressAndPort(&entryPointer->NWMConnLocal.NWMConnLocalAddr4,
                            &entryPointer->NWMConnLocal.NWMConnLocalAddr6,
                            localAddress, &localPort);

    extractIPaddressAndPort(&entryPointer->NWMConnRemote.NWMConnRemoteAddr4,
                            &entryPointer->NWMConnRemote.NWMConnRemoteAddr6,
                            remoteAddress, &remotePort);
    jsonStartObject(p, NULL);
    jsonAddString(p, "localIPaddress",  localAddress);
    jsonAddUInt(p,   "localPort",       localPort);
    jsonAddString(p, "remoteIPaddress", remoteAddress);
    jsonAddUInt(p,   "remotePort",      remotePort);
    jsonAddString(p, "startTime",       convertUInt64ToString(entryPointer->NWMConnStartTime, uint64Buffer));
    jsonAddString(p, "lastActivity",    convertUInt64ToString(entryPointer->NWMConnLastActivity, uint64Buffer));
    jsonAddUInt(p,   "bytesIn",         entryPointer->NWMConnBytesIn);
    jsonAddUInt(p,   "bytesOut",        entryPointer->NWMConnBytesOut);
    jsonAddString(p, "state",           convertTcpState(entryPointer->NWMConnState));
    jsonAddUInt(p,   "asid",            entryPointer->NWMConnAsid);
    jsonAddUInt(p,   "tcb",             entryPointer->NWMConnSubtask);
    jsonAddLimitedString(p, "resourceName", entryPointer->NWMConnResourceName, findTrimmedLength(entryPointer->NWMConnResourceName));
    jsonAddUInt(p,   "resourceID",      entryPointer->NWMConnResourceId);
    jsonEndObject(p);
  }

  jsonEndArray(p);
  jsonEnd(p);

  safeFree((char *)respBuffer, rbl);
  finishResponse(response);

  return 0;
}

int processAndRespondListeners(HttpResponse *response, CrossMemoryServerName *privilegedServerName,
                                char *tcpip) {
  int i;
  void *collectionPointer;
  NWMTCPListenEntry *entryPointer;
  unsigned char *family;
  char localAddress[INET6_ADDRSTRLEN];
  char uint64Buffer[21];
  unsigned short localPort;
  NMIBufferType *respBuffer = NULL; // Make sure the memory pointed by the pointer is released.
  int rbl = 0;       // response buffer length; used for safeFree function

  respBuffer = buildAndExecuteNWMService(&rbl, privilegedServerName, strupcase(tcpip), NWMTCPLISTENTYPE);
  if (respBuffer == NULL) {
    respondWithJsonError(response, "Check zssServer log for more details", 500, "Internal Server Error");
    return 0;
  }

  unsigned int dataOffset = respBuffer->header.NWMOutputDesc.NWMQOffset;
  unsigned int entryLength = respBuffer->header.NWMOutputDesc.NWMQLength;
  unsigned int totalEntries = respBuffer->header.NWMOutputDesc.NWMQNumber;
  unsigned int filterMatches = respBuffer->header.NWMOutputDesc.NWMQMatch; // not used at this time

  jsonPrinter *p = respondWithJsonPrinter(response);
  setResponseStatus(response, 200, "OK");
  setDefaultJSONRESTHeaders(response);
  writeHeader(response);
  jsonStart(p);
  jsonStartArray(p,"listeners");

  for (collectionPointer = (void *)respBuffer + dataOffset, i = 0; i < totalEntries; i++, collectionPointer += entryLength) {

    entryPointer = (NWMTCPListenEntry *) collectionPointer;

    if (entryPointer->NWMTCPLIdent != NWMTCPLISTENIDENTIFIER) { //check eyecatcher "NWMT" for TCP listeners response
      zowelog(NULL, loggingId, ZOWE_LOG_DEBUG,
            "NMI TCP Listener response data might be corrupted.\n");
      zowedump(NULL, loggingId, ZOWE_LOG_DEBUG2,
              (char*)collectionPointer - entryLength, 3*entryLength);
      continue;
    }

    extractIPaddressAndPort(&entryPointer->NWMTCPLLocal.NWMTCPLLocalAddr4,
                            &entryPointer->NWMTCPLLocal.NWMTCPLLocalAddr6,
                            localAddress, &localPort);

    jsonStartObject(p, NULL);
    jsonAddString(p, "localIPaddress",      localAddress);
    jsonAddUInt(p,   "localPort",           localPort);

    entryPointer->NWMTCPLSockOpt6 & NWMTCPLSOCKOPT_V6ONLY ?
    jsonAddBoolean(p, "v6onlySocket", TRUE) :
    jsonAddBoolean(p, "v6onlySocket", FALSE);

    jsonAddString(p, "startTime",           convertUInt64ToString(entryPointer->NWMTCPLStartTime, uint64Buffer));
    jsonAddString(p, "lastActivity",        convertUInt64ToString(entryPointer->NWMTCPLLastActivity, uint64Buffer));
    jsonAddString(p, "lastReject",          convertUInt64ToString(entryPointer->NWMTCPLLastReject, uint64Buffer));
    jsonAddUInt(p,   "connsAccepted",       entryPointer->NWMTCPLAcceptCount);
    jsonAddUInt(p,   "connsDropped",        entryPointer->NWMTCPLExceedBacklog);
    jsonAddUInt(p,   "connsInBacklog",      entryPointer->NWMTCPLCurrBacklog);
    jsonAddUInt(p,   "maxBacklogAllow",     entryPointer->NWMTCPLMaxBacklog);
    jsonAddUInt(p,   "currentConns",        entryPointer->NWMTCPLCurrActive);
    jsonAddUInt(p,   "estabConnsInBacklog", entryPointer->NWMTCPLEstabBacklog);
    jsonAddUInt(p,   "asid",                entryPointer->NWMTCPLAsid);
    jsonAddUInt(p,   "tcb",                 entryPointer->NWMTCPLSubtask);
    jsonAddLimitedString(p, "resourceName", entryPointer->NWMTCPLResourceName, findTrimmedLength(entryPointer->NWMTCPLResourceName));
    jsonAddUInt(p,   "resourceID",          entryPointer->NWMTCPLResourceID);
    jsonEndObject(p);
  }

  jsonEndArray(p);
  jsonEnd(p);

  safeFree((char *)respBuffer, rbl);
  finishResponse(response);

  return 0;
}

NWMRecHeader *getFirstNWMRHeader(NMIBufferType *respBuffer, int *NWMRHeaderCount) {
  NWMRecHeader *recHeader;
  void *buffPointer;

  // Navigate to the first NWMRecHeader (NWMR)
  buffPointer = (void *)respBuffer + respBuffer->header.NWMOutputDesc.NWMQOffset;
  recHeader = (NWMRecHeader *) buffPointer;
  // validity check
  if (recHeader->NWMRecHdrIdent != NWMRECHDRIDENTIFIER) {
    zowelog(NULL, loggingId, ZOWE_LOG_DEBUG,
            "NWMR header is invalid.\n");
    return NULL;
  } else {
    *NWMRHeaderCount = respBuffer->header.NWMOutputDesc.NWMQNumber;
    return recHeader;
  }
}

void *locateProfileDataSection(NMIBufferType *respBuffer, int sectionDescIndex, int *sectionEntryCount) {

  int NWMRHeaderCount;   // Should be always 1 for the Profile request type
  NWMRecHeader *recHeader;
  NWMTriplet *sectionTriplet;

  // Get the NWMRecHeader (NWMR)
  recHeader = getFirstNWMRHeader(respBuffer, &NWMRHeaderCount);
  // validity check
  if (recHeader == NULL || recHeader->NWMRecNumber != NWMRECNUMPROFILE) {
    zowelog(NULL, loggingId, ZOWE_LOG_DEBUG,
            "NMI TCPIP profile response is invalid.\n");
    return NULL;
  }
  // locate triplet of a desired section
  sectionTriplet = (NWMTriplet *) ((void *)recHeader + sizeof(NWMRecHeader) + sectionDescIndex * sizeof(NWMTriplet));
  // set a number of sections and return a pointer to the beginning of the first section
  *sectionEntryCount = sectionTriplet->NWMTNumber;
  return (void *)recHeader + sectionTriplet->NWMTOffset;
}

// if IPv6 is enabled then IPv6 loopback interface always exists
int existsIPv6LoobpackInterface(NWMRecHeader *ifNWMRHeader, int ifsEntryCount) {
  int i;
  void *iterationPointer;
  NWMTriplet *ifSectionTriplet;
  NWMRecHeader *currentIfNWMRHeader;
  NWMIfEntry *interfaceSection;

  iterationPointer = (void *)ifNWMRHeader;

  for (i = 0; i < ifsEntryCount; i++) {
    currentIfNWMRHeader = (NWMRecHeader *) iterationPointer;

    ifSectionTriplet = (NWMTriplet *)(iterationPointer + sizeof(NWMRecHeader));
    interfaceSection = (NWMIfEntry *)(iterationPointer + ifSectionTriplet->NWMTOffset);

    if (interfaceSection->NWMIfIdent == NWMIFIDENTIFIER &&
        interfaceSection->NWMIfFlags & NWMIFIPV6 &&
        interfaceSection->NWMIfType == NWMIFTLOOPB ) {
      return TRUE;
    }
    iterationPointer += currentIfNWMRHeader->NWMRecLength;
  }
  return FALSE;
}

int processAndRespondInfo(HttpResponse *response, CrossMemoryServerName *privilegedServerName,
                                char *tcpip) {
  char uint64Buffer[21];
  int commonEntryCount, ifNWMRHeaderCount;
  NMTP_PICommon *commonSection;      // pointer to first common section
  NWMRecHeader *firstIfNWMRHeader;   // pointer to first NWMR interface section
  NMIBufferType *respBufProf = NULL; // Make sure the memory pointed by the pointer is released.
  NMIBufferType *respBufIf = NULL;   // Make sure the memory pointed by the pointer is released.
  int rblp = 0, rbli = 0;       // response buffer length; used for safeFree function

  respBufProf = buildAndExecuteNWMService(&rblp, privilegedServerName, strupcase(tcpip), NWMPROFILETYPE);
  if (respBufProf == NULL) {
    respondWithJsonError(response, "Check zssServer log for more details", 500, "Internal Server Error");
    return 0;
  }
  respBufIf = buildAndExecuteNWMService(&rbli, privilegedServerName, strupcase(tcpip), NWMIFSTYPE);
  if (respBufIf == NULL) {
    safeFree((char *)respBufProf, rblp);
    respondWithJsonError(response, "Check zssServer log for more details", 500, "Internal Server Error");
    return 0;
  }

  commonSection = (NMTP_PICommon *) locateProfileDataSection(respBufProf, NWMP_SEC_PICO, &commonEntryCount);
  if (commonSection == NULL || commonSection->NMTP_PICOEye != NMTP_PICOEYEC) {
    safeFree((char *)respBufProf, rblp);
    safeFree((char *)respBufIf, rbli);
    respondWithJsonError(response, "Check zssServer log for more details", 500, "Internal Server Error");
    return 0;
  }

  firstIfNWMRHeader = getFirstNWMRHeader(respBufIf, &ifNWMRHeaderCount);
  if (firstIfNWMRHeader == NULL) {
    safeFree((char *)respBufProf, rblp);
    safeFree((char *)respBufIf, rbli);
    respondWithJsonError(response, "Check zssServer log for more details", 500, "Internal Server Error");
    return 0;
  }

  jsonPrinter *p = respondWithJsonPrinter(response);
  setResponseStatus(response, 200, "OK");
  setDefaultJSONRESTHeaders(response);
  writeHeader(response);
  jsonStart(p);
  jsonStartObject(p, "info");

  jsonAddString(p, "stackStartTime", convertUInt64ToString(*((NWM_ull *)commonSection->NMTP_PICOStartTime), uint64Buffer));

  existsIPv6LoobpackInterface(firstIfNWMRHeader, ifNWMRHeaderCount) ?
  jsonAddBoolean(p, "IPv6Enabled", TRUE) : jsonAddBoolean(p, "IPv6Enabled", FALSE);

  jsonEndObject(p);
  jsonEnd(p);

  safeFree((char *)respBufProf, rblp);
  safeFree((char *)respBufIf, rbli);

  finishResponse(response);

  return 0;
}

int processAndRespondPorts(HttpResponse *response, CrossMemoryServerName *privilegedServerName,
                                char *tcpip) {
  int i;
  void *collectionPointer;
  NMTP_PORT *portSection;
  int portEntryCount;
  NMIBufferType *respBuffer = NULL; // Make sure the memory pointed by the pointer is released.
  int rbl = 0;       // response buffer length; used for safeFree function
  char localAddress[INET6_ADDRSTRLEN];
  unsigned short localPort;

  respBuffer = buildAndExecuteNWMService(&rbl, privilegedServerName, strupcase(tcpip), NWMPROFILETYPE);
  if (respBuffer == NULL) {
    respondWithJsonError(response, "Check zssServer log for more details", 500, "Internal Server Error");
    return 0;
  }

  portSection = (NMTP_PORT *) locateProfileDataSection(respBuffer, NWMP_SEC_PORT, &portEntryCount);
  if (portSection == NULL || portSection->NMTP_PORTEye != NMTP_PORTEYEC) {
    safeFree((char *)respBuffer, rbl);
    respondWithJsonError(response, "Check zssServer log for more details", 500, "Internal Server Error");
    return 0;
  }

  jsonPrinter *p = respondWithJsonPrinter(response);
  setResponseStatus(response, 200, "OK");
  setDefaultJSONRESTHeaders(response);
  writeHeader(response);
  jsonStart(p);
  jsonStartArray(p,"ports");

  for (i = 0; i < portEntryCount; i++, portSection++ ) {

    if (portSection->NMTP_PORTEye != NMTP_PORTEYEC) { //check eyecatcher "NWMC" for TCP connection response
      zowelog(NULL, loggingId, ZOWE_LOG_DEBUG,
            "NMI Profile Port response data might be corrupted.\n");
      zowedump(NULL, loggingId, ZOWE_LOG_DEBUG,
              (char*)portSection - sizeof(NMTP_PORT), 3*sizeof(NMTP_PORT));
      continue;
    }

    jsonStartObject(p, NULL);

    jsonStartObject(p, "flags");
    portSection->NMTP_PORTFlags & NMTP_PORTIPV6
      ? jsonAddBoolean(p, "IPV6", TRUE)
      : jsonAddBoolean(p, "IPV6", FALSE);
    portSection->NMTP_PORTFlags & NMTP_PORTRANGE
      ? jsonAddBoolean(p, "RANGE", TRUE)
      : jsonAddBoolean(p, "RANGE", FALSE);
    portSection->NMTP_PORTFlags & NMTP_PORTUNRSV
      ? jsonAddBoolean(p, "UNRSV", TRUE)
      : jsonAddBoolean(p, "UNRSV", FALSE);
    portSection->NMTP_PORTFlags & NMTP_PORTTCP
      ? jsonAddBoolean(p, "TCP", TRUE)
      : jsonAddBoolean(p, "TCP", FALSE);
    jsonEndObject(p);

    jsonStartObject(p, "useType");
    if (portSection->NMTP_PORTUseType == NMTP_PORTUTRESERVED) {
      jsonAddBoolean(p, "RESERVED", TRUE);
    } else {
      jsonAddBoolean(p, "RESERVED", FALSE);
    }
    if (portSection->NMTP_PORTUseType == NMTP_PORTUTAUTHPORT) {
      jsonAddBoolean(p, "AUTHPORT", TRUE);
    } else {
      jsonAddBoolean(p, "AUTHPORT", FALSE);
    }
    if (portSection->NMTP_PORTUseType == NMTP_PORTUTJOBNAME) {
      jsonAddBoolean(p, "JOBNAME", TRUE);
    } else {
      jsonAddBoolean(p, "JOBNAME", FALSE);
    }
    jsonEndObject(p);

    jsonStartObject(p, "rsvOptions");
    portSection->NMTP_PORTRsvOptions & NMTP_PORTRAUTOLOG
      ? jsonAddBoolean(p, "AUTOLOG", TRUE)
      : jsonAddBoolean(p, "AUTOLOG", FALSE);
    portSection->NMTP_PORTRsvOptions & NMTP_PORTRDELAYACKS
      ? jsonAddBoolean(p, "DELAYACKS", TRUE)
      : jsonAddBoolean(p, "DELAYACKS", FALSE);
    portSection->NMTP_PORTRsvOptions & NMTP_PORTRSHAREPORT
      ? jsonAddBoolean(p, "SHAREPORT", TRUE)
      : jsonAddBoolean(p, "SHAREPORT", FALSE);
    portSection->NMTP_PORTRsvOptions & NMTP_PORTRSHAREPORTWLM
      ? jsonAddBoolean(p, "SHAREPORTWLM", TRUE)
      : jsonAddBoolean(p, "SHAREPORTWLM", FALSE);
    portSection->NMTP_PORTRsvOptions & NMTP_PORTRBIND
      ? jsonAddBoolean(p, "BIND", TRUE)
      : jsonAddBoolean(p, "BIND", FALSE);
    portSection->NMTP_PORTRsvOptions & NMTP_PORTRSAF
      ? jsonAddBoolean(p, "SAF", TRUE)
      : jsonAddBoolean(p, "SAF", FALSE);
    portSection->NMTP_PORTRsvOptions & NMTP_PORTRNOSMC
      ? jsonAddBoolean(p, "NOSMC", TRUE)
      : jsonAddBoolean(p, "NOSMC", FALSE);
    portSection->NMTP_PORTRsvOptions & NMTP_PORTRNOSMCR
      ? jsonAddBoolean(p, "NOSMCR", TRUE)
      : jsonAddBoolean(p, "NOSMCR", FALSE);
    jsonEndObject(p);

    jsonStartObject(p, "unrsvOptions");
    portSection->NMTP_PORTUnrsvOptions & NMTP_PORTUDENY
      ? jsonAddBoolean(p, "DENY", TRUE)
      : jsonAddBoolean(p, "DENY", FALSE);
    portSection->NMTP_PORTUnrsvOptions & NMTP_PORTUSAF
      ? jsonAddBoolean(p, "SAF", TRUE)
      : jsonAddBoolean(p, "SAF", FALSE);
    portSection->NMTP_PORTUnrsvOptions & NMTP_PORTUWHENLISTEN
      ? jsonAddBoolean(p, "WHENLISTEN", TRUE)
      : jsonAddBoolean(p, "WHENLISTEN", FALSE);
    portSection->NMTP_PORTUnrsvOptions & NMTP_PORTUWHENBIND
      ? jsonAddBoolean(p, "WHENBIND", TRUE)
      : jsonAddBoolean(p, "WHENBIND", FALSE);
    jsonEndObject(p);

    jsonAddUInt(p,   "portNumber",    portSection->NMTP_PORTBegNum);
    jsonAddUInt(p,   "portNumberEnd", portSection->NMTP_PORTEndNum);

    jsonAddLimitedString(p, "jobname",     portSection->NMTP_PORTJobName, findTrimmedLength(portSection->NMTP_PORTJobName));
    jsonAddLimitedString(p, "safname",     portSection->NMTP_PORTSafName, findTrimmedLength(portSection->NMTP_PORTSafName));

    if(portSection->NMTP_PORTRsvOptions & NMTP_PORTRBIND){
      if(portSection->NMTP_PORTFlags & NMTP_PORTIPV6){
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &portSection->NMTP_PORTBindAddr.NMTP_PORTBindAddr6, str, INET6_ADDRSTRLEN);
        jsonAddString(p, "bindAddr", str);
      } else {
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &portSection->NMTP_PORTBindAddr.NMTP_PORTBindAddr4, str, INET_ADDRSTRLEN);
        jsonAddString(p, "bindAddr", str);
      }
    } else {
      jsonAddString(p, "bindAddr",     "");
    }

    jsonEndObject(p);
  }

  jsonEndArray(p);
  jsonEnd(p); 

  safeFree((char *)respBuffer, rbl);
  finishResponse(response);

  return 0;
}

/* High-level function to serve HTTP requests */
static int serveMappingService(HttpService *service, HttpResponse *response) {
  CrossMemoryServerName *privilegedServerName;

  HttpRequest *request = response->request;
  char *tcpip = stringListPrint(request->parsedFile, service->parsedMaskPartCount, 1, "/", 0);        // extract TCPIP name from the HTTP request
  char *requestType = stringListPrint(request->parsedFile, service->parsedMaskPartCount + 1, 1, "/", 0);  // extract NWM request type from the HTTP request

  zowelog(NULL, loggingId, ZOWE_LOG_DEBUG,
          "Selected TCPIP stack is %s\n", tcpip);

  zowelog(NULL, loggingId, ZOWE_LOG_DEBUG,
          "The request type is: %s\n", requestType);

  // Validate tcpip parameter
  if (strlen(tcpip) > 8) {
    respondWithJsonError(response, "Tcpip name is too long", 400, "Bad Request");
    return 0;
  }
  // Get Zis server name
  privilegedServerName = getConfiguredProperty(service->server,
      HTTP_SERVER_PRIVILEGED_SERVER_PROPERTY);

  // Handle HTTP methods
  if (strcasecmp(request->method, methodGET) == 0) {
    // Process "connections" request type
    if (strcasecmp("connections", requestType) == 0) {
      processAndRespondConnections(response, privilegedServerName, strupcase(tcpip));
    } 
    // Process "connections" request type
    else if (strcasecmp("ports", requestType) == 0) {
      processAndRespondPorts(response, privilegedServerName, strupcase(tcpip));
    }
    // Process "listeners" request type
    else if (strcasecmp("listeners", requestType) == 0) {
      processAndRespondListeners(response, privilegedServerName, strupcase(tcpip));
    }
    // Process "info" request type
    else if (strcasecmp("info", requestType) == 0) {
      processAndRespondInfo(response, privilegedServerName, strupcase(tcpip));
    }
    else {
      respondWithJsonError(response, "Endpoint not found.", 404, "Not Found");
      return 0; 
    }   
  }
  else {
    jsonPrinter *p = respondWithJsonPrinter(response);
      
    setResponseStatus(response, 405, "Method Not Allowed");
    setDefaultJSONRESTHeaders(response);
    addStringHeader(response, "Allow", "GET");
    writeHeader(response);
    
    jsonStart(p);
    {
      jsonAddString(p, "error", "Only GET requests are supported");
    }
    jsonEnd(p); 
    finishResponse(response);
  }
  return 0;
}


void ipExplorerDataServiceInstaller(DataService *dataService, HttpServer *server)
{
  HttpService *httpService = makeHttpDataService(dataService, server);
  httpService->authType = SERVICE_AUTH_NATIVE_WITH_SESSION_TOKEN;
  httpService->serviceFunction = serveMappingService;
  httpService->runInSubtask = TRUE;
  httpService->doImpersonation = FALSE;

  loggingId = dataService->loggingIdentifier;
}

/*
  This program and the accompanying materials are
  made available under the terms of the Eclipse Public License v2.0 which accompanies
  this distribution, and is available at https://www.eclipse.org/legal/epl-v20.html
  
  SPDX-License-Identifier: EPL-2.0
  
  Copyright Contributors to the Zowe Project.
*/

