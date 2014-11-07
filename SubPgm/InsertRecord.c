//=============================================================================
// InsertRecord - подпрограмма добавления записи в контейнер
//=============================================================================
void InsertRecord(int i, short j)
{
  ULONG  cbRecordData;
  static PUSERRECORD pUserRecord;
  static RECORDINSERT recordInsert;

  cbRecordData = (LONG) (sizeof(USERRECORD) - sizeof(RECORDCORE));
  pUserRecord = WinSendMsg(hwndCntnr, CM_ALLOCRECORD,
                           MPFROMLONG(cbRecordData), MPFROMSHORT(L1));

  pUserRecord->recordCore.cb       = sizeof(RECORDCORE);
  pUserRecord->recordCore.pszText  = (PSZ)IPfirst+IPLEN*i;
  pUserRecord->recordCore.pszIcon  = (PSZ)IPfirst+IPLEN*i;
  pUserRecord->recordCore.pszName  = (PSZ)IPfirst+IPLEN*i;
  pUserRecord->recordCore.hptrIcon = hIcon;

#ifndef VIEW_LS
  pUserRecord->Status     = (PSZ)TxtExist+StatusIP[i];
#endif
  pUserRecord->IPaddress  = (PSZ)IPfirst+IPLEN*i;
  pUserRecord->MACaddress = (PSZ)MACfirst+MACLEN*i;
  pUserRecord->FQDName    = (PSZ)FQDNfirst+FQDNLEN*i;
  pUserRecord->CompName   = (PSZ)CompNfirst+COMPNLEN*j+L7;
  pUserRecord->NBname     = (PSZ)NETBNfirst+UNCLEN*i;

  recordInsert.cb                = sizeof(RECORDINSERT);
  recordInsert.pRecordParent     = NULL;
  recordInsert.pRecordOrder      = (PRECORDCORE)CMA_END;
  recordInsert.zOrder            = CMA_TOP;
  recordInsert.cRecordsInsert    = L1;
  recordInsert.fInvalidateRecord = TRUE;

  WinPostMsg(hwndCntnr, CM_INSERTRECORD,
             (PRECORDCORE)pUserRecord, &recordInsert);
}
