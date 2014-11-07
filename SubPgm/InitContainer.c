//=============================================================================
// InitContainer - подпрограмма инициализации контейнера
//=============================================================================
void InitContainer(BOOL NBparm)
{
  static CNRINFO cnrinfo;
  static PFIELDINFO pFieldInfo, firstFieldInfo;
  static FIELDINFOINSERT fieldInfoInsert;
  static PFIELDINFOINSERT pFieldInfoInsert;
#ifndef VIEW_LS
  static char pszColumnText1[]= "St.";
#endif
  static char pszColumnText2[]= "IP address";
  static char pszColumnText3[]= "Host name";
  static char pszColumnText4[]= "MAC address";
  static char pszColumnText5[]= "Manufacturer";
  static char pszColumnText6[]= "SMB name";
  u_long MsgFlg = CMA_FLWINDOWATTR | CMA_CNRTITLE;
  long NumCol;

  cnrinfo.pszCnrTitle = pszCnrTitle;
  cnrinfo.flWindowAttr = CV_DETAIL | CA_CONTAINERTITLE |
                         CA_TITLESEPARATOR | CA_DETAILSVIEWTITLES;
#ifndef VIEW_LS
  if (NBparm) NumCol = L6;
  else NumCol= L5;
#else
  if (NBparm) NumCol = L5;
  else NumCol= L4;
#endif

  pFieldInfo=WinSendMsg(hwndCntnr, CM_ALLOCDETAILFIELDINFO,
                        MPFROMLONG(NumCol), NULL);
  firstFieldInfo = pFieldInfo;

#ifndef VIEW_LS
  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_CENTER|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText1;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD, Status);
  pFieldInfo = pFieldInfo->pNextFieldInfo;
#endif

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_LEFT|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_LEFT;
  pFieldInfo->pTitleData = (PVOID) pszColumnText2;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD, IPaddress);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_LEFT|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_LEFT;
  pFieldInfo->pTitleData = (PVOID) pszColumnText3;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD, FQDName);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_LEFT|CFA_SEPARATOR;
  pFieldInfo->flTitle = CFA_CENTER;
  pFieldInfo->pTitleData = (PVOID) pszColumnText4;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD, MACaddress);
  pFieldInfo = pFieldInfo->pNextFieldInfo;

  pFieldInfo->cb = sizeof(FIELDINFO);
  pFieldInfo->flTitle = CFA_LEFT;
  pFieldInfo->pTitleData = (PVOID) pszColumnText5;
  pFieldInfo->offStruct = FIELDOFFSET(USERRECORD, CompName);

  if ( NBparm )
    {
    pFieldInfo->flData = CFA_STRING|CFA_HORZSEPARATOR|CFA_LEFT|CFA_SEPARATOR;

    cnrinfo.pFieldInfoLast = pFieldInfo;
    if ( VertSplitBar < L1 ) VertSplitBar = L198;
    cnrinfo.xVertSplitbar = VertSplitBar;
    MsgFlg |= CMA_PFIELDINFOLAST | CMA_XVERTSPLITBAR;

    pFieldInfo = pFieldInfo->pNextFieldInfo;

    pFieldInfo->cb = sizeof(FIELDINFO);
    pFieldInfo->flData = CFA_STRING | CFA_HORZSEPARATOR | CFA_LEFT;
    pFieldInfo->flTitle = CFA_LEFT;
    pFieldInfo->pTitleData = (PVOID) pszColumnText6;
    pFieldInfo->offStruct = FIELDOFFSET(USERRECORD, NBname);
    }
  else
    {
    pFieldInfo->flData = CFA_STRING | CFA_HORZSEPARATOR | CFA_LEFT;
    }

  cnrinfo.cFields = NumCol;
  fieldInfoInsert.cFieldInfoInsert = NumCol;

  fieldInfoInsert.cb = (ULONG)(sizeof(FIELDINFOINSERT));
  fieldInfoInsert.pFieldInfoOrder = (PFIELDINFO)CMA_FIRST;
  fieldInfoInsert.fInvalidateFieldInfo = TRUE;

  pFieldInfoInsert = &fieldInfoInsert;

  WinPostMsg(hwndCntnr, CM_INSERTDETAILFIELDINFO,
             MPFROMP(firstFieldInfo), MPFROMP(pFieldInfoInsert));

  WinPostMsg(hwndCntnr, CM_SETCNRINFO, &cnrinfo, MPFROMLONG(MsgFlg));
}
