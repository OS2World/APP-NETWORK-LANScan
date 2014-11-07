//=============================================================================
// DlgProcOPT - window procedure for the Options dialog
//=============================================================================
MRESULT EXPENTRY DlgProcOPT (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
{
int i;
static char mAutoRun, mAutoLog, mCommonLog, museDNS, museOTHD;
static unsigned int mInterval, mArpWait, mTcpWait, mBaseInd, mI;
static long mtv_sec;
static char *BaseTxt[3] = { "previous LanScan result",
                            "LanScan.Map file",
                            "ARP cache" };
static char *BaseArun[12] = {  "5", "10", "15", "20", "25", "30",
                              "35", "40", "45", "50", "55", "60" };
static char *BasePing[10] = { "1","2","3","4","5","6","7","8","9","10" };
static char *BaseTOTCP[10] = { "10", "20", "30", "40",  "50",
                               "60", "70", "80", "90", "100" };
static char *BARP[10] = { "3","6","9","12","15","30","45","60","75","90" };
static char *BaseLog[2] = { "common","separate" };

  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      mAutoRun = AutoRun;
      mAutoLog = AutoLog;
      mCommonLog = CommonLog;
      mInterval = Interval;
      museDNS = useDNS;
      museOTHD = useOTHD;
      mtv_sec = pingtv.tv_sec;
      mArpWait = ArpWait;
      mTcpWait = TcpWait;
      mBaseInd = BaseInd;

      WinCheckButton(hwndDlg, ARUN, mAutoRun);
      WinCheckButton(hwndDlg, USE_LOG, mAutoLog);
      WinCheckButton(hwndDlg, DNS, museDNS);
      WinCheckButton(hwndDlg, OTHD, museOTHD);

      for ( i=L0; i<L2; i++)
        WinInsertLboxItem( WinWindowFromID(hwndDlg,COMBO_ID05),
                           LIT_END, BaseLog[i] );
      mI = ( mCommonLog ) ? L0 : L1;
      WinSetDlgItemText(hwndDlg, COMBO_ID05, BaseLog[mI]);

      for ( i=L0; i<L10; i++)
        WinInsertLboxItem( WinWindowFromID(hwndDlg,COMBO_ID04),
                           LIT_END, BARP[i] );
      mI = ( mArpWait <= L15 ) ? mArpWait/L3-L1 : mArpWait/L15+L3;
      WinSetDlgItemText(hwndDlg, COMBO_ID04, BARP[mI]);

      for ( i=L0; i<L10; i++)
        WinInsertLboxItem( WinWindowFromID(hwndDlg,COMBO_ID03),
                           LIT_END, BaseTOTCP[i] );
      WinSetDlgItemText(hwndDlg, COMBO_ID03, BaseTOTCP[mTcpWait/L10-L1]);

      for ( i=L0; i<L10; i++)
        WinInsertLboxItem( WinWindowFromID(hwndDlg,COMBO_ID02),
                           LIT_END, BasePing[i] );
      WinSetDlgItemText(hwndDlg, COMBO_ID02, BasePing[mtv_sec-L1]);

      for ( i=L0; i<L12; i++)
        WinInsertLboxItem( WinWindowFromID(hwndDlg,COMBO_ID01),
                           LIT_END, BaseArun[i] );
      WinSetDlgItemText(hwndDlg, COMBO_ID01, BaseArun[mInterval/L5-L1]);

      for ( i=L0; i<L3; i++)
        WinInsertLboxItem( WinWindowFromID(hwndDlg,COMBO_ID),
                           LIT_END, BaseTxt[i] );
      WinSetDlgItemText(hwndDlg, COMBO_ID, BaseTxt[mBaseInd]);

      break;
      }
//-----------------------------------------------------------------------------
// Handle WM_CONTROL
//-----------------------------------------------------------------------------
    case WM_CONTROL:
      {
      switch(SHORT1FROMMP(mp1))
        {
        case USE_LOG:
          {
          mAutoLog = WinQueryButtonCheckstate(hwndDlg, USE_LOG);
          return (0);
          }
        case DNS:
          {
          museDNS = WinQueryButtonCheckstate(hwndDlg, DNS);
          return (0);
          }
        case OTHD:
          {
          museOTHD = WinQueryButtonCheckstate(hwndDlg, OTHD);
          return (0);
          }
        case ARUN:
          {
          mAutoRun = WinQueryButtonCheckstate(hwndDlg, ARUN);
          return (0);
          }
        case COMBO_ID05:
          {
          if (SHORT2FROMMP(mp1) == LN_SELECT)
            {
            mI=WinQueryLboxSelectedItem(WinWindowFromID(hwndDlg,COMBO_ID05));
            if ( mI == -1 ) return (L0); // Событие происходит при заполнении
            mCommonLog = ( mI ) ? FALSE : TRUE;
            }
          return (L0);
          }
        case COMBO_ID04:
          {
          if (SHORT2FROMMP(mp1) == LN_SELECT)
            {
            mI=WinQueryLboxSelectedItem(WinWindowFromID(hwndDlg,COMBO_ID04));
            if ( mI == -1 ) return (L0); // Событие происходит при заполнении
            mArpWait = ( mI < L5 ) ? (mI+L1)*L3 : (mI-L3)*L15;
            }
          return (L0);
          }
        case COMBO_ID03:
          {
          if (SHORT2FROMMP(mp1) == LN_SELECT)
            {
            mI=WinQueryLboxSelectedItem(WinWindowFromID(hwndDlg,COMBO_ID03));
            if ( mI == -1 ) return (L0); // Событие происходит при заполнении
            mTcpWait = (mI+L1)*L10;
            }
          return (L0);
          }
        case COMBO_ID02:
          {
          if (SHORT2FROMMP(mp1) == LN_SELECT)
            {
            mI=WinQueryLboxSelectedItem(WinWindowFromID(hwndDlg,COMBO_ID02));
            if ( mI == -1 ) return (L0); // Событие происходит при заполнении
            mtv_sec = mI+L1;
            }
          return (L0);
          }
        case COMBO_ID01:
          {
          if (SHORT2FROMMP(mp1) == LN_SELECT)
            {
            mI=WinQueryLboxSelectedItem(WinWindowFromID(hwndDlg,COMBO_ID01));
            if ( mI == -1 ) return (L0); // Событие происходит при заполнении
            mInterval = (mI+L1)*L5;
            }
          return (L0);
          }
        case COMBO_ID:
          {
          if (SHORT2FROMMP(mp1) == LN_SELECT)
            {
            mI=WinQueryLboxSelectedItem(WinWindowFromID(hwndDlg,COMBO_ID));
            if ( mI == -1 ) return (L0); // Событие происходит при заполнении
            mBaseInd = mI;
            }
          return (L0);
          }
        }
      break;
      }
//-----------------------------------------------------------------------------
// Handle WM_COMMAND
//-----------------------------------------------------------------------------
    case WM_COMMAND:
      {
      switch(SHORT1FROMMP(mp1))
        {
#ifndef CONFIG_LS
        case PB_SAVE_OPT:
          {
          AutoRun = mAutoRun;
          AutoLog = mAutoLog;
          CommonLog = mCommonLog;
          Interval = mInterval;
          useDNS = museDNS;
          useOTHD = museOTHD;
          pingtv.tv_sec = mtv_sec;
          ArpWait = mArpWait;
          TcpWait = mTcpWait;
          BaseInd = mBaseInd;
          SaveOpt(INIname);
          break;
          }
#endif
        case PB_PING:
          {
          WinDlgBox (HWND_DESKTOP, hwndDlg, DlgProcPING,
                     NULLHANDLE, PING_ID, NULL);
          return(L0);
          }
        case PB_ARP:
          {
          WinDlgBox (HWND_DESKTOP, hwndDlg, DlgProcARP,
                     NULLHANDLE, ARP_ID, NULL);
          return(L0);
          }
#ifndef CONFIG_LS
        case PB_FONT:
          {
          GetFontName(FontCntnr);
          return(L0);
          }
#endif
        case DID_OK:
          {
          AutoRun = mAutoRun;
          AutoLog = mAutoLog;
          CommonLog = mCommonLog;
          Interval = mInterval;
          useDNS = museDNS;
          useOTHD = museOTHD;
          pingtv.tv_sec = mtv_sec;
          ArpWait = mArpWait;
          TcpWait = mTcpWait;
          BaseInd = mBaseInd;
#ifdef CONFIG_LS
          SaveOpt(CFGname);
#endif
          break;
          }
        }
      }
      break;
    }
    return (WinDefDlgProc (hwndDlg,msg,mp1,mp2));
}
