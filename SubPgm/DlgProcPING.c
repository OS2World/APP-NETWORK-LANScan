//=============================================================================
// DlgProcPING - window procedure for the PING dialog
//=============================================================================
MRESULT EXPENTRY DlgProcPING (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
{
int i;
char OutText[L16], InAddr1[L16], InAddr2[L16];
static char mNBactP;

  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      mNBactP = NBactP;
      WinCheckButton(hwndDlg, NETB_P, mNBactP);

      for ( i=EFS_1; i<=EFP_8; i++)
        WinSendDlgItemMsg(hwndDlg, i, EM_SETTEXTLIMIT, (MPARAM)L15, L0);
      for ( i=0; i<NumPing; i++)
        {
        sprintf( OutText, "%s", inet_ntoa(*(struct in_addr *)&PingStart[i]) );
        WinSetDlgItemText(hwndDlg, EFS_1+i*L2, OutText);
        sprintf( OutText, "%s", inet_ntoa(*(struct in_addr *)&PingStop[i]) );
        WinSetDlgItemText(hwndDlg, EFS_1+i*L2+L1, OutText);
        }
      break;
      }
//-----------------------------------------------------------------------------
// Handle WM_CONTROL
//-----------------------------------------------------------------------------
    case WM_CONTROL:
      {
      switch(SHORT1FROMMP(mp1))
        {
        case NETB_P:
          {
          mNBactP = WinQueryButtonCheckstate(hwndDlg, NETB_P);
          break;
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
        case DID_OK:
          {
          NumPing = L0;
          for ( i=L0; i<MAXIPADR; i++) PingStart[i] = PingStop[i] = L0;

          for ( i=EFS_1; i<=EFS_8; i+=L2)
            {
            if ( WinQueryDlgItemTextLength(hwndDlg, i) == L0 ) continue;
            if ( WinQueryDlgItemTextLength(hwndDlg, i+1) == L0 ) continue;
            WinQueryDlgItemText(hwndDlg, i, L16, InAddr1);
            WinQueryDlgItemText(hwndDlg, i+1, L16, InAddr2);
            TestPing(InAddr1, InAddr2);
            }

          NBactP = mNBactP;
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
