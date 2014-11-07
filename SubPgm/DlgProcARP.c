//=============================================================================
// DlgProcARP - window procedure for the ARP dialog
//=============================================================================
MRESULT EXPENTRY DlgProcARP (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
{
int i, j;
static char mNBadrSet, mNBadrM[MAXIPADR], mNBact;
struct in_addr *pIPadr;
struct sockaddr_in TmpSin;
short swt;
char InAddr1[L16], InAddr2[L16];
static char mInt[MAXIPADR];

  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      mNBact = NBact;
      mNBadrSet = NBadrSet;
      memcpy(mNBadrM, NBadrM, sizeof(mNBadrM));

      for ( mNBadrSet=FALSE, i=0; i<MAXIPADR; i++ ) mInt[i] = FALSE;
#ifdef CONFIG_LS
      for ( i=INT_0; i<=INT_7; i++ ) WinEnableControl(hwndDlg, i, FALSE);
#endif
      for ( i=IP_00; i<=IP_07; i++)
        {
        WinSendDlgItemMsg(hwndDlg, i, EM_SETTEXTLIMIT, (MPARAM)L15, 0);
        WinSetDlgItemText(hwndDlg, i, "");
        }
      for ( i=IPS_00_01; i<=IPS_07_03; i++)
        {
        WinSendDlgItemMsg(hwndDlg, i, EM_SETTEXTLIMIT, (MPARAM)L15, 0);
        WinSetDlgItemText(hwndDlg, i, "");
        }
      for ( i=IPP_00_01; i<=IPP_07_03; i++)
        {
        WinSendDlgItemMsg(hwndDlg, i, EM_SETTEXTLIMIT, (MPARAM)L15, 0);
        WinSetDlgItemText(hwndDlg, i, "");
        }

      WinCheckButton(hwndDlg, NETB_N, mNBact);
      for ( i=NETB_0; i<=NETB_7; i++ )
        WinCheckButton(hwndDlg, i, mNBadrM[i-NETB_0]);

      for ( i=0; i<NumIPadr; i++ )
        {
        pIPadr = (struct in_addr *)&AddrInfoIP[i];
        WinSetDlgItemText(hwndDlg, i+IP_00, inet_ntoa(*pIPadr));
        }

      pIPadr = (struct in_addr *)&TmpSin.sin_addr;
      for ( i=0; i<NumIPadr; i++ )
        {
        if ( Interv[i] == 0 ) continue;
        for ( j=0; j<Interv[i]; j++ )
          {
#ifndef CONFIG_LS
          TmpSin.sin_addr.s_addr =  ( AddrInfoIP[i].addr &
                                     htonl(AddrInfoIP[i].mask) ) |
                                     htonl(HostInt[i].start[j]);
#else
          TmpSin.sin_addr.s_addr = htonl(HostInt[i].start[j]);
#endif
          WinSetDlgItemText(hwndDlg, i*3+IPS_00_01+j, inet_ntoa(*pIPadr));
#ifndef CONFIG_LS
          TmpSin.sin_addr.s_addr = ( AddrInfoIP[i].addr &
                                     htonl(AddrInfoIP[i].mask) ) |
                                     htonl(HostInt[i].stop[j]);
#else
          TmpSin.sin_addr.s_addr = htonl(HostInt[i].stop[j]);
#endif
          WinSetDlgItemText(hwndDlg, i*3+IPP_00_01+j, inet_ntoa(*pIPadr));
          }
        }

      break;
      }
//-----------------------------------------------------------------------------
// Handle WM_CONTROL
//-----------------------------------------------------------------------------
    case WM_CONTROL:
      {
      swt = SHORT1FROMMP(mp1);
      switch(SHORT1FROMMP(mp1))
        {
        case NETB_N:
          {
          mNBact = WinQueryButtonCheckstate(hwndDlg, NETB_N);
          return (0);
          }
        case NETB_0:
        case NETB_1:
        case NETB_2:
        case NETB_3:
        case NETB_4:
        case NETB_5:
        case NETB_6:
        case NETB_7:
          {
          mNBadrM[swt-NETB_0] = WinQueryButtonCheckstate(hwndDlg, swt);
          return (0);
          }
#ifndef CONFIG_LS
        case INT_0:
        case INT_1:
        case INT_2:
        case INT_3:
        case INT_4:
        case INT_5:
        case INT_6:
        case INT_7:
          {
          mInt[swt-INT_0] = WinQueryButtonCheckstate(hwndDlg, swt);
          return (0);
          }
#endif
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
          NumIPadr = 0;
          for ( i=0; i<MAXIPADR; i++ ) Interv[i] = 0;

          for ( i=IP_00; i<=IP_07; i++)
            {
            if ( WinQueryDlgItemTextLength(hwndDlg, i) == L0 ) continue;
            WinQueryDlgItemText(hwndDlg, i, L16, InAddr1);

            sin[NumIPadr].sin_family = AF_INET;
            if ( (sin[NumIPadr].sin_addr.s_addr=inet_addr(InAddr1)) == -1 )
              continue;
#ifndef CONFIG_LS
            if ( !TestAddr(NumIPadr) )
              continue;
#else
            AddrInfoIP[NumIPadr].addr=sin[NumIPadr].sin_addr.s_addr;
#endif
            NumIPadr++;

            for ( j=IPS_00_01+(i-IP_00)*3; j<=IPS_00_03+(i-IP_00)*3; j++)
              {
              if ( WinQueryDlgItemTextLength(hwndDlg, j) == L0 ) continue;
              if (WinQueryDlgItemTextLength(hwndDlg,j+IPP_00_01-IPS_00_01)==L0)
                continue;
              WinQueryDlgItemText(hwndDlg, j, L16, InAddr1);
              WinQueryDlgItemText( hwndDlg,j+IPP_00_01-IPS_00_01,L16,InAddr2 );
              TestInt(InAddr1, InAddr2, NumIPadr);
              }
            }
#ifndef CONFIG_LS
          for ( i=0; i<MAXIPADR; i++ )
            if ( mInt[i] ) GetIPaddr(i);
#endif

          for ( mNBadrSet=FALSE, i=0; i<MAXIPADR; i++ )
            if ( mNBadrM[i] ) mNBadrSet = TRUE;

          NBact = mNBact;
#ifndef CONFIG_LS
          if ( !mNBact ) NBresult = FALSE;
#endif
          NBadrSet = mNBadrSet;
          memcpy(NBadrM, mNBadrM, sizeof(mNBadrM));

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
