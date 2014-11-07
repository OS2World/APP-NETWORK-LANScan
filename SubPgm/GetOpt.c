//=============================================================================
// GetOpt - подпрограмма чтения параметров из INI-файла
//=============================================================================
void GetOpt (char *INIname)
{
#ifndef CONFIG_LS
char *pBfr;
#endif
//-----------------------------------------------------------------------------
// Copy the Window position info from a private INI into OS2.INI
//-----------------------------------------------------------------------------
  hini = PrfOpenProfile(hab, INIname); // Open private profile
  if ( hini )
    {
#ifndef CONFIG_LS
    if ( PrfQueryProfileSize(hini, APPNAME, WINPOS, &ulSize) )
      {
      pBfr = calloc(ulSize, L1);
      PrfQueryProfileData(hini, APPNAME, WINPOS, pBfr, &ulSize);
      PrfWriteProfileData(HINI_USERPROFILE, APPNAME, WINPOS, pBfr, ulSize);
      free(pBfr);
      }
#endif
//-----------------------------------------------------------------------------
// Restore Options from INI file
//-----------------------------------------------------------------------------
    GetParm(AUTORUN, AutoRun);
    GetParm(AUTOLOG, AutoLog);
    GetParm(COMMONLOG, CommonLog);
    GetParm(INTERVAL, Interval);
    GetParm(BASEIND, BaseInd);
    GetParm(USEDNS, useDNS);
    GetParm(USEOTHD, useOTHD);
    GetParm(PINGTO, pingtv.tv_sec);
    GetParm(ARPTO, ArpWait);
    GetParm(TCPTO, TcpWait);
    GetParm(NUMPING, NumPing);
    GetParm(PINGSTART, PingStart);
    GetParm(PINGSTOP, PingStop);
    GetParm(NBACT, NBact);
    GetParm(NBACTP, NBactP);
    GetParm(NBADRSET, NBadrSet);
    GetParm(NBADRM, NBadrM);
#ifdef CONFIG_LS
    GetParm(NUMIPADR, NumIPadr);
    GetParm(ADDRINFO, AddrInfoIP);
    GetParm(IPINTERVAL, Interv);
    GetParm(HOSTINT, HostInt);
#else
    GetParm(NUMIPADR, TempNumIPadr);
    GetParm(ADDRINFO, TempAddrInfo);
    GetParm(IPINTERVAL, TempInterv);
    GetParm(HOSTINT, TempHostInt);
    GetParm(VERTSPLITBAR, VertSplitBar);
#endif
#ifndef DAEMON
    if ( PrfQueryProfileSize(hini, APPNAME, INITFONT, &DataLen) )
      if ( DataLen == sizeof(FONTDLG) )
        {
        PrfQueryProfileData(hini, APPNAME, INITFONT, &pfdFontdlg, &DataLen);
        sprintf(FontCntnr, "%d.%s", FIXEDINT(pfdFontdlg.fxPointSize),
                                    pfdFontdlg.fAttrs.szFacename);
#ifndef CONFIG_LS
        FontSetFl = FALSE;
#endif
        }
    GetParm(INITFONTNAME, InitFont);
#endif
    PrfCloseProfile(hini);   // Close private profile
    }
//-----------------------------------------------------------------------------
// Check (and correct) parameters
//-----------------------------------------------------------------------------
  Interval = ( Interval > L60 ) ? L60 : Interval;
  Interval = ( Interval < L5 ) ? L5 : Interval;
  Interval = ( Interval / L5 ) * L5;

  BaseInd = ( BaseInd > BaseARP ) ? BaseLS : BaseInd;

  pingtv.tv_sec = ( pingtv.tv_sec > L10) ? L10 : pingtv.tv_sec;
  pingtv.tv_sec = ( pingtv.tv_sec < L1 ) ? L1 : pingtv.tv_sec;

  if ( ArpWait <= L15 )
    {
    ArpWait = ( ArpWait < L3 ) ? L3 : ArpWait;
    ArpWait = ( ArpWait / L3 ) * L3;
    }
  else
    {
    ArpWait = ( ArpWait > L90 ) ? L90 : ArpWait;
    ArpWait = ( ArpWait < L30 ) ? L30 : ArpWait;
    ArpWait = ( ArpWait / L15 ) * L15;
    }

  TcpWait = ( TcpWait > L100 ) ? L100 : TcpWait;
  TcpWait = ( TcpWait < L10 ) ? L10 : TcpWait;
  TcpWait = ( TcpWait / L10 ) * L10;
}
