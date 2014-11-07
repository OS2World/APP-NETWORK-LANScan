//=============================================================================
// SaveOpt - подпрограмма сохранения параметров работы
//=============================================================================
void SaveOpt (char *fname)
{
  hini = PrfOpenProfile(hab, fname);

  PrfWriteProfileData(hini,APPNAME,AUTORUN, &AutoRun, sizeof(AutoRun));
  PrfWriteProfileData(hini,APPNAME,AUTOLOG, &AutoLog, sizeof(AutoLog));
  PrfWriteProfileData(hini,APPNAME,COMMONLOG, &CommonLog, sizeof(CommonLog));
  PrfWriteProfileData(hini,APPNAME,INTERVAL, &Interval, sizeof(Interval));
  PrfWriteProfileData(hini,APPNAME,BASEIND, &BaseInd, sizeof(BaseInd));
  PrfWriteProfileData(hini,APPNAME,USEDNS, &useDNS, sizeof(useDNS));
  PrfWriteProfileData(hini,APPNAME,USEOTHD, &useOTHD, sizeof(useOTHD));
  PrfWriteProfileData(hini,APPNAME,PINGTO,
                      &pingtv.tv_sec, sizeof(pingtv.tv_sec));
  PrfWriteProfileData(hini,APPNAME,ARPTO, &ArpWait, sizeof(ArpWait));
  PrfWriteProfileData(hini,APPNAME,TCPTO, &TcpWait, sizeof(TcpWait));
  PrfWriteProfileData(hini,APPNAME,NUMPING, &NumPing, sizeof(NumPing));
  PrfWriteProfileData(hini,APPNAME,PINGSTART, &PingStart, sizeof(PingStart));
  PrfWriteProfileData(hini,APPNAME,PINGSTOP, &PingStop, sizeof(PingStop));
  PrfWriteProfileData(hini,APPNAME,NBACT, &NBact, sizeof(NBact));
  PrfWriteProfileData(hini,APPNAME,NBACTP, &NBactP, sizeof(NBactP));
  PrfWriteProfileData(hini,APPNAME,NBADRSET, &NBadrSet, sizeof(NBadrSet));
  PrfWriteProfileData(hini,APPNAME,NBADRM, &NBadrM, sizeof(NBadrM));
  PrfWriteProfileData(hini,APPNAME,NUMIPADR, &NumIPadr, sizeof(NumIPadr));
  PrfWriteProfileData(hini,APPNAME,ADDRINFO, &AddrInfoIP, sizeof(AddrInfoIP));
  PrfWriteProfileData(hini,APPNAME,IPINTERVAL, &Interv, sizeof(Interv));
  PrfWriteProfileData(hini,APPNAME,HOSTINT, &HostInt, sizeof(HostInt));

  PrfCloseProfile(hini);   // Close private profile
}
