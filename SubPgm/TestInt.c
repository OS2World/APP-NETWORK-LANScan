//=============================================================================
// TestInt - подпрограмма проверки законности интервала
//=============================================================================
BOOL TestInt(char *line1, char *line2, int j)
{

  if ( j == 0 ) return FALSE;

  j--;   // NumIPadr всегда на 1 больше, чем надо

  if ( Interv[j] == NUMINTERV ) return FALSE;

  if ( (HostInt[j].start[Interv[j]]=inet_addr(line1)) == -1 ) return FALSE;
  if ( (HostInt[j].stop[Interv[j]]=inet_addr(line2)) == -1 ) return FALSE;

  HostInt[j].start[Interv[j]] = htonl(HostInt[j].start[Interv[j]]);
  HostInt[j].stop[Interv[j]]  = htonl(HostInt[j].stop[Interv[j]]);
#ifndef CONFIG_LS
  HostInt[j].start[Interv[j]] &= ~AddrInfoIP[j].mask;
  HostInt[j].stop[Interv[j]]  &= ~AddrInfoIP[j].mask;
#endif
  if ( (HostInt[j].start[Interv[j]] == 0) ||
       (HostInt[j].start[Interv[j]] > HostInt[j].stop[Interv[j]])
#ifndef CONFIG_LS
       || (HostInt[j].stop[Interv[j]] == ~AddrInfoIP[j].mask)
#endif
     ) return FALSE;

  Interv[j]++;
  return TRUE;
}
