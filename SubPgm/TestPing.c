//=============================================================================
// TestPing - подпрограмма определения интарвала для PING
//=============================================================================
BOOL TestPing(char *str1, char *str2)
{

  if ( NumPing == MAXIPADR ) return FALSE;

  if ( (PingStart[NumPing]=inet_addr(str1)) == -1 ) return FALSE;
  if ( (PingStop[NumPing]=inet_addr(str2)) == -1 ) return FALSE;

  if ( (PingStart[NumPing] == 0) ||
       (htonl(PingStart[NumPing]) > htonl(PingStop[NumPing])) ) return FALSE;

  NumPing++;
  return TRUE;
}
