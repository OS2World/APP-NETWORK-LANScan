//=============================================================================
// resolv - Подпрограмма построения IP адреса
//=============================================================================
struct sockaddr_in resolv(HWND hwnd, char *address)
{
  struct sockaddr_in myaddr = { 0 };
  struct hostent *host;

  if ( (myaddr.sin_addr.s_addr = inet_addr(address)) == INADDR_NONE )
    {
    if ( (host = gethostbyname(address)) == NULL )
      {
      SendErrMsg(hwnd, "Invalid address");
      exit(0);
      }
    else memcpy(&myaddr.sin_addr, (int *)host->h_addr, host->h_length);
    }
  return myaddr;
}
