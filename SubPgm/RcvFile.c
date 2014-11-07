//=============================================================================
// RcvFile - Подпрограмма получения файла
//=============================================================================
BOOL RcvFile(int sock, char *FileName)
{
FILE *File;
char RecvBuf[FILEBUFLEN+L1];
struct timeval mytimeout;
fd_set r;
int i;

  File = fopen(FileName, "wb");
  mytimeout.tv_sec = TO_FILE;  // ждем сколько надо
  mytimeout.tv_usec = L0;

  FD_ZERO(&r);
  myFD_SET(sock, &r);

  for ( ;; )
    {
    if ( select(sock+1, &r, NULL, NULL, &mytimeout) <= 0 ) break;
    DosSleep(10); // немного подождем
    if ( (i=recv(sock, RecvBuf, sizeof(RecvBuf), L0)) <= L1 ) break;

    fwrite(RecvBuf+1, i-1, L1, File);
    if ( RecvBuf[0] != 0 ) continue;

    soclose(sock);
    fclose(File);
    return TRUE;
    }

// Обработка ошибок
  soclose(sock);
  fclose(File);
  DosDelete(FileName);
  return FALSE;
}