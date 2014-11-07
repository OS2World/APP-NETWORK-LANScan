//=============================================================================
// SndFile - Подпрограмма отправки файла
//=============================================================================
void SndFile(int sock, char *FileName)
{
FILE *File;
char SendBuf[FILEBUFLEN+L1];
int i;
struct stat info;

  stat(FileName, &info);
  if ( (int)info.st_size == L0 )
    {
    soclose(sock);
    return;
    }

  File = fopen(FileName, "rb");

  for ( i=(int)info.st_size; ; i-=L512 )
    {
    if ( i > FILEBUFLEN )
      {
      fread(SendBuf+1, FILEBUFLEN, L1, File);
      SendBuf[0] = L1;
      send(sock, SendBuf, FILEBUFLEN+L1, L0);
      }
    else
      {
      fread(SendBuf+1, i, L1, File);
      SendBuf[0] = L0;
      send(sock, SendBuf, i+L1, L0);
      fclose(File);
      soclose(sock);
      return;
      }
    }
}