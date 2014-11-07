//=============================================================================
// LS_View.c
// CGI программа просмотра результатов сканирования
//=============================================================================
#include <os2.h>
#include <time.h>
#include <stdio.h>
#include <libc\stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <types.h>
#include <sys\socket.h>
#include <sys\ioctl.h>
#include <netinet\in.h>
#include <net\route.h>
#include <net\if.h>
#include <net\if_arp.h>
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#include <arpa\inet.h>
#include <unistd.h>
#endif               // TCPV40HDRS
#include <netcons.h>
#include <sys/select.h>

#define PWDLEN          16
#define FILEBUFLEN     512
#define TO_FILE          3 // тайм-аут при получении файла
#define IPLEN           16
#define MACLEN          15
#define FQDNLEN         64
#define COMPNLEN       128

#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#define myFD_SET(fd, set) { \
    if (((fd_set *)(set))->fd_count < FD_SETSIZE) \
        ((fd_set *)(set))->fd_array[((fd_set *)(set))->fd_count++]=fd; }
#else
#define myFD_SET(fd, set) { FD_SET(fd, set); }
#endif

#define L0     0
#define L1     1
#define L4     4
#define L7     7
#define L256 256

//-----------------------------------------------------------------------------
// Global Variablies
//-----------------------------------------------------------------------------
char *CompNfirst, MAC[MACLEN];
int NumOUI = 0;
static char ParmIP[] = "ParmIP=", ParmPort[] = "ParmPort=",
            ParmViewPass[] = "ParmViewPass=", ParmRunPass[] = "ParmRunPass=";

//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------
void printMsg(char *);
struct sockaddr_in resolv(char *);
void DoRun(struct sockaddr_in *, char *);
void DoView(struct sockaddr_in *, char *);
BOOL RcvFile(int, char *);
void FormOUI(void);
_inline int FindOUI (void);

//=============================================================================
// Main procedure
//=============================================================================
void main(int argc, char *argv[])
{
int len, parmlen, i, j;
char *ptr, argstr[128], IPaddr[16], Port[6], ViewPWD[PWDLEN], RunPWD[PWDLEN];
static struct sockaddr_in myaddr = { 0 }, myaddrRun = { 0 };

   memset(argstr, '\0', sizeof(argstr));
   memset(IPaddr, '\0', sizeof(IPaddr));
   memset(Port, '\0', sizeof(Port));
   memset(ViewPWD, '\0', sizeof(ViewPWD));
   memset(RunPWD, '\0', sizeof(RunPWD));

   printf("Content-type:text/html\n\n");
   printf("<html>\n<head>\n<title>LanScan</title>\n</head>\n<body>\n");

   if ( strcmp(getenv("REQUEST_METHOD"), "POST") )
     printMsg("LS_View can use POST only.");

   if ( strcmp(getenv("CONTENT_TYPE"), "application/x-www-form-urlencoded") )
     printMsg("LS_View can only be used to decode form results.");

   if ( (getenv("CONTENT_LENGTH")) == NULL )
     printMsg("CONTENT_LENGTH is absent.");

   if ( (len = atoi(getenv("CONTENT_LENGTH"))) > 127 ) len=127;
   fgets(argstr, len+1, stdin);

   if ( (ptr = strstr(argstr, ParmIP)) == NULL )
     printMsg("ParmIP parameter is absent.");
   ptr=ptr+strlen(ParmIP);
   parmlen=strlen(ptr);
   for ( i=j=0; (*ptr!='&')&&(i<parmlen)&&(j<15); i++) IPaddr[j++] = *ptr++;
   if ( strlen(IPaddr) == 0 ) printMsg("IP address is absent.");

   if ( (ptr = strstr(argstr, ParmPort)) == NULL )
     printMsg("ParmPort parameter is absent.");
   ptr=ptr+strlen(ParmPort);
   parmlen=strlen(ptr);
   for ( i=j=0; (*ptr!='&')&&(i<parmlen)&&(j<5); i++) Port[j++] = *ptr++;
   if ( strlen(Port) == 0 ) printMsg("Port number is absent.");

   if ( (ptr = strstr(argstr, ParmViewPass)) == NULL )
     printMsg("ParmViewPass parameter is absent.");
   ptr=ptr+strlen(ParmViewPass);
   parmlen=strlen(ptr);
   for ( i=j=0; (*ptr!='&')&&(i<parmlen)&&(j<15); i++) ViewPWD[j++] = *ptr++;

   if ( (ptr = strstr(argstr, ParmRunPass)) == NULL )
     printMsg("ParmRunPass parameter is absent.");
   ptr=ptr+strlen(ParmRunPass);
   parmlen=strlen(ptr);
   for ( i=j=0; (*ptr!='&')&&(i<parmlen)&&(j<15); i++) RunPWD[j++] = *ptr++;

   myaddr = resolv(IPaddr);
   myaddr.sin_port = htons((unsigned short)atoi(Port));
   myaddr.sin_family = AF_INET;
   memcpy((char *)&myaddrRun, (char *)&myaddr, sizeof(myaddr));

   if ( (ptr = strstr(argstr, "Button=Run")) != NULL )
     DoRun(&myaddrRun, RunPWD);
   DoView(&myaddr, ViewPWD);

   printf("<div align=\"center\">\n");
   printf("<form method=\"post\" action=\"/cgi-bin/LS_View.cgi\">\n");
   printf("<input type=\"hidden\" name=\"ParmIP\" value=\"%s\">\n", IPaddr);
   printf("<input type=\"hidden\" name=\"ParmPort\" value=\"%s\">\n", Port);
   printf("<input type=\"hidden\" name=\"ParmViewPass\" value=\"%s\">\n", ViewPWD);
   printf("<input type=\"hidden\" name=\"ParmRunPass\" value=\"%s\">\n", RunPWD);
   printf("<br>\n");
   printf("<input type=\"submit\" value=\"View\" name=\"Button\">\n");
   printf("&nbsp;&nbsp;&nbsp;\n");
   printf("<input type=\"submit\" value=\"Run\" name=\"Button\">\n");
   printf("</form>\n</div>\n");

   printf("</body>\n</html>");
}

//=============================================================================
// resolv - Подпрограмма построения IP адреса
//=============================================================================
struct sockaddr_in resolv(char *address)
{
  struct sockaddr_in myaddr = { 0 };
  struct hostent *host;

  if ( (myaddr.sin_addr.s_addr = inet_addr(address)) == INADDR_NONE )
    if ( (host=gethostbyname(address))==NULL ) printMsg("Invalid IP address.");
    else memcpy(&myaddr.sin_addr, (int *)host->h_addr, host->h_length);

  return myaddr;
}

//=============================================================================
// DoRun - программа инициирования сканирования
//=============================================================================
void DoRun(struct sockaddr_in *myRun, char *RunPW)
{
char NetBuf[PWDLEN+4];
int sock;

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

// Connect to the server.
  if ( connect(sock, (struct sockaddr *)myRun, sizeof(struct sockaddr)) < 0 )
    printMsg("Error in connect.");

  memset(NetBuf, '\0', sizeof(NetBuf));
  strcpy(NetBuf, "Run");
  strcat(NetBuf, RunPW);
  send(sock, NetBuf, PWDLEN+4, 0);

  soclose(sock);
}

//=============================================================================
// DoView - программа получения результатов сканирования
//=============================================================================
void DoView(struct sockaddr_in *myView, char *ViewPW)
{
char NetBuf[PWDLEN+L4], Line[L256], FileResultName[32];
int sock, len, CNI;
FILE *File;
BOOL NBresult = FALSE;
char IP[IPLEN], FQDN[FQDNLEN], NETBN[UNCLEN];
unsigned int storaddr;

  FormOUI();
  storaddr = (int)CompNfirst;
  sprintf(FileResultName, "LanScan-%d.Tmp", storaddr);
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

// Connect to the server.
  if ( connect(sock, (struct sockaddr *)myView, sizeof(struct sockaddr)) < 0 )
    printMsg("Error in connect.");

  memset(NetBuf, '\0', sizeof(NetBuf));
  strcpy(NetBuf, "See");
  strcat(NetBuf, ViewPW);
  send(sock, NetBuf, PWDLEN+L4, L0);

  if ( !RcvFile(sock, FileResultName) ) printMsg("Error receive.");

  File = fopen(FileResultName, "r");

  fgets(Line, sizeof(Line), File);
  Line[strlen(Line)-L1] = '\0';
  printf("<h2 align=\"center\">%s</h2>\n", Line);

  fgets(Line, sizeof(Line), File);
  len = strlen(Line)-L1;
  Line[len] = '\0';
  printf("<h3 align=\"center\">%s</h3>\n", Line);

  if ( strstr(Line, " Domain -") != NULL ) NBresult = TRUE;

  fgets(Line, sizeof(Line), File); // Пропустим наименования колонок

  printf("<table border=\"1\" align=center cellspacing=\"0\" cellpadding=\"5\">\n");
  printf("<tr><td>IP address</td><td>MAC address</td><td>Host name</td>");
  if ( NBresult ) printf("<td>NetBIOS name</td>");
  printf("<td>Manufacturer</td></tr>\n");

  while ( fgets(Line, sizeof(Line), File) != NULL )
    {
    Line[strlen(Line)-L1] = '\0';
    memset(IP, '\0', IPLEN);
    memset(MAC, '\0', MACLEN);
    memset(FQDN, '\0', FQDNLEN);
    memset(NETBN, '\0', UNCLEN);

    memcpy(IP, Line, IPLEN-1);
    memcpy(MAC, Line+16, MACLEN-1);
    memcpy(NETBN, Line+31, UNCLEN-1);
    strcpy(FQDN, Line+48 );

    printf("<tr><td>%s</td>", IP);
    if ( MAC[0] != ' ' ) printf("<td>%s</td>", MAC);
    else printf("<td>&nbsp</td>");
    if ( FQDN[0] != ' ' ) printf("<td>%s</td>", FQDN);
    else printf("<td>&nbsp</td>");
    if ( NBresult )
      if ( NETBN[0] != ' ' ) printf("<td>%s</td>", NETBN);
      else printf("<td>&nbsp</td>");
    if ( (CNI = FindOUI()) == NumOUI ) printf("<td>&nbsp</td></tr>\n");
    else printf("<td>%s</td></tr>\n", CompNfirst+COMPNLEN*CNI+L7);
    }

  fclose(File);
  DosDelete(FileResultName);
  printf("</table>\n");
}

//=============================================================================
// printMsg - программа выдачи сообщения об ошибке
//=============================================================================
void printMsg(char *str)
{
  printf("%s\n</body>\n</html>", str);
  exit(0);
}

//=============================================================================
// FormOUI - подпрограмма формирования списка производителей сетевых карт
//=============================================================================
void FormOUI(void)
{
FILE *FileOUI;
int i;
char Line[COMPNLEN], *ptr;

  if ( (FileOUI = fopen("oui.lst", "r")) == NULL )
    CompNfirst=calloc(COMPNLEN*NumOUI+L7, L1);
  else
    {
    for (; fgets(Line, COMPNLEN, FileOUI) != NULL; NumOUI++) {};

    CompNfirst=calloc(COMPNLEN*NumOUI+L1, L1);
    rewind(FileOUI);

    for (i=0, ptr = CompNfirst; i<NumOUI; i++, ptr+=COMPNLEN)
      {
      fgets(ptr, COMPNLEN, FileOUI);
      ptr[strlen(ptr)-L1] = '\0';
      }

    fclose(FileOUI);
    }
}

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

//=============================================================================
// FindOUI - процедура поиска производителя сетевой карты
//=============================================================================
_inline int FindOUI (void)
{
int FirstCNI, LastCNI, n, i;

  FirstCNI = 0;
  i = LastCNI = NumOUI;
  while ( FirstCNI <= LastCNI )
    {
    i = (FirstCNI+LastCNI)/2;
    n = memcmp(MAC, CompNfirst+COMPNLEN*i, L7);
    if ( n < 0 ) LastCNI = i-1;
    else
      if ( n > 0 ) FirstCNI = i+1;
      else break;
    i = NumOUI;
    }

  return i;
}

