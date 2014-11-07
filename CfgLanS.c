//=============================================================================
// CfgLanS.c
// Программа конфигурирования LanScan
//=============================================================================
#define INCL_WIN
#define INCL_DOSFILEMGR
#define INCL_DOSPROCESS

#include <os2.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <types.h>
#include <sys/socket.h>
#include <sys\ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <net\if.h>
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#include <arpa/inet.h>
#include <unistd.h>
#endif               // TCPV40HDRS
#include <nerrno.h>
#include <netinet/in_systm.h>
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#include <netinet\ip.h>
#else
#include "ip.h"
#endif
#include <libc\sys\stat.h>
#include "LanScan.h"

//-----------------------------------------------------------------------------
// Dialog Window procedure prototype
//-----------------------------------------------------------------------------
MRESULT EXPENTRY DlgMenu (HWND, ULONG ,MPARAM, MPARAM);
void SendErrMsg(HWND, char *);
struct sockaddr_in resolv(HWND, char *);
MRESULT EXPENTRY DlgProcPING (HWND, ULONG, MPARAM, MPARAM); // Dlg proc (PING)
MRESULT EXPENTRY DlgProcOPT  (HWND, ULONG, MPARAM, MPARAM); // Dlg proc (OPT)
MRESULT EXPENTRY DlgProcARP  (HWND, ULONG, MPARAM, MPARAM); // Dlg proc (ARP)
MRESULT EXPENTRY DlgProcRead (HWND, ULONG, MPARAM, MPARAM); // Dlg proc (Read)
MRESULT EXPENTRY DlgProcWrite (HWND, ULONG, MPARAM, MPARAM); // Dlg proc (Write)
BOOL             TestPing(char *, char *);
void             SendWngMsg(HWND, char *);
BOOL             TestInt(char *, char *, int);
void             SaveOpt (char *);
void             GetOpt (char *);
void             GetFileCfg(HWND, char *);
void             PutFileCfg(HWND, char *);
BOOL             RcvFile(int, char *);
void             SndFile(int, char *);

#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#define myFD_SET(fd, set) { \
    if (((fd_set *)(set))->fd_count < FD_SETSIZE) \
        ((fd_set *)(set))->fd_array[((fd_set *)(set))->fd_count++]=fd; }
#else
#define myFD_SET(fd, set) { FD_SET(fd, set); }
#endif

//-----------------------------------------------------------------------------
// Global Variablies
//-----------------------------------------------------------------------------
int ac;
char **av;
struct sockaddr_in myaddr = { 0 };
char CFGname[] = "LANSCAN.CFR";
FONTDLG pfdFontdlg = { { 0 } };  // Font dialog info structure
char FontCntnr[FACESIZE+5] = FontName;
char InitFont[FACESIZE] = "WarpSans";
char NBact = FALSE, NBactP = FALSE, NBadrSet = FALSE,
     NBadrM[MAXIPADR] = {FALSE,FALSE,FALSE,FALSE,FALSE,FALSE,FALSE,FALSE};
int NumPing = L0, NumIPadr = L0;
unsigned int Interval = L15, ArpWait = L6, TcpWait = L10, BaseInd = L0;
int Interv[MAXIPADR] = { 0, 0, 0, 0, 0, 0, 0, 0 };
struct _HostInt
  { u_long start[NUMINTERV];
    u_long stop[NUMINTERV];
  } HostInt[MAXIPADR] =  { {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0} };
struct sockaddr_in sin[MAXIPADR] = { {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0} };
char AutoRun = FALSE, AutoLog = FALSE, CommonLog = TRUE,
     useDNS = TRUE, useOTHD = FALSE;
struct timeval pingtv;
unsigned long PingStart[MAXIPADR] = { 0, 0, 0, 0, 0, 0, 0, 0 };
unsigned long PingStop[MAXIPADR] = { 0, 0, 0, 0, 0, 0, 0, 0 };
HAB  hab;     // Anchor
HINI hini;    // Handle to private INI file
ULONG DataLen;

#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
struct statatreq AddrInfoIP[MAXIPADR];
#else                // Включить для TCP/IP 4.0
#pragma pack(1)
struct statatreq
  { u_long addr;
    short interface;
    u_long mask;
    u_long broadcast;
  } AddrInfoIP[MAXIPADR];
#pragma pack()
#endif               // TCPV40HDRS

//=============================================================================
// Main procedure
//=============================================================================
void main(int argc, char *argv[])
     {
     HMQ hmq;

     hab = WinInitialize (0);          // Anchor
     hmq = WinCreateMsgQueue(hab, 0);  // Message queue handle

     ac = argc;
     av = argv;

#ifdef TCPV40HDRS    // Включить для TCP/IP 4.0
     sock_init();
#endif               // TCPV40HDRS

     WinDlgBox( HWND_DESKTOP,
                HWND_DESKTOP,
                DlgMenu,
                NULLHANDLE,
                DIALOGWIN,
                0 );

     WinDestroyMsgQueue(hmq);
     WinTerminate(hab);
     }

//=============================================================================
// Dialog procedure
//=============================================================================
MRESULT EXPENTRY DlgMenu (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
  {
  switch (msg)
    {
//-----------------------------------------------------------------------------
// Handle the initialization of the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      unsigned short port;
      char TextIP[16], TextPort[6];
//-----------------------------------------------------------------------------
// Set icon & menu
//-----------------------------------------------------------------------------
      HPOINTER hptr = (HPOINTER)WinLoadPointer(HWND_DESKTOP, NULLHANDLE, 1);
      WinSendMsg(hwndDlg, WM_SETICON, (MPARAM) hptr, 0l);

      WinLoadMenu(hwndDlg, NULLHANDLE, MENU_ID);
      WinSendMsg(hwndDlg, WM_UPDATEFRAME, (MPARAM) FCF_MENU, 0l);

      if ( ac != 3 )
        {
        SendErrMsg(hwndDlg, "Syntax: CfgLanS <IP address> port");
        break;
        }

      myaddr = resolv(hwndDlg, av[1]);
      sprintf(TextIP, "%s", inet_ntoa(myaddr.sin_addr));
      WinSetDlgItemText(hwndDlg, TXT_IP, TextIP);

      port = (unsigned short)atoi(av[2]);
      sprintf(TextPort, "%d", port);
      WinSetDlgItemText(hwndDlg, TXT_PORT, TextPort);

      myaddr.sin_family = AF_INET;
      myaddr.sin_port = htons(port);

      GetOpt(CFGname);   // Get Options

      break;
      }
//-----------------------------------------------------------------------------
// Handle WM_COMMAND
//-----------------------------------------------------------------------------
    case WM_COMMAND:
      {
      switch(SHORT1FROMMP(mp1))
        {
//-----------------------------------------------------------------------------
// Close the dialog
//-----------------------------------------------------------------------------
        case ITEM_EXIT:
          {
          WinSendMsg(hwndDlg, WM_CLOSE, 0L, 0L);
          break;
          }
//-----------------------------------------------------------------------------
// Read
//-----------------------------------------------------------------------------
        case ITEM_READ:
          {
          WinDlgBox (HWND_DESKTOP, // Parent
                     hwndDlg,      // Owner
                     DlgProcRead,  // Dialog window procedure
                     NULLHANDLE,   // Where is dialog resource?
                     DIALOGREADPW, // Dialog Resource ID
                     0);       // Create parms (for WM_INITDLG)
          return(MRFROMSHORT(TRUE));
          }
//-----------------------------------------------------------------------------
// Write
//-----------------------------------------------------------------------------
        case ITEM_WRITE:
          {
          WinDlgBox (HWND_DESKTOP, // Parent
                     hwndDlg,      // Owner
                     DlgProcWrite, // Dialog window procedure
                     NULLHANDLE,   // Where is dialog resource?
                     DIALOGWRITEPW, // Dialog Resource ID
                     0);       // Create parms (for WM_INITDLG)
          return(MRFROMSHORT(TRUE));
          }
//-----------------------------------------------------------------------------
// Options
//-----------------------------------------------------------------------------
        case ITEM_OPTIONS:
          {
          WinDlgBox (HWND_DESKTOP, // Parent
                     hwndDlg,      // Owner
                     DlgProcOPT,  // Dialog window procedure
                     NULLHANDLE,   // Where is dialog resource?
                     OPTIONS_ID,      // Dialog Resource ID
                     0);       // Creatin parms (for WM_INITDLG)

          return(MRFROMSHORT(TRUE));
          }

        }
      break;
      }
    }

  return WinDefDlgProc(hwndDlg, msg, mp1, mp2);
  }

//=============================================================================
// GetFileCfg - Подпрограмма получения файла конфигурации
//=============================================================================
void GetFileCfg(HWND hwnd, char *passw)
{
int sock;
char buf[PWDLEN+L4];

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

// Connect to the server.
  if ( connect(sock, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0 )
    {
    SendWngMsg(hwnd, "Error in connect");
    soclose(sock);
    return;
    }

  memset(buf, '\0', sizeof(buf));
  strcpy(buf, "Get");
  strcat(buf, passw);
//  Send the Passowrd to Server.
  send(sock, buf, PWDLEN+L4, L0);

//  Receive the configuration
  if ( !RcvFile(sock, CFGname) ) return;
  GetOpt(CFGname);   // Get Options
}

//=============================================================================
// PutFileCfg - Подпрограмма отправления файла конфигурации
//=============================================================================
void PutFileCfg(HWND hwnd, char *passw)
{
int sock;
char buf[PWDLEN+L4];

  SaveOpt(CFGname);

  memset(buf, '\0', sizeof(buf));
  strcpy(buf, "Put");
  strcat(buf, passw);

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

// Connect to the server.
  if ( connect(sock, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0 )
    {
    SendWngMsg(hwnd, "Error in connect");
    soclose(sock);
    return;
    }
// Send the Passowrd to Server.
  send(sock, buf, PWDLEN+L4, L0);
// Send the Configuration to Server.
  SndFile(sock, CFGname);
}

//=============================================================================
// DlgProcRead - window procedure for the Read passowrd
//=============================================================================
MRESULT EXPENTRY DlgProcRead (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
{
char passw[PWDLEN];

  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      WinSendDlgItemMsg(hwndDlg, READ_PW, EM_SETTEXTLIMIT, (MPARAM)L15, 0);
      memset(passw, '\0', PWDLEN);
      WinSetDlgItemText(hwndDlg, READ_PW, passw);
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
          WinQueryDlgItemText(hwndDlg, READ_PW, PWDLEN, passw);
          GetFileCfg(hwndDlg, passw);
          break;
          }
        }
      }
      break;
    }
    return (WinDefDlgProc (hwndDlg,msg,mp1,mp2));
}

//=============================================================================
// DlgProcWrite - window procedure for the Write passowrd
//=============================================================================
MRESULT EXPENTRY DlgProcWrite (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
{
char passw[PWDLEN];

  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      WinSendDlgItemMsg(hwndDlg, WRITE_PW, EM_SETTEXTLIMIT, (MPARAM)L15, 0);
      memset(passw, '\0', PWDLEN);
      WinSetDlgItemText(hwndDlg, WRITE_PW, passw);
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
          WinQueryDlgItemText(hwndDlg, WRITE_PW, PWDLEN, passw);
          PutFileCfg(hwndDlg, passw);
          break;
          }
        }
      }
      break;
    }
    return (WinDefDlgProc (hwndDlg,msg,mp1,mp2));
}

#include "SubPgm\DlgProcARP.c"
#include "SubPgm\DlgProcOPT.c"
#include "SubPgm\DlgProcPING.c"
#include "SubPgm\GetOpt.c"
#include "SubPgm\RcvFile.c"
#include "SubPgm\resolv.c"
#include "SubPgm\SaveOpt.c"
#include "SubPgm\SendErrMsg.c"
#include "SubPgm\SendWngMsg.c"
#include "SubPgm\SndFile.c"
#include "SubPgm\TestInt.c"
#include "SubPgm\TestPing.c"
