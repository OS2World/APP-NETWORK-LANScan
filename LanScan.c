//=============================================================================
// LanScan.c
// Программа сканирования сети Ethernet путем выдачи ARP-запросов
//=============================================================================
#define INCL_WIN
#define INCL_DOSMEMMGR
#ifndef DAEMON
#define INCL_GPIBITMAPS
#define INCL_WINSTDFONT    // Window Standard Font Functions
#endif
#define INCL_DOSSEMAPHORES
#define INCL_DOSPROCESS
#define INCL_DOSERRORS
#define INCL_DOSDATETIME
#define INCL_REXXSAA
#define INCL_DOSFILEMGR
#define INCL_GPILCIDS
#define PURE_32

#include <os2.h>
#include <umalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
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
#include <wksta.h>
#include <access.h>
#include <server.h>
#include <ncb.h>
#include <netbios.h>
#include <neterr.h>
#include <rexxsaa.h>   // needed for RexxStart()
#include <netinet\in_systm.h>
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#include <netinet\ip.h>
#else
#include <time.h>
#include "ip.h"
#endif
#include <netinet\ip_icmp.h>
#include <shares.h>
#include <libc\sys\stat.h>
#include <sys/select.h>
#include "LanScan.h"

//-----------------------------------------------------------------------------
// Prototypes
//-----------------------------------------------------------------------------
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
static void * _Optlink get_fn(Heap_t usrheap, size_t *length, int *clean)
{
  void *p;
  int rc;

// Round up to the next chunk size
  *length = ((*length) / L65536) * L65536 + L65536;
  *clean = _BLOCK_CLEAN;
  rc = DosAllocMem(&p, *length, PAG_COMMIT | PAG_READ | PAG_WRITE | OBJ_ANY);
  if ( rc ) p=NULL;
  return (p);
}

static void _Optlink  release_fn(Heap_t usrheap, void *p, size_t size)
{
  DosFreeMem(p);
  return;
}

#define myFD_SET(fd, set) { \
    if (((fd_set *)(set))->fd_count < FD_SETSIZE) \
        ((fd_set *)(set))->fd_array[((fd_set *)(set))->fd_count++]=fd; }
#else
#define myFD_SET(fd, set) { FD_SET(fd, set); }
#endif

#ifndef DAEMON
MRESULT EXPENTRY ClientWndProc(HWND,ULONG,MPARAM,MPARAM);
MRESULT EXPENTRY DlgProcPING(HWND, ULONG, MPARAM, MPARAM); // Dlg proc (PING)
MRESULT EXPENTRY DlgProcOPT(HWND, ULONG, MPARAM, MPARAM);  // Dlg proc (OPT)
MRESULT EXPENTRY DlgProcARP(HWND, ULONG, MPARAM, MPARAM);  // Dlg proc (ARP)
void    APIENTRY DoScan(ULONG);
void             StartThreads(HWND);
void             GetIPname(HWND, char *, u_long);
ULONG            GetNBnames(HWND, char *, ULONG);
int              TCPBEUIscan(HWND);
int              NETBEUIscan(HWND, int);
void             PingRange(HWND, int);
void             InitContainer(BOOL);
void             GetFontName(char *);
void             ShowPrompt(HWND, int, int, BOOL, char *);
_inline void     InsertRecord(int, short);
void             GetIPaddr(short);
BOOL             GetFileName(char *);
BOOL             TestInt(char *, char *, int);
BOOL             TestPing(char *, char *);
_inline short    FindOUI (void);
#else
void    APIENTRY DoScan(void);
void             StartThreads(void);
void             GetIPname(char *, u_long);
ULONG            GetNBnames(char *, ULONG);
int              TCPBEUIscan(void);
int              NETBEUIscan(int);
void             PingRange(int);
#endif

void    APIENTRY CFGpgm(void);
void    APIENTRY ViewPgm(void);
_inline u_short  in_cksum(u_short *, int);
void             GetStorage(void);
void             DoSave(char *, char *, BOOL);
void             CrtRFCNAMES(void);
BOOL             TestAddr(int);
void             FormNCB(void);
BOOL             TestBEUI(void);
void             SetTitle (BOOL);
void             SaveOpt (char *);
void             GetOpt (char *);
void             IniFormIP(void);
void             SendResult(void *);
BOOL             RcvFile(int, char *);
void             SndFile(int, char *);
void             AfterScan(void);
int              GetTCPBEUIn(char *, int);
void             SmbName(char *, char *, long);

//-----------------------------------------------------------------------------
// Global Variablies
//-----------------------------------------------------------------------------
int NumPing = L0, NumIPadr = L0;
unsigned long PingStart[MAXIPADR] = { 0, 0, 0, 0, 0, 0, 0, 0 };
unsigned long PingStop[MAXIPADR] = { 0, 0, 0, 0, 0, 0, 0, 0 };
char AutoRun = FALSE, AutoLog = FALSE, CommonLog = TRUE,
     useDNS = TRUE, useOTHD = FALSE;
unsigned int Interval = L15, ArpWait = L6, TcpWait = L10, BaseInd = L0;
long VertSplitBar = L0;
struct timeval pingtv;
char NBact = FALSE, NBactP = FALSE, NBresult = FALSE, NBadrSet = FALSE,
     NBadrM[MAXIPADR] = {FALSE,FALSE,FALSE,FALSE,FALSE,FALSE,FALSE,FALSE};
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
struct statatreq AddrInfoIP[MAXIPADR], *AdrInfo;
#else                // Включить для TCP/IP 4.0
#pragma pack(1)
struct statatreq
  { u_long addr;
    short interface;
    u_long mask;
    u_long broadcast;
  } AddrInfoIP[MAXIPADR], *AdrInfo;
#pragma pack()
#endif               // TCPV40HDRS
int Interv[MAXIPADR] = { 0, 0, 0, 0, 0, 0, 0, 0 };
struct _HostInt
  { u_long start[NUMINTERV];
    u_long stop[NUMINTERV];
  } HostInt[MAXIPADR] =  { {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0} };
struct sockaddr_in sin[MAXIPADR] = { {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0} };
HAB  hab;     // Anchor
HINI hini;    // Handle to private INI file
ULONG DataLen;

#ifndef DAEMON
HWND hwndFrame = L0, hwndCntnr = L0, hwndButton = L0;
HPOINTER hIcon;
HBITMAP hbmRun   = L0, hbmRunDi   = L0, hbmRunHi   = L0,
        hbmBreak = L0, hbmBreakDi = L0, hbmBreakHi = L0,
        hbmARP   = L0, hbmARPDi   = L0, hbmARPHi   = L0,
        hbmPing  = L0, hbmPingDi  = L0, hbmPingHi  = L0,
        hbmOpt   = L0, hbmOptDi   = L0, hbmOptHi   = L0,
        hbmHelp  = L0,                  hbmHelpHi  = L0,
        hbmExit  = L0,                  hbmExitHi  = L0,
        hbmN     = L0, hbmD       = L0;
HEV hevEventStart = L0;
FONTDLG pfdFontdlg = { 0 };  // Font dialog info structure
BOOL FontSetFl = TRUE;       // Флаг "инициализировать структуру FONTDLG"
BOOL PromptFlag = FALSE;
char FontCntnr[FACESIZE+L5] = FontName, InitFont[FACESIZE] = "WarpSans",
     szFullPath[CCHMAXPATH] = "LanScan.txt", Nol[] = "<>";
typedef struct _USERRECORD
  { RECORDCORE  recordCore;
    PSZ         Status;
    PSZ         IPaddress;
    PSZ         MACaddress;
    PSZ         FQDName;
    PSZ         CompName;
    PSZ         NBname;
  } USERRECORD, *PUSERRECORD;
PNOTIFYRECORDENTER Selected;
ULONG ulPostStart = L0;
short CNI;
int x2Exit = L0, x2Help = L0;
RECTL rclButton = { L0, L0, PB_CX, PB_CY };
#endif

char pszCnrTitle[256];
PCHAR pB;
char *IPfirst,   *MACfirst,   *FQDNfirst,  *NBfirst,
     *NBIPfirst, *NETBNfirst, *MACNBfirst, *CompNfirst,
     *IP,        *MAC,        *FQDN,       *NB,
     *NBIP,      *NETBN,      *MACNB,      *CompN;
int CurrNum = L0, NumNCB = L0;
struct in_addr *inadr;
struct in_addr *inaddr[MAXIPADR] =
  { (struct in_addr *)&sin[L0].sin_addr, (struct in_addr *)&sin[L1].sin_addr,
    (struct in_addr *)&sin[L2].sin_addr, (struct in_addr *)&sin[L3].sin_addr,
    (struct in_addr *)&sin[L4].sin_addr, (struct in_addr *)&sin[L5].sin_addr,
    (struct in_addr *)&sin[L6].sin_addr, (struct in_addr *)&sin[L7].sin_addr };
unsigned long *paddr[MAXIPADR] =
  { (unsigned long *)&sin[L0].sin_addr, (unsigned long *)&sin[L1].sin_addr,
    (unsigned long *)&sin[L2].sin_addr, (unsigned long *)&sin[L3].sin_addr,
    (unsigned long *)&sin[L4].sin_addr, (unsigned long *)&sin[L5].sin_addr,
    (unsigned long *)&sin[L6].sin_addr, (unsigned long *)&sin[L7].sin_addr };
ULONG ulEntriesAvailable = L0, ulEntriesRead = L0, ulSesRead = L0,
      ulSesAvailable = L0, ulPostCnt = L0;
UCHAR *Net32Buf, DCName[UNCLEN+1], *pSes, buf[L1024], *ptr;
struct wksta_info_1 *pWkInf;
HEV hevEventHandle = L0;
TID tid = L0, tidCFG = L0, tidView = L0;
HTIMER phtimer = L0;
short int *pi = (short int *)&buf;
char MyMAC[MAXIPADR*L6], *bufFind, LineSep[] = "------------";
struct ncb NCBB[MAXIPADR] = { {0}, {0}, {0}, {0}, {0}, {0}, {0}, {0} };
struct netbios_info_1 *NBI1;
char NetName[MAXIPADR*(NETBIOS_NAME_LEN+1)], NewNBact, NewNBactP,
     ChkTCPB[MAXIPADR] = { '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0' };
struct tm *timeptr;
short NumOUI = L0, StatusIP[NUMADR];
int len = L254*sizeof(struct netbios_info_1),
    TempNumIPadr = L0, TempInterv[MAXIPADR] = { 0, 0, 0, 0, 0, 0, 0, 0 };
struct statatreq TempAddrInfo[MAXIPADR] = { {0},{0},{0},{0},{0},{0},{0},{0} };
struct _HostInt TempHostInt[MAXIPADR] = { {0},{0},{0},{0},{0},{0},{0},{0} };
BOOL flagSet = FALSE, flagRun = TRUE, FlagNewCFG = FALSE, FlagSrv = FALSE;
ULONG ulSize;  // Size of the data to be copied
char INIname[] = "LANSCAN.INI", CFGname[] = "LANSCAN.CFG", FileSrvName[L32];
char ViewPWD[PWDLEN+L1], RunPWD[PWDLEN+L1], ReadPWD[PWDLEN+L1],
     WritePWD[PWDLEN+L1];
char TxtExist[2] = "", TxtDel[2] = "-", TxtAdd[2] = "+",
     TxtRepl[2] = "<", TxtUpd[2] = ">";

//=============================================================================
// Main procedure
//=============================================================================
void main()
     {
     FILE *File;
#ifndef DAEMON
     HMQ   hmq;                    // Message queue handle
     QMSG  qmsg;                   // Message struct
     ULONG flFrameFlags = FCF_TITLEBAR   | FCF_SYSMENU | FCF_SHELLPOSITION |
                          FCF_SIZEBORDER | FCF_MINMAX  | FCF_TASKLIST      |
                          FCF_ACCELTABLE | FCF_MENU    | FCF_AUTOICON;
#endif

#ifdef DAEMON
     PPIB pib;

     DosGetInfoBlocks(NULL, &pib);
     pib->pib_ultype = L3; // Тип приложения - PM
#endif

     memset(FileSrvName, '\0', sizeof(FileSrvName));

#ifdef TCPV40HDRS    // Включить для TCP/IP 4.0
     sock_init();
#endif               // TCPV40HDRS

     pingtv.tv_sec = L1;    // по умолчанию будем ждать 1 секунду
     pingtv.tv_usec = L0;

     memset(WritePWD, '\0', sizeof(WritePWD));
     memset(ReadPWD,  '\0', sizeof(ReadPWD));
     memset(RunPWD,   '\0', sizeof(RunPWD));
     memset(ViewPWD,  '\0', sizeof(ViewPWD));
     if ( (File=fopen("LanScan.pwd", "r")) != NULL )
       {
       fgets(WritePWD, PWDLEN+L1, File);
       if ( strlen(WritePWD) > L0 )
         if ( WritePWD[strlen(WritePWD)-L1] == '\x0a' )
           WritePWD[strlen(WritePWD)-L1] = '\0';
       fgets(ReadPWD, PWDLEN+L1, File);
       if ( strlen(ReadPWD) > L0 )
         if ( ReadPWD[strlen(ReadPWD)-L1] == '\x0a' )
           ReadPWD[strlen(ReadPWD)-L1] = '\0';
       fgets(RunPWD, PWDLEN+L1, File);
       if ( strlen(RunPWD) > L0 )
         if ( RunPWD[strlen(RunPWD)-L1] == '\x0a' )
           RunPWD[strlen(RunPWD)-L1] = '\0';
       fgets(ViewPWD, PWDLEN+L1, File);
       if ( strlen(ViewPWD) > L0 )
         if ( ViewPWD[strlen(ViewPWD)-L1] == '\x0a' )
           ViewPWD[strlen(ViewPWD)-L1] = '\0';
       fclose(File);
       }
//-----------------------------------------------------------------------------
// Initialize application and create message queue
//-----------------------------------------------------------------------------
     hab = WinInitialize (L0);
#ifndef DAEMON
     hmq = WinCreateMsgQueue (hab, L0);
#endif

     GetOpt(INIname);   // Get Options
     IniFormIP();
     GetStorage();
#ifdef DAEMON
     StartThreads();
     for ( ;; )
       {
       printf("%s\nEnter Ctrl-C for exit\n", TitleBar);
       while ( (getchar()) !='\x0a' ) {};
       }
#endif

#ifndef DAEMON
//-----------------------------------------------------------------------------
// Register class and create window
//-----------------------------------------------------------------------------
     WinRegisterClass (hab, "LanScan", ClientWndProc, CS_SIZEREDRAW, L0);
     hwndFrame = WinCreateStdWindow (HWND_DESKTOP,     // Parent
                                     L0,               // Style (unvisible)
                                     &flFrameFlags,    // Creation flags
                                     "LanScan",        // Class name
                                     TitleBar,         // Titlebar text
                                     L0,               // Client style
                                     NULLHANDLE,       // Resource handle
                                     MAIN_ID,          // Frame ID
                                     NULL);            // Client handle
     WinShowWindow(hwndFrame, TRUE);       // Make the window visible
//-----------------------------------------------------------------------------
// Set icon
//-----------------------------------------------------------------------------
     hIcon = (HPOINTER)WinLoadPointer(HWND_DESKTOP, NULLHANDLE, ICON_ID);
     WinPostMsg(hwndFrame, WM_SETICON, (MPARAM)hIcon, L0);
//-----------------------------------------------------------------------------
// Message loop
//-----------------------------------------------------------------------------
     while (WinGetMsg (hab, &qmsg, L0, L0, L0)) WinDispatchMsg (hab, &qmsg);
//-----------------------------------------------------------------------------
// Clean up (destroy window, queue and hab)
//-----------------------------------------------------------------------------
     WinDestroyWindow (hwndFrame);
     WinDestroyMsgQueue (hmq);
     WinTerminate (hab);
#endif
     }

#ifndef DAEMON
//=============================================================================
// Window procedure
//=============================================================================
MRESULT EXPENTRY ClientWndProc (HWND hwnd, ULONG msg, MPARAM mp1, MPARAM mp2)
     {
     static HWND hwndButtonRun, hwndButtonBreak, hwndButtonHelp,
                 hwndButtonExit, hwndButtonARP, hwndButtonPing, hwndButtonOpt,
                 hwndStaticTxt, hwndFiction;
     static char Font[] = FontName;
     static int x, y;
     ULONG Post;
     struct in_addr IndClient;
     static char NETBmsg[L32] = "NETBEUI   ",
                 TCPBmsg[L32] = "TCPBEUI   ";

     switch (msg)
          {
//-----------------------------------------------------------------------------
// Fill client with default color
//-----------------------------------------------------------------------------
          case WM_ERASEBACKGROUND:
          return MRFROMSHORT(TRUE);
//-----------------------------------------------------------------------------
// WM_CREATE occurs only during creation
//-----------------------------------------------------------------------------
          case WM_CREATE:
               {
               HPS hps;
               long rgb_color;

               hwndFiction = WinCreateWindow(hwnd, WC_BUTTON, NULL,
                             BS_PUSHBUTTON | BS_DEFAULT,
                             L0,L0,L0,L0, hwnd, HWND_TOP, PB_FICTION, L0, L0);
               hwndButtonRun = WinCreateWindow(hwnd, WC_BUTTON, NULL,
                               WS_VISIBLE | BS_USERBUTTON | BS_NOBORDER,
                               L0,L0,L0,L0, hwnd, HWND_TOP, PB_RUN, L0, L0);
               hwndButtonBreak = WinCreateWindow(hwnd, WC_BUTTON, NULL,
                               WS_VISIBLE | BS_USERBUTTON | BS_NOBORDER,
                               L0,L0,L0,L0, hwnd, HWND_TOP, PB_BREAK, L0, L0);
               hwndButtonExit = WinCreateWindow(hwnd, WC_BUTTON, NULL,
                               WS_VISIBLE | BS_USERBUTTON | BS_NOBORDER,
                               L0,L0,L0,L0, hwnd, HWND_TOP, PB_EXIT, L0, L0);
               hwndButtonHelp = WinCreateWindow(hwnd, WC_BUTTON, NULL,
                               WS_VISIBLE | BS_USERBUTTON | BS_NOBORDER,
                               L0,L0,L0,L0, hwnd, HWND_TOP, PB_HELP, L0, L0);
               hwndButtonARP = WinCreateWindow(hwnd, WC_BUTTON, NULL,
                               WS_VISIBLE | BS_USERBUTTON | BS_NOBORDER,
                               L0,L0,L0,L0, hwnd, HWND_TOP, PB_ARP, L0, L0);
               hwndButtonPing = WinCreateWindow(hwnd, WC_BUTTON, NULL,
                               WS_VISIBLE | BS_USERBUTTON | BS_NOBORDER,
                               L0,L0,L0,L0, hwnd, HWND_TOP, PB_PING, L0, L0);
               hwndButtonOpt = WinCreateWindow(hwnd, WC_BUTTON, NULL,
                               WS_VISIBLE | BS_USERBUTTON | BS_NOBORDER,
                               L0,L0,L0,L0, hwnd, HWND_TOP, PB_OPT, L0, L0);
               hwndCntnr = WinCreateWindow(hwnd, WC_CONTAINER, NULL,
                               CCS_READONLY | CCS_SINGLESEL | WS_VISIBLE,
                               L0, L0, L0, L0,
                               hwnd, HWND_TOP, CONTAINER_ID, L0, L0);
               hwndStaticTxt = WinCreateWindow(hwnd, WC_STATIC, NULL,
                               WS_VISIBLE | SS_TEXT | DT_LEFT | DT_VCENTER,
                               L0, L0, L0, L0,
                               hwnd, HWND_TOP, STATIC_ID, L0, L0);
//-----------------------------------------------------------------------------
// Restore size & place from OS2.INI
//-----------------------------------------------------------------------------
     if ( !WinRestoreWindowPos(APPNAME, WINPOS,
                               WinQueryWindow(hwnd, QW_PARENT)) )
       WinSetWindowPos( WinQueryWindow(hwnd, QW_PARENT), HWND_TOP,
                        Win_X, Win_Y, Win_CX, Win_CY,
                        SWP_ACTIVATE | SWP_MOVE | SWP_SIZE | SWP_SHOW );
//-----------------------------------------------------------------------------
// Set Presentation Parameters
//-----------------------------------------------------------------------------
     // static text
     rgb_color = WinQuerySysColor(HWND_DESKTOP, SYSCLR_DIALOGBACKGROUND, L0);
     WinSetPresParam(hwndStaticTxt, PP_BACKGROUNDCOLOR, sizeof(RGB),
                     (PVOID)&rgb_color); // фон
     rgb_color = WinQuerySysColor(HWND_DESKTOP, SYSCLR_WINDOWTEXT, L0);
     WinSetPresParam(hwndStaticTxt, PP_FOREGROUNDCOLOR, sizeof(RGB),
                     (PVOID)&rgb_color); // текст

     // контейнер
     rgb_color = WinQuerySysColor(HWND_DESKTOP, SYSCLR_WINDOW, L0);
     WinSetPresParam(hwndCntnr, PP_BACKGROUNDCOLOR, sizeof(RGB),
                     (PVOID)&rgb_color); // фон
     rgb_color = WinQuerySysColor(HWND_DESKTOP, SYSCLR_WINDOWTEXT, L0);
     WinSetPresParam(hwndCntnr, PP_FOREGROUNDCOLOR, sizeof(RGB),
                     (PVOID)&rgb_color); // текст
     rgb_color = WinQuerySysColor(HWND_DESKTOP, SYSCLR_HILITEBACKGROUND, L0);
     WinSetPresParam(hwndCntnr, PP_HILITEBACKGROUNDCOLOR, sizeof(RGB),
                     (PVOID)&rgb_color); // фон выделенной строки
     rgb_color = WinQuerySysColor(HWND_DESKTOP, SYSCLR_HILITEFOREGROUND, L0);
     WinSetPresParam(hwndCntnr, PP_HILITEFOREGROUNDCOLOR, sizeof(RGB),
                     (PVOID)&rgb_color); // текст выделенной строки

     WinSetPresParam(hwnd, PP_FONTNAMESIZE, sizeof(Font), Font);
     WinSetPresParam(hwndCntnr,PP_FONTNAMESIZE,strlen(FontCntnr)+L1,FontCntnr);
//-----------------------------------------------------------------------------
// Загрузим bitmap'ы
//-----------------------------------------------------------------------------
               hps = WinGetPS(hwndButtonRun);
               hbmRun = GpiLoadBitmap(hps, NULLHANDLE,
                                      BMP_RUN, PB_CX, PB_CY);
               hbmRunDi = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_RUN_DI, PB_CX, PB_CY);
               hbmRunHi = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_RUN_HI, PB_CX, PB_CY);
               WinReleasePS(hps);

               hps = WinGetPS(hwndButtonBreak);
               hbmBreak = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_BREAK, PB_CX, PB_CY);
               hbmBreakDi = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_BREAK_DI, PB_CX, PB_CY);
               hbmBreakHi = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_BREAK_HI, PB_CX, PB_CY);
               WinReleasePS(hps);

               hps = WinGetPS(hwndButtonARP);
               hbmARP = GpiLoadBitmap(hps, NULLHANDLE,
                                      BMP_ARP, PB_CX, PB_CY);
               hbmARPDi = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_ARP_DI, PB_CX, PB_CY);
               hbmARPHi = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_ARP_HI, PB_CX, PB_CY);
               WinReleasePS(hps);

               hps = WinGetPS(hwndButtonPing);
               hbmPing = GpiLoadBitmap(hps, NULLHANDLE,
                                       BMP_PING, PB_CX, PB_CY);
               hbmPingDi = GpiLoadBitmap(hps, NULLHANDLE,
                                         BMP_PING_DI, PB_CX, PB_CY);
               hbmPingHi = GpiLoadBitmap(hps, NULLHANDLE,
                                         BMP_PING_HI, PB_CX, PB_CY);
               WinReleasePS(hps);

               hps = WinGetPS(hwndButtonOpt);
               hbmOpt = GpiLoadBitmap(hps, NULLHANDLE,
                                      BMP_OPT, PB_CX, PB_CY);
               hbmOptDi = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_OPT_DI, PB_CX, PB_CY);
               hbmOptHi = GpiLoadBitmap(hps, NULLHANDLE,
                                        BMP_OPT_HI, PB_CX, PB_CY);
               WinReleasePS(hps);

               hps = WinGetPS(hwndButtonHelp);
               hbmHelp = GpiLoadBitmap(hps, NULLHANDLE,
                                       BMP_HELP, PB_CX, PB_CY);
               hbmHelpHi = GpiLoadBitmap(hps, NULLHANDLE,
                                         BMP_HELP_HI, PB_CX, PB_CY);
               WinReleasePS(hps);

               hps = WinGetPS(hwndButtonExit);
               hbmExit = GpiLoadBitmap(hps, NULLHANDLE,
                                       BMP_EXIT, PB_CX, PB_CY);
               hbmExitHi = GpiLoadBitmap(hps, NULLHANDLE,
                                         BMP_EXIT_HI, PB_CX, PB_CY);
               WinReleasePS(hps);

               StartThreads(hwnd); // Create Semaphors and Threads
               break;
               }
//-----------------------------------------------------------------------------
// WM_SIZE occurs during every resize, size setting event
//-----------------------------------------------------------------------------
          case WM_SIZE:
               {
               x = SHORT1FROMMP(mp2);
               y = SHORT2FROMMP(mp2);

               x2Help = x-L2*PB_CX-L4;
               x2Help = ( x2Help > (L7*PB_CX) ) ? x2Help : L7*PB_CX;

               x2Exit = x-PB_CX-L2;
               x2Exit = ( x2Exit > (L8*PB_CX+L2) ) ? x2Exit : L8*PB_CX+L2;

               WinSetWindowPos(hwndFiction, HWND_TOP, L0, L0, L1, L1,
                               SWP_SIZE | SWP_MOVE);
               WinSetWindowPos(hwndButtonRun, HWND_TOP,
                               L2, y-PB_CY-L2, PB_CX, PB_CY,
                               SWP_SIZE | SWP_MOVE);
               WinSetWindowPos(hwndButtonBreak, HWND_TOP,
                               PB_CX+L4, y-PB_CY-L2, PB_CX, PB_CY,
                               SWP_SIZE | SWP_MOVE);
               WinSetWindowPos(hwndButtonARP, HWND_TOP,
                               L3*PB_CX, y-PB_CY-L2, PB_CX, PB_CY,
                               SWP_SIZE | SWP_MOVE);
               WinSetWindowPos(hwndButtonPing, HWND_TOP,
                               L4*PB_CX+L2, y-PB_CY-L2, PB_CX, PB_CY,
                               SWP_SIZE | SWP_MOVE);
               WinSetWindowPos(hwndButtonOpt, HWND_TOP,
                               L5*PB_CX+L4, y-PB_CY-L2, PB_CX, PB_CY,
                               SWP_SIZE | SWP_MOVE);
               WinSetWindowPos(hwndButtonHelp, HWND_TOP,
                               x2Help, y-PB_CY-L2, PB_CX, PB_CY,
                               SWP_SIZE | SWP_MOVE);
               WinSetWindowPos(hwndButtonExit, HWND_TOP,
                               x2Exit, y-PB_CY-L2, PB_CX, PB_CY,
                               SWP_SIZE | SWP_MOVE);
               WinSetWindowPos(hwndCntnr, HWND_TOP,
                               L0, Txt_Y, x, y-PB_CY-Txt_Y-L6,
                               SWP_SIZE | SWP_MOVE);

               WinSetWindowPos(hwndStaticTxt, HWND_TOP,
                               L0, L0, x, Txt_Y, SWP_SIZE | SWP_MOVE);

               WinSetFocus( HWND_DESKTOP, hwndCntnr );
               break;
               }
//-----------------------------------------------------------------------------
// Нарисуем горизонтальную линию для выделения контейнера
//-----------------------------------------------------------------------------
          case WM_PAINT:
               {
               HPS hps;    // presentation-space handle
               RECTL rctl = { 0 }; // update region

               hps = WinBeginPaint(hwnd, NULLHANDLE, NULL);
               rctl.xRight = x;
               rctl.yBottom = y-PB_CY-L6;
               rctl.yTop = rctl.yBottom + L2;
               WinFillRect(hps, &rctl, CLR_BLACK);

               rctl.yBottom = y-PB_CY-L4;
               rctl.yTop = rctl.yBottom + PB_CY + L4;
               WinFillRect(hps, &rctl, CLR_PALEGRAY);

               WinEndPaint(hps);
               return L0;
               }
//-----------------------------------------------------------------------------
// Save the window size and position on exit
//-----------------------------------------------------------------------------
          case WM_SAVEAPPLICATION:
               {
               CNRINFO cnri = { 0 };
               USHORT Len = sizeof(CNRINFO);
               char *pBfr;
//-----------------------------------------------------------------------------
// Check if window is minimized and restore to original size
//-----------------------------------------------------------------------------
               if ( WinQueryWindowULong(hwndFrame, QWL_STYLE) & WS_MINIMIZED )
                 WinSetWindowPos(hwndFrame, HWND_TOP, 0, 0, 0, 0, SWP_RESTORE);
//-----------------------------------------------------------------------------
// Store window information in OS2.INI
//-----------------------------------------------------------------------------
               WinStoreWindowPos( APPNAME, WINPOS,
                                  WinQueryWindow(hwnd, QW_PARENT) );
//-----------------------------------------------------------------------------
// Copy the Window position info from the OS2.INI into private INI file
//-----------------------------------------------------------------------------
               PrfQueryProfileSize(HINI_USERPROFILE, APPNAME, WINPOS, &ulSize);
               pBfr = calloc(ulSize, L1);
               PrfQueryProfileData( HINI_USERPROFILE, APPNAME, WINPOS,
                                    pBfr, &ulSize);
               PrfWriteProfileData(HINI_USERPROFILE, APPNAME, NULL, NULL, L0);
               hini = PrfOpenProfile(hab, INIname); // Open private profile
               PrfWriteProfileData(hini, APPNAME, WINPOS, pBfr, ulSize);
               free(pBfr);

               if ( NewNBact ) // сохраним позицию вертикального разделителя
                 {
                 WinSendMsg(hwndCntnr,CM_QUERYCNRINFO,&cnri,MPFROMSHORT(Len));
                 PrfWriteProfileData(hini, APPNAME, VERTSPLITBAR,
                                     &cnri.xVertSplitbar,
                                     sizeof(cnri.xVertSplitbar));
                 }
               if ( !FontSetFl ) // Фонт был изменен, сохраним его
                 {
                 PrfWriteProfileData(hini, APPNAME, INITFONT,
                                     &pfdFontdlg, sizeof(FONTDLG));
                 PrfWriteProfileData(hini, APPNAME, INITFONTNAME,
                                     InitFont, strlen(InitFont)+L1);
                 }
               PrfCloseProfile(hini);   // Close private profile
               break;
               }
//-----------------------------------------------------------------------------
// Формирование строки завершено
//-----------------------------------------------------------------------------
          case WM_USER_LINE_DONE:
               {
               InsertRecord( LONGFROMMP(mp1), SHORT1FROMMP(mp2) );
               break;
               }
//-----------------------------------------------------------------------------
// Сканирование начато
//-----------------------------------------------------------------------------
          case WM_USER_SCAN_START:
            {
            WinEnableWindow(hwndButtonRun,   FALSE);
            WinEnableWindow(hwndButtonARP,   FALSE);
            WinEnableWindow(hwndButtonPing,  FALSE);
            WinEnableWindow(hwndButtonOpt,   FALSE);
            WinEnableWindow(hwndButtonBreak, TRUE);

            WinPostMsg( hwndCntnr, CM_REMOVERECORD, NULL,
                        MPFROM2SHORT(L0, CMA_FREE | CMA_INVALIDATE) );
            WinPostMsg( hwndCntnr, CM_REMOVEDETAILFIELDINFO, NULL,
                        MPFROM2SHORT(L0, CMA_FREE | CMA_INVALIDATE) );

            InitContainer( NewNBact || NewNBactP );
            DosPostEventSem(hevEventStart);
            WinSetFocus( HWND_DESKTOP, hwndCntnr );
            break;
            }
//-----------------------------------------------------------------------------
// Сканирование завершено
//-----------------------------------------------------------------------------
          case WM_USER_SCAN_DONE:
            {
            WinSetWindowText(hwndStaticTxt, "");
            WinEnableWindow(hwndButtonRun,   TRUE);
            WinEnableWindow(hwndButtonOpt,   TRUE);
            WinEnableWindow(hwndButtonARP,   TRUE);
            WinEnableWindow(hwndButtonPing,  TRUE);
            WinEnableWindow(hwndButtonBreak, FALSE);
            WinSetPointer( HWND_DESKTOP,
                           WinQuerySysPointer(HWND_DESKTOP,SPTR_ARROW,FALSE) );
            WinInvalidateRegion(hwndCntnr, NULLHANDLE, TRUE); // обновим окно
            break;
            }
//-----------------------------------------------------------------------------
// Выполняем запрос Net32GetDCName
//-----------------------------------------------------------------------------
          case WM_USER_NET32DCN:
               {
               static char NET32DCNmsg[L32] = "Net32GetDCName ";

               strcpy(NET32DCNmsg+L15, PVOIDFROMMP(mp1));
               WinSetWindowText(hwndStaticTxt, NET32DCNmsg);
               break;
               }
//-----------------------------------------------------------------------------
// Выполняем запрос Net32ServerEnum2
//-----------------------------------------------------------------------------
          case WM_USER_NET32SE2:
               {
               static char NET32SE2msg[L32] = "Net32ServerEnum2 ";

               strcpy(NET32SE2msg+L17, PVOIDFROMMP(mp1));
               WinSetWindowText(hwndStaticTxt, NET32SE2msg);
               break;
               }
//-----------------------------------------------------------------------------
// Выполняем запрос ARP
//-----------------------------------------------------------------------------
          case WM_USER_ARP:
               {
               static char ARPmsg[L24] = "ARP ";

               IndClient.s_addr = LONGFROMMP(mp1);
               strcpy(ARPmsg+L4, inet_ntoa(IndClient));
               WinSetWindowText(hwndStaticTxt, ARPmsg);
               break;
               }
//-----------------------------------------------------------------------------
// Выполняем запрос DNS
//-----------------------------------------------------------------------------
          case WM_USER_DNS:
               {
               static char DNSmsg[L24] = "DNS ";

               IndClient.s_addr = LONGFROMMP(mp1);
               strcpy(DNSmsg+L4, inet_ntoa(IndClient));
               WinSetWindowText(hwndStaticTxt, DNSmsg);
               break;
               }
//-----------------------------------------------------------------------------
// Выполняем запрос PING
//-----------------------------------------------------------------------------
          case WM_USER_PING:
               {
               static char PINGmsg[L24] = "PING ";

               IndClient.s_addr = htonl(LONGFROMMP(mp1));
               strcpy(PINGmsg+L5, inet_ntoa(IndClient));
               WinSetWindowText(hwndStaticTxt, PINGmsg);
               break;
               }
//-----------------------------------------------------------------------------
// Выполняем запрос TCPBEUI
//-----------------------------------------------------------------------------
          case WM_USER_TCPBEUI:
               {
               strcpy( TCPBmsg+L10, pB+LONGFROMMP(mp1)*(UNCLEN-1) );
               WinSetWindowText(hwndStaticTxt, TCPBmsg);
               break;
               }
          case WM_USER_SMBNAME:
               {
               static char SMBmsg[L32]  = "SMBNAME   ";

               IndClient.s_addr = LONGFROMMP(mp1);
               strcpy( SMBmsg+L10, inet_ntoa(IndClient));
               WinSetWindowText(hwndStaticTxt, SMBmsg);
               break;
               }
          case WM_USER_SESTBEUI:
               {
               struct session_info_0 *session_i_0;

               session_i_0 = (struct session_info_0 *)pSes;
               strcpy(TCPBmsg+L10, (session_i_0+LONGFROMMP(mp1))->sesi0_cname);
               WinSetWindowText(hwndStaticTxt, TCPBmsg);
               break;
               }
//-----------------------------------------------------------------------------
// Выполняем запрос NETBEUI
//-----------------------------------------------------------------------------
          case WM_USER_NETBEUI:
               {
               strcpy( NETBmsg+L10, pB+LONGFROMMP(mp1)*(UNCLEN-1) );
               WinSetWindowText(hwndStaticTxt, NETBmsg);
               break;
               }
          case WM_USER_SESNBEUI:
               {
               struct session_info_0 *session_i_0;

               session_i_0 = (struct session_info_0 *)pSes;
               strcpy(NETBmsg+L10, (session_i_0+LONGFROMMP(mp1))->sesi0_cname);
               WinSetWindowText(hwndStaticTxt, NETBmsg);
               break;
               }
//-----------------------------------------------------------------------------
// Обработка мышки
//-----------------------------------------------------------------------------
          case WM_CONTROL:
            {
            switch (SHORT2FROMMP(mp1))
              {
              case CN_ENTER:
                {
                UCHAR LoadError[CCHMAXPATH] = { 0 };
                RESULTCODES ChieldRC = { 0 };
                char CmdLine[32];

                Selected = (PNOTIFYRECORDENTER)mp2;
                if ( Selected->pRecord->pszIcon[0] == '-' ) break;
                memset(CmdLine, '\0', sizeof(CmdLine));

#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
                sprintf(CmdLine, "PortScan.exe%c%s", '\0',
                                 Selected->pRecord->pszIcon);
#else                // Включить для TCP/IP 4.0
                sprintf(CmdLine, "PortScn4.exe%c%s", '\0',
                                 Selected->pRecord->pszIcon);
#endif               // TCPV40HDRS

                DosExecPgm( LoadError, sizeof(LoadError), EXEC_ASYNC, CmdLine,
                            (PSZ)NULL, &ChieldRC, CmdLine );
                break;
                }
//-----------------------------------------------------------------------------
// Обработка кнопки
//-----------------------------------------------------------------------------
              case BN_PAINT:
                {
                if ( SHORT1FROMMP(mp1) == PB_RUN )
                  if ( ((PUSERBUTTON)mp2)->fsState & BDS_DISABLED )
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmRunDi, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);
                  else
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmRun, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);

                if ( SHORT1FROMMP(mp1) == PB_BREAK )
                  if ( ((PUSERBUTTON)mp2)->fsState & BDS_DISABLED )
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmBreakDi, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);
                  else
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmBreak, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);

                if ( SHORT1FROMMP(mp1) == PB_ARP )
                  if ( ((PUSERBUTTON)mp2)->fsState & BDS_DISABLED )
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmARPDi, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);
                  else
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmARP, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);

                if ( SHORT1FROMMP(mp1) == PB_PING )
                  if ( ((PUSERBUTTON)mp2)->fsState & BDS_DISABLED )
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmPingDi, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);
                  else
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmPing, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);

                if ( SHORT1FROMMP(mp1) == PB_OPT )
                  if ( ((PUSERBUTTON)mp2)->fsState & BDS_DISABLED )
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmOptDi, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);
                  else
                    WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmOpt, NULL,
                                  (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);

                if ( SHORT1FROMMP(mp1) == PB_HELP )
                  WinDrawBitmap(((PUSERBUTTON)mp2)->hps, hbmHelp, NULL,
                                (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);

                if ( SHORT1FROMMP(mp1) == PB_EXIT )
                  WinDrawBitmap(((PUSERBUTTON) mp2)->hps, hbmExit, NULL,
                                (PPOINTL)&rclButton, L0, L0, DBM_NORMAL);

                break;
                }
              }
            break;
            }
//-----------------------------------------------------------------------------
// Обработка меню
//-----------------------------------------------------------------------------
          case WM_INITMENU:
               {
               switch (SHORT1FROMMP(mp1))
                    {
                    case SUBMENU_FILE:
                         {
                         DosQueryEventSem( hevEventHandle, &Post );
                         WinEnableMenuItem((HWND)mp2, ITEM_RUN,    Post == L0);
                         WinEnableMenuItem((HWND)mp2, ITEM_BREAK,  Post != L0);
                         WinEnableMenuItem((HWND)mp2, ITEM_SAVE  , Post == L0);
                         WinEnableMenuItem((HWND)mp2, ITEM_SAVEAS, Post == L0);
                         break;
                         }
                    case SUBMENU_OPTIONS:
                         {
                         DosQueryEventSem( hevEventHandle, &Post );
                         WinEnableMenuItem((HWND)mp2,ITEM_ARP, Post == L0);
                         WinEnableMenuItem((HWND)mp2,ITEM_PING, Post == L0);
                         WinEnableMenuItem((HWND)mp2,ITEM_SET_OPT, Post == L0);
                         break;
                         }
                    }
               }
          break;
//-----------------------------------------------------------------------------
// Обработка мышки
//-----------------------------------------------------------------------------
          case WM_CONTROLPOINTER:
               {
               HPS hps = L0;
               long KeyState;
               static int PromptId = L0;
               unsigned int idCtl = SHORT1FROMMP(mp1);

               KeyState = WinGetKeyState(HWND_DESKTOP, VK_BUTTON1);

               if ( (PromptFlag && (PromptId != idCtl)) ||
                    (KeyState & KEY_PRESSED) )
                 {
                 RECTL rcl;
                 HPS hps;

                 rcl.xLeft = L0;
                 rcl.xRight = x;
                 rcl.yBottom = y-PB_CY-L2;
                 rcl.yTop = rcl.yBottom+P_CY;
                 WinInvalidateRect(hwnd, &rcl, TRUE);
                 PromptFlag = FALSE;

                 // Вернем ранее подсвеченную кнопку в актуальное состояние
                 hps = WinGetPS(hwndButton);
                 if ( WinIsWindowEnabled(hwndButton) )
                   WinDrawBitmap(hps, hbmN, NULL, (PPOINTL)&rclButton,
                                 L0, L0, DBM_NORMAL);
                 else
                   WinDrawBitmap(hps, hbmD, NULL, (PPOINTL)&rclButton,
                                 L0, L0, DBM_NORMAL);
                 WinReleasePS(hps);
                 }

               switch (idCtl)
                 {
                 case PB_RUN:
                   {
                   if ( WinIsWindowEnabled(hwndButtonRun) &&
                        !(KeyState & KEY_PRESSED) )
                     {
                     hps = WinGetPS(hwndButtonRun);
                     WinDrawBitmap(hps, hbmRunHi, NULL, (PPOINTL)&rclButton,
                                   L0, L0, DBM_NORMAL);
                     WinDrawBorder(hps, &rclButton, L1, L1,
                                   CLR_BLACK, CLR_BLACK, DB_STANDARD);
                     hwndButton = hwndButtonRun;
                     hbmN = hbmRun;
                     hbmD = hbmRunDi;
                     WinReleasePS(hps);
                     }
                   ShowPrompt(hwnd, L2+PB_CX, y-PB_CY-L2, TRUE, "~Run");
                   PromptFlag = TRUE;
                   break;
                   }
                 case PB_BREAK:
                   {
                   if ( WinIsWindowEnabled(hwndButtonBreak) &&
                        !(KeyState & KEY_PRESSED) )
                     {
                     hps = WinGetPS(hwndButtonBreak);
                     WinDrawBitmap(hps, hbmBreakHi, NULL, (PPOINTL)&rclButton,
                                   L0, L0, DBM_NORMAL);
                     WinDrawBorder(hps, &rclButton, L1, L1,
                                   CLR_BLACK, CLR_BLACK, DB_STANDARD);
                     hwndButton = hwndButtonBreak;
                     hbmN = hbmBreak;
                     hbmD = hbmBreakDi;
                     WinReleasePS(hps);
                     }
                   ShowPrompt(hwnd, L2*PB_CX+L4, y-PB_CY-L2, TRUE, "~Break");
                   PromptFlag = TRUE;
                   break;
                   }
                 case PB_ARP:
                   {
                   if ( WinIsWindowEnabled(hwndButtonARP) &&
                        !(KeyState & KEY_PRESSED) )
                     {
                     hps = WinGetPS(hwndButtonARP);
                     WinDrawBitmap(hps, hbmARPHi, NULL, (PPOINTL)&rclButton,
                                   L0, L0, DBM_NORMAL);
                     WinDrawBorder(hps, &rclButton, L1, L1,
                                   CLR_BLACK, CLR_BLACK, DB_STANDARD);
                     hwndButton = hwndButtonARP;
                     hbmN = hbmARP;
                     hbmD = hbmARPDi;
                     WinReleasePS(hps);
                     }
                   ShowPrompt(hwnd, L4*PB_CX, y-PB_CY-L2, TRUE, "~ARP");
                   PromptFlag = TRUE;
                   break;
                   }
                 case PB_PING:
                   {
                   if ( WinIsWindowEnabled(hwndButtonPing) &&
                        !(KeyState & KEY_PRESSED) )
                     {
                     hps = WinGetPS(hwndButtonPing);
                     WinDrawBitmap(hps, hbmPingHi, NULL, (PPOINTL)&rclButton,
                                   L0, L0, DBM_NORMAL);
                     WinDrawBorder(hps, &rclButton, L1, L1,
                                   CLR_BLACK, CLR_BLACK, DB_STANDARD);
                     hwndButton = hwndButtonPing;
                     hbmN = hbmPing;
                     hbmD = hbmPingDi;
                     WinReleasePS(hps);
                     }
                   ShowPrompt(hwnd, L5*PB_CX+L2, y-PB_CY-L2, TRUE, "~Ping");
                   PromptFlag = TRUE;
                   break;
                   }
                 case PB_OPT:
                   {
                   if ( WinIsWindowEnabled(hwndButtonOpt) &&
                        !(KeyState & KEY_PRESSED) )
                     {
                     hps = WinGetPS(hwndButtonOpt);
                     WinDrawBitmap(hps, hbmOptHi, NULL, (PPOINTL)&rclButton,
                                   L0, L0, DBM_NORMAL);
                     WinDrawBorder(hps, &rclButton, L1, L1,
                                   CLR_BLACK, CLR_BLACK, DB_STANDARD);
                     hwndButton = hwndButtonOpt;
                     hbmN = hbmOpt;
                     hbmD = hbmOptDi;
                     WinReleasePS(hps);
                     }
                   ShowPrompt(hwnd, L6*PB_CX+L4, y-PB_CY-L2, TRUE,
                              "~Configuration");
                   PromptFlag = TRUE;
                   break;
                   }
                 case PB_HELP:
                   {
                   if ( WinIsWindowEnabled(hwndButtonHelp) &&
                        !(KeyState & KEY_PRESSED) )
                     {
                     hps = WinGetPS(hwndButtonHelp);
                     WinDrawBitmap(hps, hbmHelpHi, NULL, (PPOINTL)&rclButton,
                                   L0, L0, DBM_NORMAL);
                     WinDrawBorder(hps, &rclButton, L1, L1,
                                   CLR_BLACK, CLR_BLACK, DB_STANDARD);
                     hwndButton = hwndButtonHelp;
                     hbmN = hbmHelp;
                     hbmD = hbmHelp;
                     WinReleasePS(hps);
                     }
                   ShowPrompt(hwnd, x2Help, y-PB_CY-L2, FALSE, "~Information");
                   PromptFlag = TRUE;
                   break;
                   }
                 case PB_EXIT:
                   {
                   if ( WinIsWindowEnabled(hwndButtonExit) &&
                        !(KeyState & KEY_PRESSED) )
                     {
                     hps = WinGetPS(hwndButtonExit);
                     WinDrawBitmap(hps, hbmExitHi, NULL, (PPOINTL)&rclButton,
                                   L0, L0, DBM_NORMAL);
                     WinDrawBorder(hps, &rclButton, L1, L1,
                                   CLR_BLACK, CLR_BLACK, DB_STANDARD);
                     hwndButton = hwndButtonExit;
                     hbmN = hbmExit;
                     hbmD = hbmExit;
                     WinReleasePS(hps);
                     }
                   ShowPrompt(hwnd, x2Exit, y-PB_CY-L2, FALSE, "~Exit");
                   PromptFlag = TRUE;
                   break;
                   }
                 }
               PromptId = idCtl;

               if ( (idCtl != PB_RUN) && (idCtl != PB_OPT) &&
                    (idCtl != PB_ARP) && (idCtl != PB_PING) &&
                    (idCtl != CONTAINER_ID) && (idCtl != STATIC_ID) ) break;
               }
//-----------------------------------------------------------------------------
// Изменим при необходимости вид курсора
//-----------------------------------------------------------------------------
          case WM_MOUSEMOVE:
               {
               if ( (msg == WM_MOUSEMOVE) && PromptFlag )
                 {
                 RECTL rcl;
                 HPS hps;

                 rcl.xLeft = L0;
                 rcl.xRight = x;
                 rcl.yBottom = y-PB_CY-L2;
                 rcl.yTop = rcl.yBottom+P_CY;
                 WinInvalidateRect(hwnd, &rcl, TRUE);
                 PromptFlag = FALSE;

                 // Вернем ранее подсвеченную кнопку в актуальное состояние
                 hps = WinGetPS(hwndButton);
                 if ( WinIsWindowEnabled(hwndButton) )
                   WinDrawBitmap(hps, hbmN, NULL, (PPOINTL)&rclButton,
                                 L0, L0, DBM_NORMAL);
                 else
                   WinDrawBitmap(hps, hbmD, NULL, (PPOINTL)&rclButton,
                                 L0, L0, DBM_NORMAL);
                 WinReleasePS(hps);
                 }

               DosQueryEventSem(hevEventHandle, &Post);
               WinSetPointer( HWND_DESKTOP,
                              WinQuerySysPointer(HWND_DESKTOP,
                                                 Post ? SPTR_WAIT : SPTR_ARROW,
                                                 FALSE) );
               return (MRESULT) TRUE;
               }
//-----------------------------------------------------------------------------
// Handling of the menu-items and the button by WM_COMMAND
//-----------------------------------------------------------------------------
          case WM_COMMAND:
               {
               switch(SHORT1FROMMP(mp1))
                    {
//-----------------------------------------------------------------------------
// Close the dialog
//-----------------------------------------------------------------------------
                    case PB_EXIT:
                    case ITEM_EXIT:
                         {
                         WinEnableWindow(hwndButtonExit, FALSE);
                         WinPostMsg(hwnd, WM_CLOSE, L0, L0);
                         break;
                         }
//-----------------------------------------------------------------------------
// Прервем сканирование
//-----------------------------------------------------------------------------
                    case PB_BREAK:
                    case ITEM_BREAK:
                         {
                         flagRun = FALSE;
                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Изменим опции
//-----------------------------------------------------------------------------
                    case PB_OPT:
                    case ITEM_SET_OPT:
                         {
                         if ( flagSet ) break;
                         WinEnableWindow(hwndButtonOpt, FALSE);
                         flagSet = TRUE;

                         WinDlgBox (HWND_DESKTOP, hwnd, DlgProcOPT,
                                    NULLHANDLE, OPTIONS_ID, L0);
                         if ( AutoRun ) DosAsyncTimer((ULONG)Interval*60000L,
                                                      (HSEM)hevEventHandle,
                                                      &phtimer);
                         else DosStopTimer(phtimer);   // Остановим таймер
                         flagSet = FALSE;
                         WinEnableWindow(hwndButtonOpt, TRUE);
                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Вывести Help
//-----------------------------------------------------------------------------
                    case PB_HELP:
                    case ITEM_GENERAL_HELP:
                         {
                         UCHAR LoadError[CCHMAXPATH] = { 0 };
                         RESULTCODES ChieldRC = { 0 };
                         char CommandLine[] = "view.exe\0LanScan.Inf\0";

                         WinEnableWindow(hwndButtonHelp, FALSE);
                         DosExecPgm( LoadError, sizeof(LoadError), EXEC_ASYNC,
                                     CommandLine, (PSZ)NULL, &ChieldRC,
                                     CommandLine );
                         WinEnableWindow(hwndButtonHelp, TRUE);
                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Рассказать о себе
//-----------------------------------------------------------------------------
                    case ITEM_ABOUT:
                         {
                         WinDlgBox( HWND_DESKTOP, hwnd, WinDefDlgProc,
                                    NULLHANDLE, ABOUT_ID, L0 );
                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Выполнить сохранение результатов сканирования
//-----------------------------------------------------------------------------
                    case ITEM_SAVEAS:
                         {
                         if ( !GetFileName(szFullPath) )
                           {
                           WinSetFocus( HWND_DESKTOP, hwndCntnr );
                           break;
                           }
                         }
                    case ITEM_SAVE:
                         {
                         if ( szFullPath[0] != '\0' )
                           DoSave(szFullPath, "a", OldFormat);
                         else
                           if ( GetFileName(szFullPath) )
                             DoSave(szFullPath, "a", OldFormat);

                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Установить диапазон адресов для PING
//-----------------------------------------------------------------------------
                    case PB_PING:
                    case ITEM_PING:
                         {
                         if ( flagSet ) break;
                         WinEnableWindow(hwndButtonPing, FALSE);
                         flagSet = TRUE;

                         WinDlgBox (HWND_DESKTOP, hwnd, DlgProcPING,
                                    NULLHANDLE, PING_ID, L0);

                         flagSet = FALSE;
                         WinEnableWindow(hwndButtonPing, TRUE);
                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Установить диапазон адресов для ARP
//-----------------------------------------------------------------------------
                    case PB_ARP:
                    case ITEM_ARP:
                         {
                         if ( flagSet ) break;
                         WinEnableWindow(hwndButtonARP, FALSE);
                         flagSet = TRUE;

                         WinDlgBox (HWND_DESKTOP, hwnd, DlgProcARP,
                                    NULLHANDLE, ARP_ID, L0);

                         flagSet = FALSE;
                         WinEnableWindow(hwndButtonARP, TRUE);
                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Выполнить сканирование
//-----------------------------------------------------------------------------
                    case PB_RUN:
                    case ITEM_RUN:
                         {
                         DosQueryEventSem( hevEventHandle, &Post );
                         if ( Post == L0 ) DosPostEventSem(hevEventHandle);
                         break;
                         }
                    }
               }
          break;
          }
     return (WinDefWindowProc (hwnd,msg,mp1,mp2));
     }
#endif
//=============================================================================
// DoScan - подпрограмма сканирования сети
//=============================================================================
#ifndef DAEMON
void APIENTRY DoScan(ULONG parmHwnd)
#else
void APIENTRY DoScan()
#endif
{
FILE *FileMap;
struct servent *WINSprot;
int i, j, k, l, m, NumNBN, NumNBNn, sock, resi, preCurrNum, currBase, ind,
    i1, j1;
unsigned long num, FirstNotMe = L0, preFirstNotMe = L0,
              numMax[MAXIPADR], Mask[MAXIPADR];
struct arpreq myarp = { L0 };
char ReverseMAC[L6], *pp, BufDNname[DNLEN], *tptr, Record[MAPLEN],
     preMAC[MACLEN], preIP[IPLEN], currMAC[MACLEN], *oldMAC, *oldIP;
short currStatus = L0;
time_t ltime;
BOOL ExistMAC = FALSE;
#ifdef DAEMON
char temp[L32];
#endif

  DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L15, L0);
  oldMAC = NULL;
  oldIP = NULL;

for (;;)
   {
   DosWaitEventSem(hevEventHandle, SEM_INDEFINITE_WAIT);
   DosStopTimer(phtimer);   // Остановим таймер
   if ( flagSet )
     {
     DosResetEventSem( hevEventHandle, &ulPostCnt);
     if ( AutoRun ) DosAsyncTimer( (ULONG)Interval*60000L,
                                   (HSEM)hevEventHandle, &phtimer );
     continue;
     }
//-----------------------------------------------------------------------------
// Выполнить подготовку окна к сканированию
//-----------------------------------------------------------------------------
#ifndef DAEMON
   DosResetEventSem( hevEventStart, &ulPostStart);
#endif
   NewNBact = NBact;
   NewNBactP = NBactP;
   if ( NewNBact ) FormNCB();
   if ( NewNBact || NewNBactP ) NBresult = TestBEUI();
   SetTitle(NBresult);
#ifndef DAEMON
   WinPostMsg (parmHwnd, WM_USER_SCAN_START, L0, L0);
   DosWaitEventSem(hevEventStart, SEM_INDEFINITE_WAIT);
#endif
//-----------------------------------------------------------------------------
// Начнем сканирование
//-----------------------------------------------------------------------------
   time(&ltime);
   timeptr=localtime(&ltime);
#ifdef DAEMON
   strftime(temp, sizeof(temp)-1, "%d/%m/%Y %T", timeptr);
   printf("Scan started - %s\n", temp);
#endif
   if ( oldMAC != NULL )
     {
     free(oldMAC);
     free(oldIP);
     oldMAC = NULL;
     oldIP = NULL;
     }

   currBase = BaseInd;

   preCurrNum = CurrNum;
   preFirstNotMe = FirstNotMe;

   if ( currBase == BaseMap )
     {
//-----------------------------------------------------------------------------
// Сформируем массив "План сети"
//-----------------------------------------------------------------------------
     preFirstNotMe = L0;
     preCurrNum = L0;
     if ( (FileMap = fopen("LanScan.Map", "r")) != NULL )
       {
       for (i1=L0; fgets(Record, MAPLEN, FileMap) != NULL; ) i1++;
       if ( i1 != L0 )
         {
         oldIP = calloc(IPLEN*i1, L1);
         oldMAC = calloc(MACLEN*i1, L1);
         rewind(FileMap);

         for (ind=L0; ind<i1; ind++)
           {
           fgets(Record, MAPLEN, FileMap);
           if ( strlen(Record) > L0 )
             if ( Record[strlen(Record)-1] == '\x0a' )
               Record[strlen(Record)-1] = '\0';
           for ( j1=L22; j1<strlen(Record); j1++)
             if ( Record[j1] == ' ' )
               {
               Record[j1] = '\0';
               break;
               }
           if ( (strlen(Record) < L22) || (strlen(Record) > L40) ) continue;
           memcpy(oldMAC+MACLEN*preCurrNum, Record, MACLEN-L1);
           strcpy(oldIP+IPLEN*preCurrNum, Record+L15);
           preCurrNum++;
           }
         }
       fclose(FileMap);
       }
     }
//-----------------------------------------------------------------------------
   if ( ( currBase == BaseLS ) && ( preCurrNum != L0 ) )
     {
     oldIP = calloc(IPLEN*preCurrNum, L1);
     oldMAC = calloc(MACLEN*preCurrNum, L1);
     for (i1=L0, j1=L0; j1<preCurrNum; j1++)
       {
       if ((StatusIP[j1]==TxtDel-TxtExist)||(StatusIP[j1]==TxtRepl-TxtExist))
         continue;
       if ( *(MACfirst+j1*MACLEN) == '\0' ) continue; // Пропустим инфо от PING
       memcpy(oldIP+i1*IPLEN, IPfirst+j1*IPLEN, IPLEN);
       memcpy(oldMAC+i1*MACLEN, MACfirst+j1*MACLEN, MACLEN);
       i1++;
       }
     preCurrNum = i1;
     }
//-----------------------------------------------------------------------------
   CurrNum = L0;
   for ( i=L0; i<MAXIPADR; i++ )
     {
     numMax[i] = ~AddrInfoIP[i].mask;
     Mask[i] = htonl(AddrInfoIP[i].mask);
     }

   IP=IPfirst;
   MAC=MACfirst;
   FQDN=FQDNfirst;
   NB=NBfirst;
   NBIP=NBIPfirst;
   NETBN=NETBNfirst;
   MACNB=MACNBfirst;

   memset(IPfirst, '\0', IPLEN*NUMADR);
   memset(MACfirst, '\0', MACLEN*NUMADR);
   memset(FQDNfirst, '\0', FQDNLEN*NUMADR);
   memset(NETBNfirst, '\0', UNCLEN*NUMADR);
   memset(NBfirst, '\0', UNCLEN*L254);
   memset(NBIPfirst, '\0', IPLEN*L254);
   memset(MACNBfirst, '\0', MACLEN*L254);

   memset(preMAC, '\0', sizeof(preMAC));
   memset(currMAC, '\0', sizeof(currMAC));
   memset(StatusIP, '\0', sizeof(short)*NUMADR);

   sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
   if ( (WINSprot = getservbyname("netbios-ns", "udp")) == NULL  )
     for ( i=L0; i<NumIPadr; i++) sin[i].sin_port = htons(NETBIOS_NS);
   else
     for ( i=L0; i<NumIPadr; i++) sin[i].sin_port = WINSprot->s_port;
//-----------------------------------------------------------------------------
// Get all interface addresses
//-----------------------------------------------------------------------------
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
   os2_ioctl(sock, SIOSTATAT, (char *)buf, sizeof(buf));
#else                // Включить для TCP/IP 4.0
   ioctl(sock, SIOSTATAT, (char *)buf, sizeof(buf));
#endif               // TCPV40HDRS
   for ( i=L0, AdrInfo=(struct statatreq *)&buf[L2]; i < *pi;
         i++, AdrInfo++,
         IP += IPLEN, MAC += MACLEN, FQDN += FQDNLEN, NETBN += UNCLEN )
     {
     inadr = (struct in_addr *)AdrInfo;
     strcpy(IP, inet_ntoa(*inadr));
#ifndef DAEMON
     CNI = NumOUI;
#endif
     if ( (l=AdrInfo->interface) < MAXIPADR )
       {
       sprintf( MAC, "%2.2x%2.2x-%2.2x%2.2x-%2.2x%2.2x",
                MyMAC[l*L6],   MyMAC[l*L6+L1], MyMAC[l*L6+L2],
                MyMAC[l*L6+L3], MyMAC[l*L6+L4], MyMAC[l*L6+L5] );
#ifndef DAEMON
       CNI = FindOUI();
#endif
       }

#ifdef DAEMON
     GetIPname((char *)inadr, inadr->s_addr);
#else
     GetIPname(parmHwnd, (char *)inadr, inadr->s_addr);
     WinPostMsg ( parmHwnd, WM_USER_LINE_DONE,
                  MPFROMLONG(CurrNum), MPFROM2SHORT(CNI, L0) );
#endif
     CurrNum++;
     }
   FirstNotMe = CurrNum;
//-----------------------------------------------------------------------------
// Сканируем по TCPBEUI и NETBEUI
//-----------------------------------------------------------------------------
   NumNBN, NumNBNn = L0;
   if ( NBresult )
     {
#ifndef DAEMON
     ulEntriesRead = GetNBnames(parmHwnd, pWkInf->wki1_logon_domain, L0);
#else
     ulEntriesRead = GetNBnames(pWkInf->wki1_logon_domain, L0);
#endif

     if ( useOTHD && (strlen(pWkInf->wki1_oth_domains)!= 0) )
       {
       for ( pp=pWkInf->wki1_oth_domains; ; pp=ptr+1 )
         {
         memset(BufDNname, '\0', sizeof(BufDNname));
         if ( (ptr=strchr(pp, ' ')) != NULL )
           {
           strncpy(BufDNname, pp, ptr-pp);
           if (strcmp(pWkInf->wki1_logon_domain, BufDNname) == L0 ) continue;
#ifndef DAEMON
           ulEntriesRead += GetNBnames(parmHwnd, BufDNname, ulEntriesRead);
#else
           ulEntriesRead += GetNBnames(BufDNname, ulEntriesRead);
#endif
           continue;
           }
         else
           {
           if (strcmp(pWkInf->wki1_logon_domain, pp) == L0 ) break;
#ifndef DAEMON
           ulEntriesRead += GetNBnames(parmHwnd, pp, ulEntriesRead);
#else
           ulEntriesRead += GetNBnames(pp, ulEntriesRead);
#endif
           break;
           }
         }
       }

     if ( ulEntriesRead != L0 )
       {
#ifndef DAEMON
       NumNBN = TCPBEUIscan(parmHwnd);
       NumNBNn = NETBEUIscan(parmHwnd, NumNBN);
#else
       NumNBN = TCPBEUIscan();
       NumNBNn = NETBEUIscan(NumNBN);
#endif
       }
     }
//-----------------------------------------------------------------------------
// Сканируем путем работы с кэшем ARP
//-----------------------------------------------------------------------------
   for ( k=L0; flagRun && (k<NumIPadr); k++ )
     {
//-----------------------------------------------------------------------------
// Выведем разделитель перед сканированием новой сети
//-----------------------------------------------------------------------------
     strcpy(IP, LineSep);
     strcpy(MAC, LineSep);
     strcpy(FQDN, LineSep);

     IP += IPLEN;
     MAC += MACLEN;
     FQDN += FQDNLEN;
     NETBN += UNCLEN;
#ifndef DAEMON
     WinPostMsg ( parmHwnd, WM_USER_LINE_DONE,
                  MPFROMLONG(CurrNum), MPFROM2SHORT(NumOUI, L0) );
#endif
     CurrNum++;
     if ( Interv[k] == L0 )
       {
       HostInt[k].start[Interv[k]] = L1;
       HostInt[k].stop[Interv[k]]  = numMax[k]-L1;
       Interv[k] = L1;
       }

     for ( m=L0; flagRun && (m<Interv[k]); m++ )
       {
       for ( num = HostInt[k].start[m];
             flagRun && (num <= HostInt[k].stop[m]) & (CurrNum < NUMADR);
             num++ )
         {
         *paddr[k] &= Mask[k];
         *paddr[k] |= htonl(num);
         memset( &myarp, L0, sizeof(myarp) );
         memcpy( &myarp.arp_pa, &sin[k], sizeof(myarp.arp_pa) );
         ptr = &myarp.arp_ha.sa_data[L0];

         ExistMAC = FALSE;
         if ( currBase == BaseARP ) // Используем кэш ARP
           {
#ifdef TCPV40HDRS    // Включить для TCP/IP 4.0
           if ( ioctl(sock, SIOCGARP, (char *)&myarp, sizeof(myarp)) == L0 )
             if ( memcmp(ptr, "\0\0\0\0\0", L6) != L0 )
               {
               sprintf(preMAC, "%2.2x%2.2x-%2.2x%2.2x-%2.2x%2.2x", *ptr,
                       *(ptr+L1), *(ptr+L2), *(ptr+L3), *(ptr+L4), *(ptr+L5));
               ExistMAC = TRUE;
               }
#else
           if ( ioctl(sock, SIOCGARP, &myarp) == L0 )
             {
             sprintf(preMAC, "%2.2x%2.2x-%2.2x%2.2x-%2.2x%2.2x", *ptr,
                      *(ptr+L1), *(ptr+L2), *(ptr+L3), *(ptr+L4), *(ptr+L5));
             ExistMAC = TRUE;
             }
#endif
           }
         else
           {
           strcpy(preIP, inet_ntoa(*inaddr[k]));
           for (ind=preFirstNotMe, tptr=oldIP+IPLEN*preFirstNotMe;
                ind<preCurrNum; ind++)
             {
             if ( strcmp(preIP, tptr) == L0 )
               {
               strcpy(preMAC, oldMAC+MACLEN*ind);
               ExistMAC = TRUE;
               break;
               }
             tptr += IPLEN;
             }
           }

         memset( &myarp, L0, sizeof(myarp) );
         memcpy( &myarp.arp_pa, &sin[k], sizeof(myarp.arp_pa) );

#ifndef DAEMON
         WinPostMsg (parmHwnd, WM_USER_ARP, MPFROMLONG(*paddr[k]), L0);
#endif

#ifdef TCPV40HDRS    // Включить для TCP/IP 4.0
//-----------------------------------------------------------------------------
// Удалим запись из кэша ARP
//-----------------------------------------------------------------------------
         ioctl(sock, SIOCDARP, (char *)&myarp, sizeof(myarp));
//-----------------------------------------------------------------------------
// Выдадим запрос ARP
//-----------------------------------------------------------------------------
         sendto( sock, (char *)&num, sizeof(num), L0,
                 (struct sockaddr *)&sin[k], sizeof(struct sockaddr) );
//-----------------------------------------------------------------------------
// Прочитаем запись из кэша ARP
//-----------------------------------------------------------------------------
         DosSleep(ArpWait);
         resi=ioctl(sock,SIOCGARP,(char *)&myarp,sizeof(myarp));
         if ( resi && !ExistMAC ) continue;
         if ( !resi && !memcmp(ptr, "\0\0\0\0\0", L6) )
           { // Удалим запись из кэша ARP
           ioctl(sock, SIOCDARP, (char *)&myarp, sizeof(myarp));
           if ( !ExistMAC ) continue;
           }
#else                // Исключить для TCP/IP 4.0
//-----------------------------------------------------------------------------
// Удалим запись из кэша ARP
//-----------------------------------------------------------------------------
         ioctl(sock, SIOCDARP, &myarp);
//-----------------------------------------------------------------------------
// Выдадим запрос ARP
//-----------------------------------------------------------------------------
         ioctl(sock, SIOCARP, inaddr[k]);
//-----------------------------------------------------------------------------
// Прочитаем запись из кэша ARP
//-----------------------------------------------------------------------------
         DosSleep(ArpWait);
         resi = ioctl(sock, SIOCGARP, &myarp);
         if ( resi && !ExistMAC ) continue;
#endif               // TCPV40HDRS

         if ( resi && ExistMAC ) // узла теперь нет
           {
           strcpy(IP, inet_ntoa(*inaddr[k]));
           strcpy(MAC, preMAC);
#ifndef DAEMON
           CNI = FindOUI();
#endif
#ifdef DAEMON
           GetIPname((char *)paddr[k], *paddr[k]);
#else
           GetIPname(parmHwnd, (char *)paddr[k], *paddr[k]);
#endif
           IP += IPLEN;
           MAC += MACLEN;
           FQDN += FQDNLEN;
           NETBN += UNCLEN;
           StatusIP[CurrNum] = TxtDel-TxtExist;
#ifndef DAEMON
           WinPostMsg ( parmHwnd, WM_USER_LINE_DONE,
                        MPFROMLONG(CurrNum), MPFROM2SHORT(CNI, L0) );
#endif
           CurrNum++;
           continue;
           }

         strcpy(IP, inet_ntoa(*inaddr[k]));
         sprintf(currMAC, "%2.2x%2.2x-%2.2x%2.2x-%2.2x%2.2x",
                 *ptr, *(ptr+L1), *(ptr+L2), *(ptr+L3), *(ptr+L4), *(ptr+L5));
         if ( ExistMAC ) // узел был и есть
           {
           if ( strcmp(preMAC, currMAC) ) // запись ARP в кэше изменилась
             {
             strcpy(MAC, preMAC);
#ifndef DAEMON
             CNI = FindOUI();
#endif
             IP += IPLEN;
             MAC += MACLEN;
             FQDN += FQDNLEN;
             NETBN += UNCLEN;
             StatusIP[CurrNum] = TxtRepl-TxtExist;
#ifndef DAEMON
             WinPostMsg ( parmHwnd, WM_USER_LINE_DONE,
                          MPFROMLONG(CurrNum), MPFROM2SHORT(CNI, L0) );
#endif
             CurrNum++;
             currStatus = TxtUpd-TxtExist; // статус добавленной записи
             }
           else currStatus = TxtExist-TxtExist; // статус существующей записи
           }
         else currStatus = TxtAdd-TxtExist; // статус добавленной записи

         strcpy(IP, inet_ntoa(*inaddr[k]));
         strcpy(MAC, currMAC);
#ifdef DAEMON
         GetIPname((char *)paddr[k], *paddr[k]);
#else
         GetIPname(parmHwnd, (char *)paddr[k], *paddr[k]);
#endif
//-----------------------------------------------------------------------------
// Выводим результаты сканирования
//-----------------------------------------------------------------------------
         if ( NBresult )
           {
           for (j=L0, NBIP=NBIPfirst, NB=NBfirst, MACNB=MACNBfirst; j<NumNBNn;
                j++, NBIP+=IPLEN, NB+=UNCLEN, MACNB+=MACLEN)
             {
             if ( j < NumNBN )
               {
               if ( strcmp(NBIP, IP) == L0 )
                 {
                 strcpy(NETBN, NB);
                 break;
                 }
               }
             else
               {
               for (i=L0; i<L6; i++) ReverseMAC[L5-i]=MACNB[i];
               if ( (memcmp(MACNB, ptr, L6) == L0) ||
                    (memcmp(ReverseMAC, ptr, L6) == L0) )
                 {
                 strcpy(NETBN, NB);
                 break;
                 }
               }
             }
           }

         if ( NewNBact && ( *NETBN == '\0' ) )
           {
#ifndef DAEMON
           WinPostMsg (parmHwnd, WM_USER_SMBNAME, MPFROMLONG(*paddr[k]), L0);
#endif
           SmbName(NETBN, IP, TcpWait);
           }
#ifndef DAEMON
         CNI = FindOUI();
#endif
         IP += IPLEN;
         MAC += MACLEN;
         FQDN += FQDNLEN;
         NETBN += UNCLEN;
         StatusIP[CurrNum] = currStatus;
#ifndef DAEMON
         WinPostMsg ( parmHwnd, WM_USER_LINE_DONE,
                      MPFROMLONG(CurrNum), MPFROM2SHORT(CNI, L0) );
#endif
         CurrNum++;
         }
       }
     }
//-----------------------------------------------------------------------------
// Закроем socket
//-----------------------------------------------------------------------------
   soclose(sock);
//-----------------------------------------------------------------------------
// Выполним Ping
//-----------------------------------------------------------------------------
#ifndef DAEMON
   for ( i=L0; flagRun && (i<NumPing); i++) PingRange(parmHwnd, i);
#else
   for ( i=L0; flagRun && (i<NumPing); i++) PingRange(i);
#endif
//-----------------------------------------------------------------------------
// Завершим сканирование
//-----------------------------------------------------------------------------
   DosResetEventSem( hevEventHandle, &ulPostCnt);
   AfterScan();
#ifdef DAEMON
   printf("Scan ended\n");
#endif
#ifndef DAEMON
   WinPostMsg (parmHwnd, WM_USER_SCAN_DONE, L0, L0);
#endif
   }
}

//=============================================================================
// GetNBnames - подпрограмма получения имен NetBIOS
//=============================================================================
#ifndef DAEMON
ULONG GetNBnames(HWND hwndNum, char *ptrDN, ULONG j)
#else
ULONG GetNBnames(char *ptrDN, ULONG j)
#endif
{
   int i;
   ULONG eSave;

#ifndef DAEMON
   if ( !flagRun ) return L0;
   WinPostMsg ( hwndNum, WM_USER_NET32DCN, MPFROMP(ptrDN), L0 );
#endif
   if ( !flagRun ) return L0;
   if ( (i=Net32GetDCName(NULL, ptrDN, DCName, sizeof(DCName))) != L0 )
     if ( i != NERR_DCNotFound ) return L0;

   if ( i == L0 )
     {
#ifndef DAEMON
     if ( !flagRun ) return L0;
     WinPostMsg ( hwndNum, WM_USER_NET32SE2, MPFROMP(DCName), L0 );
#endif
     i = Net32ServerEnum2( DCName, L0, pB+j*(UNCLEN-L1), (UNCLEN-L1)*(L254-j),
                           &eSave, &ulEntriesAvailable, 0xFFFFFFFF, ptrDN );
     }
   else
     {
#ifndef DAEMON
     if ( !flagRun ) return L0;
     WinPostMsg ( hwndNum, WM_USER_NET32SE2, MPFROMP(Nol), L0 );
#endif
     i = Net32ServerEnum2( NULL, L0, pB+j*(UNCLEN-L1), (UNCLEN-L1)*(L254-j),
                           &eSave, &ulEntriesAvailable, 0xFFFFFFFF, ptrDN );
     }
   if ( i != L0 ) return L0;

   return eSave;
}

//=============================================================================
// TCPBEUIscan - подпрограмма сканирования по протоколу TCPBEUI
//=============================================================================
#ifndef DAEMON
int TCPBEUIscan(HWND hwndNum)
#else
int TCPBEUIscan(void)
#endif
{
   int i, j, NumberNBN = L0;
   struct session_info_0 *ses_i_0;
   struct {
     short int Id;
     short int Flag;
     short int NQ;
     short int NAnsRR;
     short int NAutRR;
     short int NAddRR;
     char NBname[L34];
     short int QT;
     short int QC; } NBQ;
//               123456789x123456789x123456789x123
   char NBN[] = " CACACACACACACACACACACACACACACACA";

   NBQ.Id     = 10001;
   NBQ.Flag   = htons(0x0110);
   NBQ.NQ     = htons(0x0001);
   NBQ.NAnsRR = 0;
   NBQ.NAutRR = 0;
   NBQ.NAddRR = 0;
   NBQ.QT     = htons(0x0020);
   NBQ.QC     = htons(0x0001);

   for ( ses_i_0 = (struct session_info_0 *)pSes, i=0;
         flagRun && (i<ulSesRead); i++, ses_i_0++ )
     {
#ifndef DAEMON
     if ( !flagRun ) return L0;
     WinPostMsg ( hwndNum, WM_USER_SESTBEUI, MPFROMLONG((long)i), 0L );
#endif
     strcpy(NBQ.NBname,NBN);
     for (j=0; j<strlen(ses_i_0->sesi0_cname); j++)
       {
       NBQ.NBname[2*j+1] = ((ses_i_0->sesi0_cname[j])>>4)+'A';
       NBQ.NBname[2*j+2] = ((ses_i_0->sesi0_cname[j])&0x0F)+'A';
       }
     NumberNBN += GetTCPBEUIn((char *)&NBQ, sizeof(NBQ));
     }

   for (i=0; flagRun && (i<ulEntriesRead); i++)
     {
#ifndef DAEMON
     if ( !flagRun ) return L0;
     WinPostMsg ( hwndNum, WM_USER_TCPBEUI, MPFROMLONG((long)i), 0L );
#endif
     strcpy(NBQ.NBname,NBN);
     for (j=0; j<strlen(pB+i*(UNCLEN-1)); j++)
       {
       NBQ.NBname[2*j+1] = (pB[i*(UNCLEN-1)+j]>>4)+'A';
       NBQ.NBname[2*j+2] = (pB[i*(UNCLEN-1)+j]&0x0F)+'A';
       }
     NumberNBN += GetTCPBEUIn((char *)&NBQ, sizeof(NBQ));
     }
   return NumberNBN;
}

//=============================================================================
// GetTCPBEUIn - подпрограмма ввода-вывода по протоколу TCPBEUI
//=============================================================================
int GetTCPBEUIn(char *line, int len)
{
int j, k, NumberNBN = 0, sock;
fd_set r;
char buff[PACKETSIZE];
struct sockaddr_in client;
struct timeval tv;

  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  tv.tv_sec = 0;
  tv.tv_usec = TcpWait*1000; // единица измерения - микросекунда

  for ( k=0; k<NumIPadr; k++ ) *paddr[k] |= htonl(~AddrInfoIP[k].mask);

  for ( k=0; flagRun && (k<NumIPadr); k++ )
    {
    if ( ChkTCPB[k] )
      {
      setsockopt( sock, SOL_SOCKET, SO_BROADCAST,
                  (char *)&sin[k].sin_addr.s_addr,
                  sizeof(sin[0].sin_addr.s_addr) );

      FD_ZERO(&r);
      myFD_SET(sock, &r);

      sendto( sock, line, len, 0, (struct sockaddr *)&sin[k],
              sizeof(struct sockaddr) );

      memset(buff, 0, PACKETSIZE);
      if ( select(sock+1, &r, NULL, NULL, &pingtv) <= 0 ) continue;
      if ( recvfrom(sock, buff, PACKETSIZE, 0, 0, 0) == -1 ) continue;

      memcpy((char *)&client.sin_addr, buff+58, L4);
      strcpy(NBIP, inet_ntoa(client.sin_addr));
      for (j=13; j<=44; j+=2)
        {
        if ( (buff[j] < 'A') || (buff[j] > 'P') ||
             (buff[j+1] < 'A') || (buff[j+1] > 'P') )
          {
          NB[(j-13)/2] = '\0';
          break;
          }
        NB[(j-13)/2] = ((buff[j]-'A')<<4)+(buff[j+1]-'A');
        if ( NB[(j-13)/2] == ' ' )
          {
          NB[(j-13)/2] = '\0';
          break;
          }
        }
      MACNB+=MACLEN;
      NB += UNCLEN;
      NBIP += IPLEN;
      NumberNBN++;
      }
    }
  soclose(sock);
  return NumberNBN;
}

//=============================================================================
// NETBEUIscan - подпрограмма сканирования по протоколу NETBEUI
//=============================================================================
#ifndef DAEMON
int NETBEUIscan(HWND hwndNum, int NumberNBN)
#else
int NETBEUIscan(int NumberNBN)
#endif
{
   unsigned long handle[MAXIPADR] = { 0, 0, 0, 0, 0, 0, 0, 0 };
   int i, k;
   struct session_info_0 *ses_i_0;

   for ( k=0; k<NumNCB; k++ )
     NetBios32Open(NetName+k*(NETBIOS_NAME_LEN+1), NULL, L1, &handle[k]);

   for ( ses_i_0 = (struct session_info_0 *)pSes, i=0;
         flagRun && (i<ulSesRead); i++, ses_i_0++ )
     {
#ifndef DAEMON
     if ( !flagRun ) return L0;
     WinPostMsg ( hwndNum, WM_USER_SESNBEUI, MPFROMLONG((long)i), 0L );
#endif
     for ( k=0; flagRun && (k<NumNCB); k++ )
       {
       NCBB[k].ncb_length = len;
       memset(NCBB[k].ncb_callname, ' ', NCBNAMSZ);
       strncpy( NCBB[k].ncb_callname, ses_i_0->sesi0_cname,
                strlen(ses_i_0->sesi0_cname) );
       if ( NetBios32Submit(handle[k], L0, &NCBB[k]) == 0 )
         {
         strcpy(NB, ses_i_0->sesi0_cname);
         memcpy(MACNB, bufFind, L6);
         NB += UNCLEN;
         MACNB += MACLEN;
         NumberNBN++;
         break;
         }
       }
     }

   for (i=0; flagRun && (i<ulEntriesRead); i++)
     {
#ifndef DAEMON
     if ( !flagRun ) return L0;
     WinPostMsg ( hwndNum, WM_USER_NETBEUI, MPFROMLONG((long)i), 0L );
#endif
     for ( k=0; flagRun && (k<NumNCB); k++ )
       {
       NCBB[k].ncb_length = len;
       memset(NCBB[k].ncb_callname, ' ', NCBNAMSZ);
       strncpy(NCBB[k].ncb_callname, pB+i*(UNCLEN-1), strlen(pB+i*(UNCLEN-1)));
       if ( NetBios32Submit(handle[k], L0, &NCBB[k]) == 0 )
         {
         strcpy(NB, pB+i*(UNCLEN-1));
         memcpy(MACNB, bufFind, L6);
         NB += UNCLEN;
         MACNB += MACLEN;
         NumberNBN++;
         break;
         }
       }
     }

   for ( k=0; k<NumNCB; k++ ) NetBios32Close(handle[k], L0);

   return NumberNBN;
}

//=============================================================================
// DoSave - подпрограмма сохранения результатов сканирования в текстовом виде
//=============================================================================
void DoSave(char *File, char *mode, BOOL Format)
{
  FILE *OutFile;
  char temp[L32];
  int i;

  strftime(temp, sizeof(temp)-1, "%d/%m/%Y %T", timeptr);
  OutFile = fopen(File, mode);

  fprintf(OutFile, "%s %s\n%s\n", TitleBar, temp, pszCnrTitle);
  if ( Format )
    fprintf(OutFile,
      "Status   IP address       MAC address   NetBIOS name     Host name\n");
  else
    fprintf(OutFile,
      "IP address       MAC address   NetBIOS name     Host name\n");
//     123.123.123.123 1234-1234-1234 123456789x123456

  IP=IPfirst;
  MAC=MACfirst;
  FQDN=FQDNfirst;
  NETBN=NETBNfirst;
  for (i = 0; i < CurrNum;
       i++, IP += IPLEN, MAC += MACLEN, FQDN += FQDNLEN, NETBN += UNCLEN)
    {
    if ( Format )
      fprintf( OutFile, "  %-6.6s %-15s %-14s %-16s %s\n",
               TxtExist+StatusIP[i], IP, MAC, NETBN, FQDN );
    else
      {
      if ( (StatusIP[i]==TxtDel-TxtExist)||(StatusIP[i]==TxtRepl-TxtExist) )
        continue;
      fprintf(OutFile, "%-15s %-14s %-16s %s\n", IP, MAC, NETBN, FQDN);
      }
    }

  fclose(OutFile);
}

//=============================================================================
// CrtRFCNAMES - подпрограмма создания файла RFCNAMES.LST
//=============================================================================
void CrtRFCNAMES(void)
{
  FILE *OutFile;
  char temp[L24];
  int i;

  OutFile = fopen("RFCNAMES.LST", "w");
  IP=IPfirst;
  NETBN=NETBNfirst;

  for (i = 0; i < CurrNum; i++, IP += IPLEN, NETBN += UNCLEN)
    {
    if ( *NETBN == '\0' ) continue; // Имя SMB не найдено
    sprintf( temp, "\"%s\"", NETBN );
    fprintf( OutFile, "%-20s %s\n", temp, IP );
    }

  fclose(OutFile);
}

//=============================================================================
// TestAddr - подпрограмма проверки наличия IP-адреса в списке интерфейсов
//=============================================================================
BOOL TestAddr(int k)
{
int i, sock;

   sock = socket(AF_INET, SOCK_DGRAM, 0);
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
   os2_ioctl(sock, SIOSTATAT, (char *)buf, sizeof(buf));
#else                // Включить для TCP/IP 4.0
   ioctl(sock, SIOSTATAT, (char *)buf, sizeof(buf));
#endif               // TCPV40HDRS
   soclose(sock);

   for ( i=0, AdrInfo=(struct statatreq *)&buf[2]; i < *pi; i++, AdrInfo++ )
     {
#ifdef TCPV40HDRS   // Включить для TCP/IP 4.0
     if ( (sin[k].sin_addr.s_addr == AdrInfo->addr) &&
          (AdrInfo->interface >= 0) &&       // должен быть
          (AdrInfo->interface < MAXIPADR) )  // lan0 - lan7
#else
     if ( (sin[k].sin_addr.s_addr == AdrInfo->addr) &&
          (AdrInfo->interface >= 0) &&        // должен быть
          (AdrInfo->interface < MAXIPADR) &&  // lan0 - lan7
          ((AdrInfo->addr & 0x000000ff) != 0x0000007f) ) // не loopback
#endif
       {
       memcpy((char *)&AddrInfoIP[k], AdrInfo, sizeof(struct statatreq));
       return TRUE;
       }
     }
   return FALSE;
}

//=============================================================================
// FormNCB - подпрограмма построения блоков NCB и подготовки к TCPBEUI
//=============================================================================
void FormNCB(void)
{
  int i, j;
  unsigned long ERead, EAvailable;

  NumNCB = 0;
  memset(ChkTCPB, '\0', sizeof(ChkTCPB));

  if ( NetBios32Enum(NULL,L1,bufFind,len,&ERead,&EAvailable) != 0 ) return;

  for ( i=0; i<ERead; i++)
    {
    if (strcmpi(NBI1[i].nb1_driver_name, "NETBEUI$") == 0)
      {
      if ( NBadrSet && NBadrM[NBI1[i].nb1_lana_num] )
        {
        strcpy(NetName+NumNCB*(NETBIOS_NAME_LEN+1), NBI1[i].nb1_net_name);
        NCBB[NumNCB].ncb_command = NCBASTAT;    // NCB.STATUS
        NCBB[NumNCB].ncb_buffer = bufFind;
        NCBB[NumNCB].ncb_lana_num = NBI1[i].nb1_lana_num;
        NumNCB++;
        continue;
        }

      if ( NBadrSet ) continue;
      for ( j=0; j<NumIPadr; j++ )
        if ( NBI1[i].nb1_lana_num == AddrInfoIP[j].interface )
          {
          strcpy(NetName+NumNCB*(NETBIOS_NAME_LEN+1), NBI1[i].nb1_net_name);
          NCBB[NumNCB].ncb_command = NCBASTAT;    // NCB.STATUS
          NCBB[NumNCB].ncb_buffer = bufFind;
          NCBB[NumNCB].ncb_lana_num = NBI1[i].nb1_lana_num;
          NumNCB++;
          break;
          }
      }
    else
      if (strcmpi(NBI1[i].nb1_driver_name, "TCPBEUI$") == 0)
        {
        if ( NBadrSet && NBadrM[NBI1[i].nb1_lana_num] )
          {
          for ( j=0; j<NumIPadr; j++ ) ChkTCPB[j] = TRUE;
          continue;
          }

        if ( NBadrSet ) continue;
        for ( j=0; j<NumIPadr; j++ )
          if (NBI1[i].nb1_lana_num == AddrInfoIP[j].interface) ChkTCPB[j]=TRUE;
        }
    }
}

#ifndef DAEMON
//=============================================================================
// GetIPaddr - подпрограмма нахождения IP-адреса по имени интерфейса
//=============================================================================
void GetIPaddr(short j)
{
int i, sock;

  sock = socket(AF_INET, SOCK_DGRAM, 0);
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
  os2_ioctl(sock, SIOSTATAT, (char *)buf, sizeof(buf));
#else                // Включить для TCP/IP 4.0
  ioctl(sock, SIOSTATAT, (char *)buf, sizeof(buf));
#endif               // TCPV40HDRS
  soclose(sock);

  for ( i=0, AdrInfo=(struct statatreq *)&buf[2]; i < *pi; i++, AdrInfo++ )
    {
#ifdef TCPV40HDRS   // Включить для TCP/IP 4.0
    if ( (AdrInfo->interface == j) &&
         ((AdrInfo->addr & 0x000000ff) != 0x0000007f) )  // не loopback
#else
    if ( AdrInfo->interface == j )
#endif
      {
      sin[NumIPadr].sin_family = AF_INET;
      sin[NumIPadr].sin_addr.s_addr = AdrInfo->addr;
      memcpy((char *)&AddrInfoIP[NumIPadr], AdrInfo, sizeof(struct statatreq));
      NumIPadr++;
      if ( NumIPadr == MAXIPADR ) return;
      }
    }
}
#endif

//=============================================================================
// GetIPname - подпрограмма нахождения имени хоста
//=============================================================================
#ifndef DAEMON
void GetIPname(HWND hwnd, char *ptr, u_long i)
#else
void GetIPname(char *ptr, u_long i)
#endif
{
struct hostent *hent;

   if ( !useDNS ) return;

#ifndef DAEMON
   WinPostMsg (hwnd, WM_USER_DNS, MPFROMLONG(i), 0L);
#endif

   if ( (hent = gethostbyaddr(ptr, L4, AF_INET)) != NULL )
     sprintf(FQDN, "%0.63s",hent->h_name);
}

//=============================================================================
// PingRange - подпрограмма выполнения PING для диапазона адресов
//=============================================================================
#ifndef DAEMON
void PingRange(HWND hwnd, int j)
#else
void PingRange(int j)
#endif
{
u_long len, num, start, stop;
struct sockaddr_in whereto;   // Who to ping
u_char outpack[PING_MAXPACKET];
struct icmp *icp = (struct icmp *)outpack;
u_char *datap = (u_char *)(icp->icmp_data);
u_char inpack[PING_MAXPACKET];
struct ip *ip = (struct ip *)inpack;
fd_set r;
int sock, i;
struct timeval waitpk = { L0 , L1 };
BOOL pkCame;

   strcpy(IP, LineSep);
   strcpy(MAC, LineSep);
   strcpy(FQDN, LineSep);
   IP += IPLEN;
   MAC += MACLEN;
   FQDN += FQDNLEN;
   NETBN += UNCLEN;
#ifndef DAEMON
   WinPostMsg ( hwnd, WM_USER_LINE_DONE,
                MPFROMLONG(CurrNum), MPFROM2SHORT(NumOUI, L0) );
#endif
   CurrNum++;
   start = htonl(PingStart[j]);
   stop = htonl(PingStop[j]);

   sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);

   memset( (char *)&whereto, L0, sizeof(struct sockaddr_in) );
   whereto.sin_family = PF_INET;
   strcpy(icp->icmp_data, TitleBar);
   strcat(icp->icmp_data, " ABCDEFGHIJKLMNOPRSTUVWXYZ 0123456789 Verify");
   len = strlen(icp->icmp_data) + 1 + (datap-outpack);
   icp->icmp_type = ICMP_ECHO;
   icp->icmp_code = L0;
   icp->icmp_id = 0x3554; // identitier for outbound packet
   icp->icmp_seq = L1;    // sequence number for outbound packet

   for (num=start; flagRun && (num<=stop) && (CurrNum<NUMADR); num++)
     {
#ifndef DAEMON
     WinPostMsg (hwnd, WM_USER_PING, MPFROMLONG(num), L0);
#endif
     whereto.sin_addr.s_addr = htonl(num);
     icp->icmp_cksum = L0;
     icp->icmp_cksum = in_cksum( (u_short*)icp, len ); // Compute ICMP CheckSum

     FD_ZERO(&r);
     myFD_SET(sock, &r);

     for (;;) // А вдруг к нам пекеты пришли, удалим их
       {
       if ( select(sock+L1, &r, NULL, NULL, &waitpk) <= L0 ) break;
       recvfrom(sock, inpack, PING_MAXPACKET, L0, L0, L0);
       }

     sendto( sock, (char *)outpack, len, L0, (struct sockaddr *)&whereto,
             sizeof(struct sockaddr_in) );
     for ( i=L0, pkCame=FALSE; i<L3; i++ ) // есть пакеты, принимаем 3 первых
       {
       if ( select(sock+L1, &r, NULL, NULL, &pingtv) <= L0 ) break;
       if ( recvfrom(sock, inpack, PING_MAXPACKET, L0, L0, L0) == -1) break;
       if (!memcmp((char *)&(ip->ip_src),(char *)&whereto.sin_addr.s_addr,L4))
         {
         pkCame = TRUE; // пришел "наш" пакет
         break;
         }
       }
     if ( !pkCame ) continue;
     sprintf( IP, "%s", inet_ntoa(ip->ip_src) );

#ifdef DAEMON
     GetIPname((char *)&whereto.sin_addr.s_addr, whereto.sin_addr.s_addr);
     if ( NewNBactP ) SmbName(NETBN, IP, TcpWait);
#else
     GetIPname(hwnd,(char *)&whereto.sin_addr.s_addr,whereto.sin_addr.s_addr);
     if ( NewNBactP )
       {
       WinPostMsg (hwnd, WM_USER_SMBNAME, MPFROMLONG(htonl(num)), L0);
       SmbName(NETBN, IP, TcpWait);
       }
#endif
     IP += IPLEN;
     MAC += MACLEN;
     FQDN += FQDNLEN;
     NETBN += UNCLEN;
#ifndef DAEMON
     WinPostMsg ( hwnd, WM_USER_LINE_DONE,
                  MPFROMLONG(CurrNum), MPFROM2SHORT(NumOUI, L0) );
#endif
     CurrNum++;
     }
   soclose(sock);
}

//=============================================================================
// TestBEUI - подпрограмма проверки запуска Lan Requester (Lan Server)
//=============================================================================
BOOL TestBEUI(void)
{
  if (Net32WkstaGetInfo(NULL, L1, Net32Buf, L1024, &ulEntriesAvailable) != 0)
    return FALSE;

  ulSesRead = ulSesAvailable = 0;
  Net32SessionEnum( NULL, L0, pSes, L4096, &ulSesRead, &ulSesAvailable );

  return TRUE;
}

//=============================================================================
// SetTitle - подпрограмма формирования заголовка
//=============================================================================
void SetTitle (BOOL NETparm)
{
int i, j;

  sprintf(pszCnrTitle, "Network(s) -");

  for ( i=0; i<NumIPadr; i++ )
    {
    j = strlen(pszCnrTitle);
    *paddr[i] &= htonl(AddrInfoIP[i].mask);
    sprintf(pszCnrTitle+j, " %s", inet_ntoa(*inaddr[i]));
    }

  for ( i=0; i<NumPing; i++ )
    {
    j=strlen(pszCnrTitle);
    sprintf(pszCnrTitle+j, " %s", inet_ntoa(*(struct in_addr *)&PingStart[i]));
    j = strlen(pszCnrTitle);
    sprintf(pszCnrTitle+j, "-%s",inet_ntoa(*(struct in_addr *)&PingStop[i]));
  }

  if ( !NETparm ) return;

  j=strlen(pszCnrTitle);
  sprintf( pszCnrTitle+j, "     Domain - %s     Computer - %s",
          pWkInf->wki1_logon_domain, pWkInf->wki1_computername );
}

//=============================================================================
// CFGpgm - подпрограмма конфигурирования LanScan
//=============================================================================
void APIENTRY CFGpgm(void)
{
struct sockaddr_in server; // server address information
struct sockaddr_in client; // client address information
struct servent *CFGprot;
int srvsock;    // socket for accepting connections
int ns;         // socket connected to client
int namelen = sizeof(client);    // length of client name
char CFGbuf[PWDLEN+L4];
fd_set r;
ULONG Post;

  DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L15, L0);
#ifdef DAEMON
  if ( (CFGprot = getservbyname("LanScanC", "tcp")) == NULL )
    {
    printf("Can not found LanScanC port\n");
    exit(L0);
    }
#else
  if ( (CFGprot = getservbyname("LanScanC", "tcp")) == NULL ) return;
#endif
  srvsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  memset(&server, '\0', sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = CFGprot->s_port;
  server.sin_addr.s_addr = INADDR_ANY;

// Bind the socket to the server address.
#ifdef DAEMON
  if ( bind(srvsock, (struct sockaddr *)&server, sizeof(server)) != 0 )
    {
    printf("Can not bind to LanScanC port\n");
    exit(L0);
    }
  printf("Successful bind to LanScanC port\n");
#else
  if ( bind(srvsock, (struct sockaddr *)&server, sizeof(server)) != 0 )
    {
    soclose(srvsock);
    return;
    }
#endif
// Listen for connections. Specify the backlog as 0.
  listen(srvsock, L0);

  for (;;)
    {
// Accept a connection.
    ns = accept(srvsock, (struct sockaddr *)&client, &namelen);

    FD_ZERO(&r);
    myFD_SET(ns, &r);
    select(ns+1, &r, NULL, NULL, NULL);
// Receive the message on the newly connected socket.
    memset(CFGbuf, '\0', sizeof(CFGbuf));
    len = recv(ns, CFGbuf, PWDLEN+L4, L0);

    if ( (memcmp(CFGbuf, "Get", L3) == 0) &&
         (memcmp(CFGbuf+3, ReadPWD, strlen(ReadPWD)+1) == 0) )
      {
      if ( flagSet )
        {
        soclose(ns);
        continue;
        }
      flagSet = TRUE;
      SaveOpt(CFGname);
      flagSet = FALSE;

// Send the Configuration to Client.
      SndFile(ns, CFGname);
      continue;
      }

    if ( (memcmp(CFGbuf, "Put", L3) == 0) &&
         (memcmp(CFGbuf+3, WritePWD, strlen(WritePWD)+1) == 0) )
      {
//  Receive the configuration
      if ( !RcvFile(ns, CFGname) ) continue;
      GetOpt(CFGname);

      DosQueryEventSem( hevEventHandle, &Post );
      if ( flagSet || Post )
        {
        FlagNewCFG = TRUE;
        continue;
        }

      flagSet = TRUE;
      NumIPadr = 0;
      IniFormIP();
      SaveOpt(INIname);
      FlagNewCFG = FALSE;
      flagSet = FALSE;

      continue;
      }
    soclose(ns);
    }
}

//=============================================================================
// IniFormIP - подпрограмма формировния IP-адресов из INI-файла
//=============================================================================
void IniFormIP(void)
{
int i, j;

  for ( i=0; i<MAXIPADR; i++) Interv[i] = 0;

  for ( i=0; i<TempNumIPadr; i++)
     {
     sin[NumIPadr].sin_family = AF_INET;
     sin[NumIPadr].sin_addr.s_addr = TempAddrInfo[i].addr;
     if ( !TestAddr(NumIPadr) ) continue;

     if ( TempInterv[i] == 0 )
       {
       NumIPadr++;
       continue;
       }

     for ( j=0; j<TempInterv[i]; j++ )
       {
       HostInt[NumIPadr].start[j] = TempHostInt[i].start[j];
       HostInt[NumIPadr].stop[j] = TempHostInt[i].stop[j];
       HostInt[NumIPadr].start[j] &= ~AddrInfoIP[NumIPadr].mask;
       HostInt[NumIPadr].stop[j]  &= ~AddrInfoIP[NumIPadr].mask;

       if ((HostInt[NumIPadr].start[j] == 0) ||
           (HostInt[NumIPadr].start[j] > HostInt[NumIPadr].stop[j]) ||
           (HostInt[NumIPadr].stop[j] == ~AddrInfoIP[NumIPadr].mask)) return;

       Interv[NumIPadr]++;
       }
     NumIPadr++;
     }
}

//=============================================================================
// ViewPgm - подпрограмма ожидания запроса о результатах сканирования
//=============================================================================
void APIENTRY ViewPgm(void)
{
struct sockaddr_in server; // server address information
struct sockaddr_in client; // client address information
struct servent *ViewProt;
int srvsock;    // socket for accepting connections
int ns;         // socket connected to client
int namelen = sizeof(client);    // length of client name
fd_set r;

  DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L15, L0);
#ifdef DAEMON
  if ( (ViewProt = getservbyname("LanScanV", "tcp")) == NULL )
    {
    printf("Can not found LanScanV port\n");
    exit(L0);
    }
#else
  if ( (ViewProt = getservbyname("LanScanV", "tcp")) == NULL ) return;
#endif
  FlagSrv = TRUE;

  srvsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  memset(&server, '\0', sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = ViewProt->s_port;
  server.sin_addr.s_addr = INADDR_ANY;

// Bind the socket to the server address.
#ifdef DAEMON
  if ( bind(srvsock, (struct sockaddr *)&server, sizeof(server)) != 0 )
    {
    printf("Can not bind to LanScanV port\n");
    exit(L0);
    }
  printf("Successful bind to LanScanV port\n");
#else
  if ( bind(srvsock, (struct sockaddr *)&server, sizeof(server)) != 0 )
    {
    soclose(srvsock);
    return;
    }
#endif
// Listen for connections. Specify the backlog as Maximum.
  listen(srvsock, SOMAXCONN);

// Wait indefinitely
  for (;;)
    {
    FD_ZERO(&r);
    myFD_SET(srvsock, &r);

    select(srvsock+1, &r, NULL, NULL, NULL);

// Accept a connection.
    ns = accept(srvsock, (struct sockaddr *)&client, &namelen);

// Create Thread
    _beginthread(SendResult, NULL, L8192, (void *)ns);
    }
}

//=============================================================================
// SendResult - подпрограмма рассылки результатов сканирования
//=============================================================================
void SendResult(void *arg)
{
int sock;
char ViewBuf[PWDLEN+L4];
ULONG Post;
char FileResultName[L32];

  sock = (int)arg;

// Receive the message on the newly connected socket.
  memset(ViewBuf, '\0', sizeof(ViewBuf));
  recv(sock, ViewBuf, PWDLEN+L4, L0);

  if ( (memcmp(ViewBuf, "Run", L3) == 0) &&
       (memcmp(ViewBuf+3, RunPWD, strlen(RunPWD)+1) == 0) )
    {
    soclose(sock);
    DosQueryEventSem( hevEventHandle, &Post );
    if ( Post == 0 ) DosPostEventSem(hevEventHandle);
    return;
    }

  if ( (memcmp(ViewBuf, "See", L3) == 0) &&
       (memcmp(ViewBuf+3, ViewPWD, strlen(ViewPWD)+1) == 0) )
    {
    DosEnterCritSec();
    strcpy(FileResultName, FileSrvName);
    DosExitCritSec();

    if ( FileResultName[0] == '\0')
      {
      soclose(sock);
      return;
      }
    SndFile(sock, FileResultName);   // Send the Result to the client.
    }
}

//=============================================================================
// AfterScan - подпрограмма выполнения полезных действий после сканирования
//=============================================================================
void AfterScan(void)
{
char FileName[L32], DateTime[L32];
RXSTRING arg;             // argument string for REXX
RXSTRING rexxretval;      // return value from REXX
static UCHAR *strC = "C"; // Log пишется в общий файл
static UCHAR *strS = "S"; // Log пишется в отдельные файлы
SHORT rexxrc = 0;         // return code from function

  DoSave("LanScan.Net", "a", NewFormat);
  if ( NewNBact || NewNBactP ) CrtRFCNAMES();

  if ( AutoLog && CommonLog )
    {
    DoSave("LanScan.Log", "a", OldFormat);
    MAKERXSTRING(arg, strC, strlen(strC)); // create argument
    }

  if ( FlagSrv || ( AutoLog && !CommonLog ) )
    {
    strftime(DateTime,sizeof(DateTime)-1,"%Y%m%d-%H%M%S",timeptr);
    sprintf(FileName,"LanScan-%s.Log",DateTime);
    DoSave(FileName, "w", OldFormat);
    MAKERXSTRING(arg, strS, strlen(strS)); // create argument
    }

  if ( FlagSrv )
    {
    DosEnterCritSec();
    memset(FileSrvName, '\0', sizeof(FileSrvName));
    strcpy(FileSrvName, FileName);
    DosExitCritSec();
    }

  if ( AutoLog ) RexxStart( L1, (PRXSTRING) &arg, (PSZ) "LanScanP.cmd",
                            (PRXSTRING) 0, (PSZ) 0, (LONG) RXCOMMAND,
                            (PRXSYSEXIT) 0, (PSHORT) &rexxrc,
                            (PRXSTRING) &rexxretval );

  if ( FlagNewCFG )
    {
    flagSet = TRUE;
    NumIPadr = 0;
    IniFormIP();
    SaveOpt(INIname);
    flagSet = FALSE;
    }

  flagRun = TRUE;
  if ( AutoRun ) DosAsyncTimer( (ULONG)Interval*60000L,
                                (HSEM)hevEventHandle, &phtimer );
}

//=============================================================================
// StartThreads - подпрограмма запуска потоков
//=============================================================================
#ifndef DAEMON
void StartThreads(HWND hwnd)
#else
void StartThreads(void)
#endif
{
  DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L16, L0);

  DosCreateEventSem( (ULONG)NULL, &hevEventHandle, DC_SEM_SHARED, TRUE );

#ifndef DAEMON
  DosCreateEventSem( (ULONG)NULL, &hevEventStart,  DC_SEM_SHARED, FALSE );
  DosCreateThread( &tid, (PFNTHREAD) DoScan, hwnd,
                   CREATE_READY | STACK_SPARSE, L65536 );
#else
  DosCreateThread( &tid, (PFNTHREAD) DoScan, L0,
                   CREATE_READY | STACK_SPARSE, L65536 );
#endif
  DosCreateThread( &tidCFG, (PFNTHREAD) CFGpgm, L0,
                   CREATE_READY | STACK_SPARSE, L8192 );
  DosCreateThread( &tidView, (PFNTHREAD) ViewPgm, L0,
                   CREATE_READY | STACK_SPARSE, L8192 );
}

#ifndef DAEMON
//=============================================================================
// ShowPrompt - подпрограмма вывода подсказки
//=============================================================================
void ShowPrompt(HWND hwndP, int x, int y, BOOL right, char *ptr)
{
HPS  hps;    // Screen presentation space
RECTL rct;
FONTMETRICS fm;

  hps = WinGetPS( hwndP);  // Get handle to presentation space
  GpiQueryFontMetrics(hps, sizeof(fm), &fm);

  if ( right )
    {
    rct.xLeft = x;
    rct.xRight = rct.xLeft + fm.lAveCharWidth*(strlen(ptr)+L3);
    }
  else
    {
    rct.xRight = x;
    rct.xLeft = rct.xRight - fm.lAveCharWidth*(strlen(ptr)+L3);
    }
  rct.yBottom = y;
  rct.yTop = rct.yBottom+P_CY;

  WinDrawText(hps, -1, ptr, &rct, CLR_BLACK, CLR_YELLOW,
              DT_CENTER | DT_TOP | DT_ERASERECT | DT_MNEMONIC);
  WinDrawBorder(hps, &rct, L1, L1, CLR_BLACK, CLR_BLACK, DB_STANDARD);
  WinReleasePS(hps);
}
#endif

#ifndef DAEMON
#include "SubPgm\DlgProcARP.c"
#include "SubPgm\DlgProcOPT.c"
#include "SubPgm\DlgProcPING.c"
#include "SubPgm\InitContainer.c"
#include "SubPgm\Insertrecord.c"
#include "SubPgm\GetFontName.c"
#include "SubPgm\GetFileName.c"
#include "SubPgm\TestInt.c"
#include "SubPgm\TestPing.c"
#include "SubPgm\FindOUI.c"
#endif

#include "SubPgm\GetStorage.c"
#include "SubPgm\GetOpt.c"
#include "SubPgm\in_cksum.c"
#include "SubPgm\RcvFile.c"
#include "SubPgm\SaveOpt.c"
#include "SubPgm\SndFile.c"
