//=============================================================================
// ViewLS.c
// Программа просмотра результатов сканирования
//=============================================================================
#define INCL_WIN
#define INCL_DOSMEMMGR
#define INCL_GPIBITMAPS
#define INCL_DOSSEMAPHORES
#define INCL_DOSPROCESS
#define INCL_DOSERRORS
#define INCL_DOSDATETIME
#define INCL_REXXSAA
#define INCL_DOSFILEMGR

#include <os2.h>
#include <bsememf.h>
#include <umalloc.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <rexxsaa.h>   // needed for RexxStart()
#include <netinet\in_systm.h>
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#include <netinet\ip.h>
#else
#include "ip.h"
#endif
#include <netinet\ip_icmp.h>
#include <libc\sys\stat.h>
#include <sys/select.h>
#include <netcons.h>
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
  *length = ((*length) / 65536) * 65536 + 65536;
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

MRESULT EXPENTRY   ClientWndProc (HWND,ULONG,MPARAM,MPARAM);
MRESULT EXPENTRY   DlgProcView (HWND, ULONG, MPARAM, MPARAM); // Dlg proc (View)
MRESULT EXPENTRY   DlgProcRun (HWND, ULONG, MPARAM, MPARAM); // Dlg proc (Run)
void    APIENTRY   DoView(ULONG);
void    APIENTRY   DoRun(ULONG);
void               GetStorage(void);
void               SendErrMsg(HWND, char *);
void               SendWngMsg(HWND, char *);
void               InitContainer(BOOL);
_inline void       InsertRecord(int, short);
_inline short      FindOUI (void);
BOOL               GetFileName(char *);
void               DoSave(HWND, char *);
struct sockaddr_in resolv(HWND, char *);
void               PostWngMsg(ULONG, char *);
BOOL               RcvFile(int, char *);

//-----------------------------------------------------------------------------
// Global Variablies
//-----------------------------------------------------------------------------
HWND hwndFrame, hwndCntnr;
HPOINTER hIcon;
struct sockaddr_in myaddr = { 0 }, myaddrRun = { 0 };
int ac;
char **av;
HEV hevEventHandle = 0, hevEventHandleRun = 0;
char INIname[] = "LANSCAN.INI", FileResultName[] = "LanScan.Tmp";
char ViewPW[PWDLEN], RunPW[PWDLEN];
BOOL FlagPW = FALSE, FlagPWrun = FALSE;
char SrvBufN[128];
char pszCnrTitle[256];
char *IPfirst, *MACfirst, *FQDNfirst, *NETBNfirst, *CompNfirst,
     *IP,      *MAC,      *FQDN,      *NETBN,      *CompN;
int CNI, NumOUI = L0, CurrNum = L0;
TID tid = 0, tidRun = 0;
PVOID pBuffer; // Buffer
BOOL FlagSave = FALSE;
char ErrMsg[L160];
long ColorWhite = CLR_WHITE, ColorBlack    = CLR_BLACK, ColorCyan = CLR_CYAN,
     ColorGreen = CLR_GREEN, ColorPaleGray = CLR_PALEGRAY;
long VertSplitBar = L0;
ULONG ulSize;  // Size of the data to be copied
typedef struct _USERRECORD
  { RECORDCORE  recordCore;
    PSZ         IPaddress;
    PSZ         MACaddress;
    PSZ         FQDName;
    PSZ         CompName;
    PSZ         NBname;
  } USERRECORD, *PUSERRECORD;
PNOTIFYRECORDENTER Selected;
ULONG ulPostCnt = L0;
HAB  hab;     // Anchor
HINI hini;    // Handle to private INI file
char NBresult = FALSE;
char szFullPath[CCHMAXPATH] = "LanScan.txt";

//=============================================================================
// Main procedure
//=============================================================================
void main(int argc, char *argv[])
     {
     HMQ   hmq;                    // Message queue handle
     QMSG  qmsg;                   // Message struct
     ULONG flFrameFlags = FCF_TITLEBAR   | FCF_SYSMENU | FCF_SHELLPOSITION |
                          FCF_SIZEBORDER | FCF_MINMAX  | FCF_TASKLIST      |
                          FCF_ACCELTABLE | FCF_MENU    | FCF_AUTOICON;

     ac = argc;
     av = argv;

#ifdef TCPV40HDRS    // Включить для TCP/IP 4.0
     sock_init();
#endif               // TCPV40HDRS
//-----------------------------------------------------------------------------
// Initialize application and create message queue
//-----------------------------------------------------------------------------
     hab = WinInitialize (0);
     hmq = WinCreateMsgQueue (hab, 0);
//-----------------------------------------------------------------------------
// Register class and create window
//-----------------------------------------------------------------------------
     WinRegisterClass (hab, "ViewLanScan", ClientWndProc, CS_SIZEREDRAW, 0);
     hwndFrame = WinCreateStdWindow (HWND_DESKTOP,     // Parent
                                     0,                // Style (unvisible)
                                     &flFrameFlags,    // Creation flags
                                     "ViewLanScan",    // Class name
                                     TitleBarView,     // Titlebar text
                                     0,                // Client style
                                     NULLHANDLE,       // Resource handle
                                     MAIN_ID,          // Frame ID
                                     NULL);            // Client handle
     WinShowWindow(hwndFrame, TRUE);       // Make the window visible
//-----------------------------------------------------------------------------
// Set icon
//-----------------------------------------------------------------------------
     hIcon = (HPOINTER)WinLoadPointer(HWND_DESKTOP, NULLHANDLE, ICON_ID);
     WinPostMsg(hwndFrame, WM_SETICON, (MPARAM)hIcon, 0L);
//-----------------------------------------------------------------------------
// Message loop
//-----------------------------------------------------------------------------
     while (WinGetMsg (hab, &qmsg, 0, 0, 0)) WinDispatchMsg (hab, &qmsg);
//-----------------------------------------------------------------------------
// Clean up (destroy window, queue and hab)
//-----------------------------------------------------------------------------
     WinDestroyWindow (hwndFrame);
     WinDestroyMsgQueue (hmq);
     WinTerminate (hab);
     }

//=============================================================================
// Window procedure
//=============================================================================
MRESULT EXPENTRY ClientWndProc (HWND hwnd, ULONG msg, MPARAM mp1, MPARAM mp2)
     {
     static HWND hwndButtonRun, hwndButtonSave, hwndButtonExit,
                 hwndButtonView, hwndStaticTxt;
     static char Font[] = FontName;
     ULONG Post;
     SWP swp;

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
               hwndButtonRun  =
               WinCreateWindow(hwnd,              // Parent handle
                               WC_BUTTON,         // Window class
                               "~Run",             // Window text
                               WS_VISIBLE | BS_PUSHBUTTON,
                               0, 0, 0, 0,        // no size or position now
                               hwnd,              // Owner handle
                               HWND_TOP,          // Z-order ontop
                               PB_RUN,            // Window ID
                               0,                 // Control
                               0);                // Presentation Parameters
               hwndButtonView  = WinCreateWindow(hwnd, WC_BUTTON, "~View",
                                 WS_VISIBLE | BS_PUSHBUTTON,
                                 0, 0, 0, 0,
                                 hwnd, HWND_TOP, PB_VIEW, 0, 0);
               hwndButtonSave = WinCreateWindow(hwnd, WC_BUTTON, "~Save",
                                WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                                0, 0, 0, 0,
                                hwnd, HWND_TOP, PB_SAVE, 0, 0);
               hwndButtonExit = WinCreateWindow(hwnd, WC_BUTTON, "~Exit",
                                WS_VISIBLE | BS_PUSHBUTTON,
                                0, 0, 0, 0,
                                hwnd, HWND_TOP, PB_EXIT, 0, 0);
               hwndCntnr = WinCreateWindow(hwnd,  // Parent
                               WC_CONTAINER,      // Window class
                               NULL,              // Window text
                               CCS_READONLY | CCS_SINGLESEL | WS_VISIBLE,
                               0, 0, 0, 0,        // no size or position now
                               hwnd,              // Owner handle
                               HWND_TOP,          // Z-order ontop
                               CONTAINER_ID,      // Window ID
                               0,                 // Control
                               0);                // Presentation Parameters
               hwndStaticTxt  =
               WinCreateWindow(hwnd,              // Parent handle
                               WC_STATIC,         // Window class
                               "",                // Window text
                               WS_VISIBLE | SS_TEXT | DT_LEFT | DT_VCENTER,
                               0, 0, 0, 0,        // no size or position now
                               hwnd,              // Owner handle
                               HWND_TOP,          // Z-order ontop
                               STATIC_ID,         // Window ID
                               0,                 // Control
                               0);                // Presentation Parameters
//-----------------------------------------------------------------------------
// Copy the Window position info from a private INI into OS2.INI
//-----------------------------------------------------------------------------
               hini = PrfOpenProfile(hab, INIname); // Open private profile
               if ( hini )
                 if ( PrfQueryProfileSize(hini, APPNAME, WINPOS, &ulSize) )
                   {
                   pBuffer = calloc(ulSize, L1);
                   PrfQueryProfileData(hini,APPNAME, WINPOS,pBuffer,&ulSize);
                   PrfWriteProfileData( HINI_USERPROFILE, APPNAME,
                                        WINPOS, pBuffer, ulSize );
                   free(pBuffer);
                   }
//-----------------------------------------------------------------------------
// Restore size & place from OS2.INI
//-----------------------------------------------------------------------------
               if ( !WinRestoreWindowPos(APPNAME, WINPOS, hwndFrame) )
                 WinSetWindowPos( hwndFrame, NULLHANDLE,
                                  Win_X, Win_Y, Win_CX, Win_CY,
                                  SWP_ACTIVATE|SWP_MOVE|SWP_SIZE|SWP_SHOW );
//-----------------------------------------------------------------------------
// Set Presentation Parameters
//-----------------------------------------------------------------------------
               WinSetPresParam( hwnd, PP_FONTNAMESIZE, sizeof(Font), Font );
               WinSetPresParam( hwnd, PP_BACKGROUNDCOLORINDEX,
                                sizeof(ColorPaleGray), (PVOID)&ColorPaleGray );
               WinSetPresParam( hwnd, PP_FOREGROUNDCOLORINDEX,
                                sizeof(ColorBlack), (PVOID)&ColorBlack );
               WinSetPresParam( hwndCntnr, PP_BACKGROUNDCOLORINDEX,
                                sizeof(ColorWhite), (PVOID)&ColorWhite );
               WinSetPresParam( hwndCntnr, PP_FOREGROUNDCOLORINDEX,
                                sizeof(ColorBlack), (PVOID)&ColorBlack );
               WinSetPresParam( hwndCntnr, PP_HILITEBACKGROUNDCOLORINDEX,
                                sizeof(ColorCyan), (PVOID)&ColorCyan );
               WinSetPresParam( hwndCntnr, PP_HILITEFOREGROUNDCOLORINDEX,
                                sizeof(ColorBlack), (PVOID)&ColorBlack );
               WinSetPresParam( hwndStaticTxt, PP_BACKGROUNDCOLORINDEX,
                                sizeof(ColorGreen), (PVOID)&ColorGreen );
               WinSetPresParam( hwndStaticTxt, PP_FOREGROUNDCOLORINDEX,
                                sizeof(ColorBlack), (PVOID)&ColorBlack);
//-----------------------------------------------------------------------------
// Test Parameters and Get Storage
//-----------------------------------------------------------------------------
               if ( ac != 3 )
                 {
                 SendErrMsg(hwnd, "Syntax: ViewLS <IP address> port");
                 break;
                 }

               myaddr = resolv(hwnd, av[1]);
               myaddr.sin_port = htons((unsigned short)atoi(av[2]));
               myaddr.sin_family = AF_INET;
               memcpy((char *)&myaddrRun, (char *)&myaddr, sizeof(myaddr));

               GetStorage();
//-----------------------------------------------------------------------------
// Set Priority for current Thread, Create Semaphors and Threads
//-----------------------------------------------------------------------------
               DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L16, L0);

               DosCreateEventSem( (ULONG)NULL, &hevEventHandle,
                                  DC_SEM_SHARED, FALSE );
               DosCreateEventSem( (ULONG)NULL, &hevEventHandleRun,
                                  DC_SEM_SHARED, FALSE );

               DosCreateThread( &tid,
                                (PFNTHREAD) DoView,
                                hwnd,
                                CREATE_READY | STACK_SPARSE,
                                L65536 );
               DosCreateThread( &tidRun,
                                (PFNTHREAD) DoRun,
                                hwnd,
                                CREATE_READY | STACK_SPARSE,
                                L65536 );

               WinDlgBox (HWND_DESKTOP, // Parent
                          hwnd,         // Owner
                          DlgProcView,  // Dialog window procedure
                          NULLHANDLE,   // Where is dialog resource?
                          DIALOGVIEWPW, // Dialog Resource ID
                          0);       // Create parms (for WM_INITDLG)
               if ( FlagPW ) DosPostEventSem(hevEventHandle);

               WinSetFocus( HWND_DESKTOP, hwnd );  // Установим фокус
               break;
               }
//-----------------------------------------------------------------------------
// WM_SIZE occurs during every resize, size setting event
//-----------------------------------------------------------------------------
          case WM_SIZE:
               {
               int x = (SHORT1FROMMP(mp2)-(4*PB_CX))/5;

               WinSetWindowPos(hwndButtonRun,      // Place and size button
                               HWND_TOP,           // ONTOP in Z-order
                               x,                  // x coord
                               Y,                  // y coord
                               PB_CX,              // cx size
                               PB_CY,              // cy size
                               SWP_SIZE|SWP_MOVE); // Change size|move
               WinSetWindowPos(hwndButtonView,     // Place and size button
                               HWND_TOP,           // ONTOP in Z-order
                               2*x+PB_CX,          // x coord
                               Y,                  // y coord
                               PB_CX,              // cx size
                               PB_CY,              // cy size
                               SWP_SIZE|SWP_MOVE); // Change size|move
               WinSetWindowPos(hwndButtonSave,     // Place and size button
                               HWND_TOP,           // ONTOP in Z-order
                               3*x+2*PB_CX,        // x coord
                               Y,                  // y coord
                               PB_CX,              // cx size
                               PB_CY,              // cy size
                               SWP_SIZE|SWP_MOVE); // Change size|move
               WinSetWindowPos(hwndButtonExit,     // Place and size button
                               HWND_TOP,           // ONTOP in Z-order
                               4*x+3*PB_CX,        // x coord
                               Y,                  // y coord
                               PB_CX,              // cx size
                               PB_CY,              // cy size
                               SWP_SIZE|SWP_MOVE); // Change size|move
               WinSetWindowPos(hwndCntnr,          // Place and size container
                               HWND_TOP,           // ONTOP in Z-order
                               0,                  // x coord
                               Y+PB_CY+Y+Txt_Y,    // y coord
                               SHORT1FROMMP(mp2),  // cx size
                               SHORT2FROMMP(mp2)-(Y+PB_CY+Y+Txt_Y),
                               SWP_SIZE|SWP_MOVE); // Change size|move
               WinSetWindowPos(hwndStaticTxt,      // Place and size container
                               HWND_TOP,           // ONTOP in Z-order
                               0,                  // x coord
                               Y+PB_CY+Y,          // y coord
                               SHORT1FROMMP(mp2),  // cx size
                               Txt_Y,              // cy size
                               SWP_SIZE|SWP_MOVE); // Change size|move
               break;
               }
//-----------------------------------------------------------------------------
// Save the window size and position on exit
//-----------------------------------------------------------------------------
          case WM_SAVEAPPLICATION:
               {
//-----------------------------------------------------------------------------
// Check if window is minimized and restore to original size
//-----------------------------------------------------------------------------
               if ( WinQueryWindowULong(hwndFrame, QWL_STYLE) & WS_MINIMIZED )
                 WinSetWindowPos(hwndFrame, HWND_TOP, 0, 0, 0, 0, SWP_RESTORE);
//-----------------------------------------------------------------------------
// Store window information in OS2.INI
//-----------------------------------------------------------------------------
               WinStoreWindowPos( APPNAME,
                                  WINPOS,
                                  WinQueryWindow(hwnd, QW_PARENT) );
//-----------------------------------------------------------------------------
// Copy the Window position info from the OS2.INI into private INI file
//-----------------------------------------------------------------------------
               PrfQueryProfileSize(HINI_USERPROFILE, APPNAME, WINPOS, &ulSize);
               pBuffer = calloc(ulSize, L1);
               PrfQueryProfileData( HINI_USERPROFILE, APPNAME, WINPOS,
                                    pBuffer, &ulSize);
               PrfWriteProfileData(HINI_USERPROFILE, APPNAME, NULL, NULL, 0);
               hini = PrfOpenProfile(hab, INIname); // Open private profile
               PrfWriteProfileData(hini, APPNAME, WINPOS, pBuffer, ulSize);
               PrfCloseProfile(hini);   // Close private profile
               free(pBuffer);

               break;
               }
//-----------------------------------------------------------------------------
// Формирование строки завершено
//-----------------------------------------------------------------------------
          case WM_USER_LINE_DONE:
               {
               InsertRecord(LONGFROMMP(mp1), LONGFROMMP(mp2));
               break;
               }
//-----------------------------------------------------------------------------
// Выведем имя сервера LanScan
//-----------------------------------------------------------------------------
          case WM_USER_SRV_NAME:
            {
            WinSetWindowText(hwndStaticTxt, SrvBufN);
            break;
            }
//-----------------------------------------------------------------------------
// Сканирование начато
//-----------------------------------------------------------------------------
          case WM_USER_SCAN_START:
            {
            WinSetWindowText(hwndStaticTxt, SrvBufN);

            WinPostMsg( WinWindowFromID(hwnd, CONTAINER_ID),
                        CM_REMOVEDETAILFIELDINFO, NULL,
                        MPFROM2SHORT(L0, CMA_FREE | CMA_INVALIDATE) );

            WinDestroyWindow(hwndCntnr); // Заново создадим окно
            hwndCntnr = WinCreateWindow(hwnd,     // Parent
                               WC_CONTAINER,      // Window class
                               NULL,              // Window text
                               CCS_READONLY | CCS_SINGLESEL | WS_VISIBLE,
                               0, 0, 0, 0,        // no size or position now
                               hwnd,              // Owner handle
                               HWND_TOP,          // Z-order ontop
                               CONTAINER_ID,      // Window ID
                               0,                 // Control
                               0);                // Presentation Parameters
            WinQueryWindowPos( hwnd, (PSWP)&swp );
            WinSetWindowPos(hwndCntnr,             // Place and size container
                               HWND_TOP,           // ONTOP in Z-order
                               0,                  // x coord
                               Y+PB_CY+Y+Txt_Y,    // y coord
                               swp.cx,             // cx size
                               swp.cy-(Y+PB_CY+Y+Txt_Y), // cy size
                               SWP_SIZE|SWP_MOVE); // Change size|move
            WinSetPresParam( hwndCntnr, PP_BACKGROUNDCOLORINDEX,
                             sizeof(ColorWhite), (PVOID)&ColorWhite );
            WinSetPresParam( hwndCntnr, PP_FOREGROUNDCOLORINDEX,
                             sizeof(ColorBlack), (PVOID)&ColorBlack );
            WinSetPresParam( hwndCntnr, PP_HILITEBACKGROUNDCOLORINDEX,
                             sizeof(ColorCyan), (PVOID)&ColorCyan );
            WinSetPresParam( hwndCntnr, PP_HILITEFOREGROUNDCOLORINDEX,
                             sizeof(ColorBlack), (PVOID)&ColorBlack );

            InitContainer(NBresult);
            break;
            }
//-----------------------------------------------------------------------------
// Сканирование завершено
//-----------------------------------------------------------------------------
          case WM_USER_SCAN_DONE:
            {
            WinEnableControl(hwnd, PB_VIEW, TRUE);
            if ( FlagSave ) WinEnableControl(hwnd, PB_SAVE, TRUE);
            WinInvalidateRegion(hwnd, NULLHANDLE, TRUE); // обновим окно
            break;
            }
//-----------------------------------------------------------------------------
// Ошибка при сканировании
//-----------------------------------------------------------------------------
          case WM_USER_SCAN_ERROR:
               {
               SendErrMsg(hwnd, ErrMsg);
               break;
               }
//-----------------------------------------------------------------------------
// Ошибка при сканировании
//-----------------------------------------------------------------------------
          case WM_USER_SCAN_WARNING:
               {
               SendWngMsg(hwnd, ErrMsg);
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

                DosExecPgm( LoadError,
                            sizeof(LoadError),
                            EXEC_ASYNC,
                            CmdLine,
                            (PSZ)NULL,
                            &ChieldRC,
                            CmdLine );
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
                         WinEnableMenuItem( (HWND)mp2, ITEM_VIEW, Post == 0 );
                         WinEnableMenuItem( (HWND)mp2, ITEM_SAVE,
                                            (Post == 0) && FlagSave );
                         WinEnableMenuItem( (HWND)mp2, ITEM_SAVEAS,
                                            (Post == 0) && FlagSave );
                         break;
                         }
                    }
               }
          break;
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
                         WinPostMsg(hwnd, WM_CLOSE, 0L, 0L);
                         break;
                         }
//-----------------------------------------------------------------------------
// Вывести Help
//-----------------------------------------------------------------------------
                    case ITEM_GENERAL_HELP:
                         {
                         UCHAR LoadError[CCHMAXPATH] = { 0 };
                         RESULTCODES ChieldRC = { 0 };
                         char CommandLine[] = "view.exe\0LanScan.Inf\0";

                         DosExecPgm( LoadError,
                                     sizeof(LoadError),
                                     EXEC_ASYNC,
                                     CommandLine,
                                     (PSZ)NULL,
                                     &ChieldRC,
                                     CommandLine );
                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Рассказать о себе
//-----------------------------------------------------------------------------
                    case ITEM_ABOUT:
                         {
                         WinDlgBox( HWND_DESKTOP,
                                    hwnd,
                                    WinDefDlgProc,
                                    NULLHANDLE,
                                    ABOUT_ID,
                                    0 );
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
                    case PB_SAVE:
                    case ITEM_SAVE:
                         {
                         if ( szFullPath[0] != '\0' )
                           DoSave(hwnd, szFullPath);
                         else
                           if ( GetFileName(szFullPath) )
                             DoSave(hwnd, szFullPath);

                         WinSetFocus( HWND_DESKTOP, hwndCntnr );
                         break;
                         }
//-----------------------------------------------------------------------------
// Выполнить сканирование
//-----------------------------------------------------------------------------
                    case PB_RUN:
                    case ITEM_RUN:
                         {
                         if ( !FlagPWrun ) WinDlgBox (HWND_DESKTOP,
                                        hwnd,
                                        DlgProcRun,
                                        NULLHANDLE,
                                        DIALOGRUNPW,
                                        0);
                         if ( FlagPWrun ) DosPostEventSem(hevEventHandleRun);
                         break;
                         }
//-----------------------------------------------------------------------------
// Выполнить вывод результатов сканирования
//-----------------------------------------------------------------------------
                    case PB_VIEW:
                    case ITEM_VIEW:
                         {
                         if ( !FlagPW ) WinDlgBox (HWND_DESKTOP,
                                        hwnd,
                                        DlgProcView,
                                        NULLHANDLE,
                                        DIALOGVIEWPW,
                                        0);
                         if ( FlagPW ) DosPostEventSem(hevEventHandle);
                         break;
                         }
                    }
               }
          break;
          }
     return (WinDefWindowProc (hwnd,msg,mp1,mp2));
     }

//=============================================================================
// DoView - программа получения результатов сканирования
//=============================================================================
void APIENTRY DoView(ULONG parmHwnd)
{
char NetBuf[PWDLEN+L4], Line[L128];
int sock;
FILE *File;

  DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L15, L0);

for (;;)
  {
  DosWaitEventSem(hevEventHandle, SEM_INDEFINITE_WAIT);
  WinEnableControl(parmHwnd, PB_VIEW, FALSE);
  WinEnableControl(parmHwnd, PB_SAVE, FALSE);
  FlagSave = FALSE;

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

// Connect to the server.
  if ( connect(sock, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0 )
    {
    PostWngMsg(parmHwnd, "Error in connect");
    DosResetEventSem( hevEventHandle, &ulPostCnt);
    WinPostMsg (parmHwnd, WM_USER_SCAN_DONE, 0L, 0L);
    soclose(sock);
    continue;
    }

  memset(NetBuf, '\0', sizeof(NetBuf));
  strcpy(NetBuf, "See");
  strcat(NetBuf, ViewPW);
  send(sock, NetBuf, PWDLEN+L4, L0);

  if ( !RcvFile(sock, FileResultName) )
    {
    DosResetEventSem( hevEventHandle, &ulPostCnt);
    WinPostMsg (parmHwnd, WM_USER_SCAN_DONE, 0L, 0L);
    continue;
    }

  File = fopen(FileResultName, "r");

  fgets(SrvBufN, sizeof(pszCnrTitle), File);
  SrvBufN[strlen(SrvBufN)-L1] = '\0';

  fgets(pszCnrTitle, sizeof(pszCnrTitle), File);
  pszCnrTitle[strlen(pszCnrTitle)-L1] = '\0';
  NBresult = FALSE;
  if ( strstr(pszCnrTitle, " Domain -") != NULL ) NBresult = TRUE;

  WinPostMsg (parmHwnd, WM_USER_SCAN_START, L0, L0);
  WinPostMsg (parmHwnd, WM_USER_SRV_NAME, L0, L0);

  fgets(Line, sizeof(Line), File); // Пропустим наименования колонок

  IP=IPfirst;
  MAC=MACfirst;
  FQDN=FQDNfirst;
  NETBN=NETBNfirst;
  CurrNum = 0;
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

    CNI = FindOUI();
    WinPostMsg ( parmHwnd,
                 WM_USER_LINE_DONE,
                 MPFROMLONG(CurrNum++),
                 MPFROMLONG(CNI) );
    IP += IPLEN;
    MAC += MACLEN;
    FQDN += FQDNLEN;
    NETBN += UNCLEN;
    }

  fclose(File);
  DosResetEventSem( hevEventHandle, &ulPostCnt);
  FlagSave = TRUE;
  WinPostMsg (parmHwnd, WM_USER_SCAN_DONE, 0L, 0L);
  }
}

//=============================================================================
// DoRun - программа инициирования сканирования
//=============================================================================
void APIENTRY DoRun(ULONG parmHwnd)
{
char NetBuf[PWDLEN+L4];
int sock;

  DosSetPriority(PRTYS_THREAD, PRTYC_REGULAR, L15, L0);

for (;;)
  {
  DosWaitEventSem(hevEventHandleRun, SEM_INDEFINITE_WAIT);

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

// Connect to the server.
  if ( connect(sock, (struct sockaddr *)&myaddrRun, sizeof(myaddrRun)) < 0 )
    {
    PostWngMsg(parmHwnd, "Error in connect");
    DosResetEventSem( hevEventHandleRun, &ulPostCnt);
    soclose(sock);
    continue;
    }

  memset(NetBuf, '\0', sizeof(NetBuf));
  strcpy(NetBuf, "Run");
  strcat(NetBuf, RunPW);
  send(sock, NetBuf, PWDLEN+L4, L0);

  soclose(sock);

  DosResetEventSem( hevEventHandleRun, &ulPostCnt);
  }
}

//=============================================================================
// DoSave - подпрограмма сохранения результатов сканирования в текстовом виде
//=============================================================================
void DoSave(HWND hwnd, char *File)
{
FILE *InFile, *OutFile;
char Line[L128];

  if ( (OutFile = fopen(File, "w")) == NULL )
    {
    sprintf(ErrMsg, "Error in fopen for %s", File);
    SendWngMsg(hwnd, ErrMsg);
    return;
    }

  InFile = fopen(FileResultName, "r");
  while ( fgets(Line, sizeof(Line), InFile) != NULL ) fputs(Line, OutFile);

  fclose(InFile);
  fclose(OutFile);
}

//=============================================================================
// DlgProcView - window procedure for the View password
//=============================================================================
MRESULT EXPENTRY DlgProcView (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
{
  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      WinSendDlgItemMsg(hwndDlg, VIEW_PW, EM_SETTEXTLIMIT, (MPARAM)L15, 0);
      memset(ViewPW, '\0', PWDLEN);
      WinSetDlgItemText(hwndDlg, VIEW_PW, ViewPW);
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
          WinQueryDlgItemText(hwndDlg, VIEW_PW, PWDLEN, ViewPW);
          FlagPW = TRUE;
          break;
          }
        }
      }
      break;
    }
    return (WinDefDlgProc (hwndDlg,msg,mp1,mp2));
}

//=============================================================================
// DlgProcRun - window procedure for the Run password
//=============================================================================
MRESULT EXPENTRY DlgProcRun (HWND hwndDlg, ULONG msg, MPARAM mp1, MPARAM mp2)
{
  switch (msg)
    {
//-----------------------------------------------------------------------------
// Init the dialog
//-----------------------------------------------------------------------------
    case WM_INITDLG:
      {
      WinSendDlgItemMsg(hwndDlg, RUN_PW, EM_SETTEXTLIMIT, (MPARAM)L15, 0);
      memset(RunPW, '\0', PWDLEN);
      WinSetDlgItemText(hwndDlg, RUN_PW, RunPW);
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
          WinQueryDlgItemText(hwndDlg, RUN_PW, PWDLEN, RunPW);
          FlagPWrun = TRUE;
          break;
          }
        }
      }
      break;
    }
    return (WinDefDlgProc (hwndDlg,msg,mp1,mp2));
}

#include "SubPgm\FindOUI.c"
#include "SubPgm\GetFileName.c"
#include "SubPgm\GetStorage.c"
#include "SubPgm\InitContainer.c"
#include "SubPgm\Insertrecord.c"
#include "SubPgm\PostWngMsg.c"
#include "SubPgm\RcvFile.c"
#include "SubPgm\resolv.c"
#include "SubPgm\SendErrMsg.c"
#include "SubPgm\SendWngMsg.c"
