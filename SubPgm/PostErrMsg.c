//=============================================================================
// PostErrMsg - подпрограмма информирования о наличии ошибки
//=============================================================================
void PostErrMsg(ULONG pHwnd, char *ptr)
{
   DosResetEventSem( hevEventHandle, &ulPostCnt );
   strcpy(ErrMsg, ptr);
   WinPostMsg( pHwnd, WM_USER_SCAN_ERROR, 0L, 0L );
   DosSuspendThread(tid);
#ifdef LANSCAN
   DosSuspendThread(tidCFG);
   DosSuspendThread(tidView);
#endif
#ifdef VIEW_LS
   DosSuspendThread(tidRun);
#endif
}
