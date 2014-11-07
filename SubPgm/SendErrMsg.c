//=============================================================================
// SendErrMsg - подпрограмма выдачи сообщений об ошибках
//=============================================================================
void SendErrMsg(HWND hwnd, char *ptr)
{
   WinMessageBox( HWND_DESKTOP,
                  hwnd,
                  ptr,
                  "LanScan Error",
                  0,
                  MB_OK | MB_APPLMODAL | MB_ERROR );
   WinPostMsg(hwnd, WM_CLOSE, 0L, 0L);
}
