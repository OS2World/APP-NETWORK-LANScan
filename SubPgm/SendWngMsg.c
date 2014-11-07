//=============================================================================
// SendWngMsg - подпрограмма выдачи сообщений об ошибках (warning)
//=============================================================================
void SendWngMsg(HWND hwnd, char *ptr)
{
   WinMessageBox( HWND_DESKTOP,
                  hwnd,
                  ptr,
                  "LanScan Warning",
                  0,
                  MB_OK | MB_APPLMODAL | MB_WARNING );
}
