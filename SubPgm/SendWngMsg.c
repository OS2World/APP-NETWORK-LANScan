//=============================================================================
// SendWngMsg - ����ணࠬ�� �뤠� ᮮ�饭�� �� �訡��� (warning)
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
