//=============================================================================
// PostWngMsg - ����ணࠬ�� ���ନ஢���� � ����稨 �訡��
//=============================================================================
void PostWngMsg(ULONG pHwnd, char *ptr)
{
   strcpy(ErrMsg, ptr);
   WinPostMsg( pHwnd, WM_USER_SCAN_WARNING, 0L, 0L );
}
