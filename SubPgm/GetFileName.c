//=============================================================================
// GetFileName - подпрограмма вызова диалога Save As ...
//=============================================================================
BOOL GetFileName(char *path)
{
   static HWND hwndMLE;
   FILEDLG fileDialog;
   CHAR szButton[] = "Ok";
   char title[] = "Set name for saving LanScan results as TEXT file";

   fileDialog.cbSize = sizeof(FILEDLG);       // Size of FILEDLG structure
   fileDialog.fl = FDS_SAVEAS_DIALOG | FDS_ENABLEFILELB; // FDS_ flags.
   fileDialog.ulUser = 0UL;           // User defined field
   fileDialog.lReturn = 0L;           // Result code from dialog dismissal
   fileDialog.lSRC = 0L;              // System return code
   fileDialog.pszTitle = title;     // String to display in title bar
   fileDialog.pszOKButton = szButton; // String to display in OK button
   fileDialog.pfnDlgProc = NULL;      // Entry point to custom dialog proc.
   fileDialog.pszIType = NULL;        // Pointer to string containing initial
                                      // EA type filter. Type does not have
                                      // to exist in list.
   fileDialog.papszITypeList = NULL;  // Pointer to table of pointers that
                                      // point to null terminated Type strings.
                                      // End of table is marked by a NULL ptr.
   fileDialog.pszIDrive = NULL;  // Pointer to string containing initial drive.
                                 // Drive does not have to exist in drive list.
   fileDialog.papszIDriveList = NULL; // Pointer to table of pointers that
                                      // point to null terminated Drive strings
                                      // End of table is marked by a NULL ptr.
   fileDialog.hMod = (HMODULE)0;              // Custom File Dialog template
   strcpy(fileDialog.szFullFile, path);       // Initial or selected fully
                                              // qualified path and file.
   fileDialog.papszFQFilename = NULL; // Pointer to table of pointers that
                                      // point to null terminated FQFname
                                      // strings. End of table is marked
                                      // by a NULL pointer.
   fileDialog.ulFQFCount = 0UL;               // Number of files selected
   fileDialog.usDlgId = IDD_FILESAVE;         // Custom dialog id.
   fileDialog.x = 0;                          // X coordinate of the dialog
   fileDialog.y = 0;                          // Y coordinate of the dialog
   fileDialog.sEAType = 0;                    // Selected file's EA Type.
//-----------------------------------------------------------------------------
// Get the file name
//-----------------------------------------------------------------------------
   if (!WinFileDlg(HWND_DESKTOP, hwndMLE, (PFILEDLG)&fileDialog)) return FALSE;
   if (fileDialog.lReturn != DID_OK) return FALSE;
//-----------------------------------------------------------------------------
// Copy file name and path returned into buffers
//-----------------------------------------------------------------------------
   strcpy(path, fileDialog.szFullFile);
   return TRUE;
}
