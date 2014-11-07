//=============================================================================
// GetFontName - подпрограмма вызова диалога Set Font ...
//=============================================================================
void GetFontName(char *buf)
{
HPS  hpsScreen;    // Screen presentation space
HWND hwndFontDlg;  // Font dialog window
char szTitle[] = "Set font for LanScan";

  hpsScreen=WinGetPS(hwndCntnr);  // Get handle to presentation space
  pfdFontdlg.pszFamilyname = InitFont; // Use default font
// Initialize those fields in the FONTDLG structure
  pfdFontdlg.hpsScreen=hpsScreen; // Screen presentation space
  if ( FontSetFl )
    {
    pfdFontdlg.cbSize=sizeof(FONTDLG);     // Size of structure
    pfdFontdlg.pszTitle = szTitle;         // Заголовок
    pfdFontdlg.usFamilyBufLen = FACESIZE;  // Length of family name buffer
    pfdFontdlg.fxPointSize = MAKEFIXED(9, 0); // Font point size
    pfdFontdlg.usWeight=FWEIGHT_NORMAL;       // Нормальный фонт
    pfdFontdlg.fl = FNTS_CENTER;    // Центрируем
    pfdFontdlg.clrFore=CLR_BLACK;   // Foreground color
    pfdFontdlg.clrBack=CLR_WHITE;   // Background color
    }
// Display the font dialog and get the font
  hwndFontDlg = WinFontDlg(HWND_DESKTOP, hwndCntnr, &pfdFontdlg);
  if ( hwndFontDlg && (pfdFontdlg.lReturn==DID_OK) )
    {
    sprintf(buf, "%d.%s", FIXEDINT(pfdFontdlg.fxPointSize),
                          pfdFontdlg.fAttrs.szFacename);
    WinSetPresParam(hwndCntnr, PP_FONTNAMESIZE, strlen(buf)+L1, buf);
    FontSetFl = FALSE;
    }
  WinReleasePS(hpsScreen);
}