//=============================================================================
// FindOUI - процедура поиска производителя сетевой карты
//=============================================================================
_inline short FindOUI (void)
{
short FirstCNI, LastCNI, n, i;

  FirstCNI = 0;
  i = LastCNI = NumOUI;
  while ( FirstCNI <= LastCNI )
    {
    i = (FirstCNI+LastCNI)/2;
    n = memcmp(MAC, CompNfirst+COMPNLEN*i, L7);
    if ( n < 0 ) LastCNI = i-1;
    else
      if ( n > 0 ) FirstCNI = i+1;
      else break;
    i = NumOUI;
    }

  return i;
}