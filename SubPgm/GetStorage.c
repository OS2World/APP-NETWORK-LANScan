//=============================================================================
// GetStorage - подпрограмма получения ОП и своих MAC-адресов
//=============================================================================
void GetStorage(void)
{
#ifndef VIEW_LS
int sock;
struct ifmib *stat;
#endif
int i;
FILE *FileOUI;
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
void *initial_block;
static Heap_t myheap;
#endif

#ifndef TCPV40HDRS    // Выключить для TCP/IP 4.0
// Call DosAllocMem to get the initial block of memory
  DosAllocMem(&initial_block, L65536, PAG_WRITE | PAG_READ | PAG_COMMIT);
// Create an expandable heap starting with the block declared earlier
  myheap = _ucreate(initial_block, L65536, _BLOCK_CLEAN, _HEAP_REGULAR,
                    get_fn, release_fn);
  _uopen(myheap);

#ifndef VIEW_LS
  pB = (char *)_umalloc(myheap, (UNCLEN-1)*L254);
  Net32Buf = (char *)_umalloc(myheap, L1024);
  pWkInf = (struct wksta_info_1 *)Net32Buf;
  pSes = (char *)_umalloc(myheap, L4096);

  NBfirst = (char *)_umalloc(myheap, UNCLEN*L254);
  NBIPfirst = (char *)_umalloc(myheap, IPLEN*L254);
  MACNBfirst = (char *)_umalloc(myheap, MACLEN*L254);
#endif

  IPfirst = (char *)_umalloc(myheap, IPLEN*NUMADR);
  MACfirst = (char *)_umalloc(myheap, MACLEN*NUMADR);
  FQDNfirst = (char *)_umalloc(myheap, FQDNLEN*NUMADR);
  NETBNfirst = (char *)_umalloc(myheap, UNCLEN*NUMADR);

#else
#ifndef VIEW_LS
  pB = calloc((UNCLEN-1)*L254, L1);
  Net32Buf = calloc(L1024, L1);
  pWkInf = (struct wksta_info_1 *)Net32Buf;
  pSes = calloc(L4096, L1);

  NBfirst = malloc(UNCLEN*L254);
  NBIPfirst = malloc(IPLEN*L254);
  MACNBfirst = malloc(MACLEN*L254);
#endif

  IPfirst = malloc(IPLEN*NUMADR);
  MACfirst = malloc(MACLEN*NUMADR);
  FQDNfirst = malloc(FQDNLEN*NUMADR);
  NETBNfirst = malloc(UNCLEN*NUMADR);
#endif
//-----------------------------------------------------------------------------
// Сформируем массив "Наименование компании"
//-----------------------------------------------------------------------------
  if ( (FileOUI = fopen("oui.lst", "r")) == NULL )
    CompNfirst=calloc(COMPNLEN*NumOUI+L7, L1);
  else
    {
    for (; fgets(IPfirst, COMPNLEN, FileOUI) != NULL; ) NumOUI++;
#ifndef TCPV40HDRS    // Выключить для TCP/IP 4.0
    CompNfirst=(char *)_umalloc(myheap, COMPNLEN*NumOUI+L1);
    memset(CompNfirst, '\0', COMPNLEN*NumOUI+L1);
#else
    CompNfirst=calloc(COMPNLEN*NumOUI+L1, L1);
#endif
    rewind(FileOUI);

    for (i=0, CompN = CompNfirst; i<NumOUI; i++, CompN+=COMPNLEN)
      {
      fgets(CompN, COMPNLEN, FileOUI);
      if ( strlen(CompN) > 0 )
         if ( CompN[strlen(CompN)-1] == '\x0a' ) CompN[strlen(CompN)-1]='\0';
      }

    fclose(FileOUI);
    }

//-----------------------------------------------------------------------------
// Найдем свои MAC-адреса
//-----------------------------------------------------------------------------
#ifndef VIEW_LS
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  stat = malloc(sizeof(struct ifmib));

  NBI1 = malloc(L254*sizeof(struct netbios_info_1));
  bufFind = (char *)NBI1;

#ifdef TCPV40HDRS    // Включить для TCP/IP 4.0
  ioctl(sock, SIOSTATIF42, (char *)stat, sizeof(struct ifmib));

  memset(MyMAC, 0, sizeof(MyMAC));
  for( i=0; i < MAXIPADR; i++)
    if ( stat->iftable[i].ifMtu != 0 )
      memcpy(&MyMAC[i*L6], stat->iftable[i].ifPhysAddr, L6);
#else                // Исключить для TCP/IP 4.0
  os2_ioctl(sock, SIOSTATIF42, (char *)stat, sizeof(struct ifmib));

//-----------------------------------------------------------------------------
// Найдем свои MAC-адреса
//-----------------------------------------------------------------------------
  memset(MyMAC, 0, sizeof(MyMAC));
  for( i=0; i < MAXIPADR; i++)
    if ( stat->iftable[i].iftMtu != 0 )
      memcpy(&MyMAC[i*L6], stat->iftable[i].iftPhysAddr, L6);
#endif               // TCPV40HDRS
  soclose(sock);
  free(stat);
#endif
}
