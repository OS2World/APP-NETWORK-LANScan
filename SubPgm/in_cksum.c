//=============================================================================
//	   I N _ C K S U M
// Checksum routine for Internet Protocol family headers (C Version)
//=============================================================================
_inline u_short in_cksum(u_short* addr, int Len)
{
   register int nleft = Len;
   register u_short *w = addr;
   register int sum = 0;
   u_short answer = 0;

//-----------------------------------------------------------------------------
// Our algorithm is simple, using a 32 bit accumulator (sum),
// we add sequential 16 bit words to it, and at the end,
// fold back all the carry bits from the top 16 bits into the lower 16 bits.
//-----------------------------------------------------------------------------
   while( nleft > 1 )
      {
      sum += *w++;
      nleft -= 2;
      }

//-----------------------------------------------------------------------------
// mop up an odd byte, if necessary
//-----------------------------------------------------------------------------
   if ( nleft == 1 )
      {
      *(u_char *)(&answer) = *(u_char *)w ;
      sum += answer;
      }

//-----------------------------------------------------------------------------
// add back carry outs from top 16 bits to low 16 bits
//-----------------------------------------------------------------------------
   sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
   sum += (sum >> 16);                 // add possible carry
   answer = (u_short)~sum;             // ones complement & truncate to 16 bits
   return (answer);
}
