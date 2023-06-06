#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

#include <stdlib.h>

#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../ballet/sha512/fd_sha512.h"
#include "../../../util/fd_util.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"
#include "../../aio/fd_aio.h"
#include "../../xdp/fd_xdp.h"
#include "../fd_quic.c"

#define INITIAL_PKT_LEN 1200

/* Sample INITIAL packet from RFC 9001 */
#define INITIAL_PKT                                                                                \
  ( (uchar *)"\xc0\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x44\x9e\x7b\x9a"    \
             "\xec\x34\xd1\xb1\xc9\x8d\xd7\x68\x9f\xb8\xec\x11\xd2\x42\xb1\x23\xdc\x9b\xd8\xba"    \
             "\xb9\x36\xb4\x7d\x92\xec\x35\x6c\x0b\xab\x7d\xf5\x97\x6d\x27\xcd\x44\x9f\x63\x30"    \
             "\x00\x99\xf3\x99\x1c\x26\x0e\xc4\xc6\x0d\x17\xb3\x1f\x84\x29\x15\x7b\xb3\x5a\x12"    \
             "\x82\xa6\x43\xa8\xd2\x26\x2c\xad\x67\x50\x0c\xad\xb8\xe7\x37\x8c\x8e\xb7\x53\x9e"    \
             "\xc4\xd4\x90\x5f\xed\x1b\xee\x1f\xc8\xaa\xfb\xa1\x7c\x75\x0e\x2c\x7a\xce\x01\xe6"    \
             "\x00\x5f\x80\xfc\xb7\xdf\x62\x12\x30\xc8\x37\x11\xb3\x93\x43\xfa\x02\x8c\xea\x7f"    \
             "\x7f\xb5\xff\x89\xea\xc2\x30\x82\x49\xa0\x22\x52\x15\x5e\x23\x47\xb6\x3d\x58\xc5"    \
             "\x45\x7a\xfd\x84\xd0\x5d\xff\xfd\xb2\x03\x92\x84\x4a\xe8\x12\x15\x46\x82\xe9\xcf"    \
             "\x01\x2f\x90\x21\xa6\xf0\xbe\x17\xdd\xd0\xc2\x08\x4d\xce\x25\xff\x9b\x06\xcd\xe5"    \
             "\x35\xd0\xf9\x20\xa2\xdb\x1b\xf3\x62\xc2\x3e\x59\x6d\x11\xa4\xf5\xa6\xcf\x39\x48"    \
             "\x83\x8a\x3a\xec\x4e\x15\xda\xf8\x50\x0a\x6e\xf6\x9e\xc4\xe3\xfe\xb6\xb1\xd9\x8e"    \
             "\x61\x0a\xc8\xb7\xec\x3f\xaf\x6a\xd7\x60\xb7\xba\xd1\xdb\x4b\xa3\x48\x5e\x8a\x94"    \
             "\xdc\x25\x0a\xe3\xfd\xb4\x1e\xd1\x5f\xb6\xa8\xe5\xeb\xa0\xfc\x3d\xd6\x0b\xc8\xe3"    \
             "\x0c\x5c\x42\x87\xe5\x38\x05\xdb\x05\x9a\xe0\x64\x8d\xb2\xf6\x42\x64\xed\x5e\x39"    \
             "\xbe\x2e\x20\xd8\x2d\xf5\x66\xda\x8d\xd5\x99\x8c\xca\xbd\xae\x05\x30\x60\xae\x6c"    \
             "\x7b\x43\x78\xe8\x46\xd2\x9f\x37\xed\x7b\x4e\xa9\xec\x5d\x82\xe7\x96\x1b\x7f\x25"    \
             "\xa9\x32\x38\x51\xf6\x81\xd5\x82\x36\x3a\xa5\xf8\x99\x37\xf5\xa6\x72\x58\xbf\x63"    \
             "\xad\x6f\x1a\x0b\x1d\x96\xdb\xd4\xfa\xdd\xfc\xef\xc5\x26\x6b\xa6\x61\x17\x22\x39"    \
             "\x5c\x90\x65\x56\xbe\x52\xaf\xe3\xf5\x65\x63\x6a\xd1\xb1\x7d\x50\x8b\x73\xd8\x74"    \
             "\x3e\xeb\x52\x4b\xe2\x2b\x3d\xcb\xc2\xc7\x46\x8d\x54\x11\x9c\x74\x68\x44\x9a\x13"    \
             "\xd8\xe3\xb9\x58\x11\xa1\x98\xf3\x49\x1d\xe3\xe7\xfe\x94\x2b\x33\x04\x07\xab\xf8"    \
             "\x2a\x4e\xd7\xc1\xb3\x11\x66\x3a\xc6\x98\x90\xf4\x15\x70\x15\x85\x3d\x91\xe9\x23"    \
             "\x03\x7c\x22\x7a\x33\xcd\xd5\xec\x28\x1c\xa3\xf7\x9c\x44\x54\x6b\x9d\x90\xca\x00"    \
             "\xf0\x64\xc9\x9e\x3d\xd9\x79\x11\xd3\x9f\xe9\xc5\xd0\xb2\x3a\x22\x9a\x23\x4c\xb3"    \
             "\x61\x86\xc4\x81\x9e\x8b\x9c\x59\x27\x72\x66\x32\x29\x1d\x6a\x41\x82\x11\xcc\x29"    \
             "\x62\xe2\x0f\xe4\x7f\xeb\x3e\xdf\x33\x0f\x2c\x60\x3a\x9d\x48\xc0\xfc\xb5\x69\x9d"    \
             "\xbf\xe5\x89\x64\x25\xc5\xba\xc4\xae\xe8\x2e\x57\xa8\x5a\xaf\x4e\x25\x13\xe4\xf0"    \
             "\x57\x96\xb0\x7b\xa2\xee\x47\xd8\x05\x06\xf8\xd2\xc2\x5e\x50\xfd\x14\xde\x71\xe6"    \
             "\xc4\x18\x55\x93\x02\xf9\x39\xb0\xe1\xab\xd5\x76\xf2\x79\xc4\xb2\xe0\xfe\xb8\x5c"    \
             "\x1f\x28\xff\x18\xf5\x88\x91\xff\xef\x13\x2e\xef\x2f\xa0\x93\x46\xae\xe3\x3c\x28"    \
             "\xeb\x13\x0f\xf2\x8f\x5b\x76\x69\x53\x33\x41\x13\x21\x19\x96\xd2\x00\x11\xa1\x98"    \
             "\xe3\xfc\x43\x3f\x9f\x25\x41\x01\x0a\xe1\x7c\x1b\xf2\x02\x58\x0f\x60\x47\x47\x2f"    \
             "\xb3\x68\x57\xfe\x84\x3b\x19\xf5\x98\x40\x09\xdd\xc3\x24\x04\x4e\x84\x7a\x4f\x4a"    \
             "\x0a\xb3\x4f\x71\x95\x95\xde\x37\x25\x2d\x62\x35\x36\x5e\x9b\x84\x39\x2b\x06\x10"    \
             "\x85\x34\x9d\x73\x20\x3a\x4a\x13\xe9\x6f\x54\x32\xec\x0f\xd4\xa1\xee\x65\xac\xcd"    \
             "\xd5\xe3\x90\x4d\xf5\x4c\x1d\xa5\x10\xb0\xff\x20\xdc\xc0\xc7\x7f\xcb\x2c\x0e\x0e"    \
             "\xb6\x05\xcb\x05\x04\xdb\x87\x63\x2c\xf3\xd8\xb4\xda\xe6\xe7\x05\x76\x9d\x1d\xe3"    \
             "\x54\x27\x01\x23\xcb\x11\x45\x0e\xfc\x60\xac\x47\x68\x3d\x7b\x8d\x0f\x81\x13\x65"    \
             "\x56\x5f\xd9\x8c\x4c\x8e\xb9\x36\xbc\xab\x8d\x06\x9f\xc3\x3b\xd8\x01\xb0\x3a\xde"    \
             "\xa2\xe1\xfb\xc5\xaa\x46\x3d\x08\xca\x19\x89\x6d\x2b\xf5\x9a\x07\x1b\x85\x1e\x6c"    \
             "\x23\x90\x52\x17\x2f\x29\x6b\xfb\x5e\x72\x40\x47\x90\xa2\x18\x10\x14\xf3\xb9\x4a"    \
             "\x4e\x97\xd1\x17\xb4\x38\x13\x03\x68\xcc\x39\xdb\xb2\xd1\x98\x06\x5a\xe3\x98\x65"    \
             "\x47\x92\x6c\xd2\x16\x2f\x40\xa2\x9f\x0c\x3c\x87\x45\xc0\xf5\x0f\xba\x38\x52\xe5"    \
             "\x66\xd4\x45\x75\xc2\x9d\x39\xa0\x3f\x0c\xda\x72\x19\x84\xb6\xf4\x40\x59\x1f\x35"    \
             "\x5e\x12\xd4\x39\xff\x15\x0a\xab\x76\x13\x49\x9d\xbd\x49\xad\xab\xc8\x67\x6e\xef"    \
             "\x02\x3b\x15\xb6\x5b\xfc\x5c\xa0\x69\x48\x10\x9f\x23\xf3\x50\xdb\x82\x12\x35\x35"    \
             "\xeb\x8a\x74\x33\xbd\xab\xcb\x90\x92\x71\xa6\xec\xbc\xb5\x8b\x93\x6a\x88\xcd\x4e"    \
             "\x8f\x2e\x6f\xf5\x80\x01\x75\xf1\x13\x25\x3d\x8f\xa9\xca\x88\x85\xc2\xf5\x52\xe6"    \
             "\x57\xdc\x60\x3f\x25\x2e\x1a\x8e\x30\x8f\x76\xf0\xbe\x79\xe2\xfb\x8f\x5d\x5f\xbb"    \
             "\xe2\xe3\x0e\xca\xdd\x22\x07\x23\xc8\xc0\xae\xa8\x07\x8c\xdf\xcb\x38\x68\x26\x3f"    \
             "\xf8\xf0\x94\x00\x54\xda\x48\x78\x18\x93\xa7\xe4\x9a\xd5\xaf\xf4\xaf\x30\x0c\xd8"    \
             "\x04\xa6\xb6\x27\x9a\xb3\xff\x3a\xfb\x64\x49\x1c\x85\x19\x4a\xab\x76\x0d\x58\xa6"    \
             "\x06\x65\x4f\x9f\x44\x00\xe8\xb3\x85\x91\x35\x6f\xbf\x64\x25\xac\xa2\x6d\xc8\x52"    \
             "\x44\x25\x9f\xf2\xb1\x9c\x41\xb9\xf9\x6f\x3c\xa9\xec\x1d\xde\x43\x4d\xa7\xd2\xd3"    \
             "\x92\xb9\x05\xdd\xf3\xd1\xf9\xaf\x93\xd1\xaf\x59\x50\xbd\x49\x3f\x5a\xa7\x31\xb4"    \
             "\x05\x6d\xf3\x1b\xd2\x67\xb6\xb9\x0a\x07\x98\x31\xaa\xf5\x79\xbe\x0a\x39\x01\x31"    \
             "\x37\xaa\xc6\xd4\x04\xf5\x18\xcf\xd4\x68\x40\x64\x7e\x78\xbf\xe7\x06\xca\x4c\xf5"    \
             "\xe9\xc5\x45\x3e\x9f\x7c\xfd\x2b\x8b\x4c\x8d\x16\x9a\x44\xe5\x5c\x88\xd4\xa9\xa7"    \
             "\xf9\x47\x42\x41\xe2\x21\xaf\x44\x86\x00\x18\xab\x08\x56\x97\x2e\x19\x4c\xd9\x34" )

fd_aio_pkt_info_t fd_aio_pkt_info_populate(
    fd_quic_t * quic,
    uchar **    tx_ptr_ptr,
    uchar *     tx_buf,
    ulong       tx_buf_sz,
    ulong *     tx_sz,
    uchar *     crypt_scratch,
    ulong       crypt_scratch_sz,
    uchar *     dst_mac_addr,
    ushort *    ipv4_id,
    uint        dst_ipv4_addr,
    ushort      src_udp_port,
    ushort      dst_udp_port,
    int         flush
) {
  (void)tx_buf_sz;
  (void)tx_sz;
  /* TODO leave space at front of tx_buf for header
          then encode directly into it to avoid 1 copy */
  uchar * tx_ptr     = *tx_ptr_ptr;
  long    payload_sz = tx_ptr - tx_buf;

  /* nothing to do */
  if ( FD_UNLIKELY( payload_sz <= 0L ) ) {
    if ( flush ) {
      /* send empty batch to flush tx */
      fd_aio_pkt_info_t aio_buf = { .buf = NULL, .buf_sz = 0 };
      int               aio_rc  = fd_aio_send( &quic->aio_tx, &aio_buf, 0, NULL, 1 );
      (void)aio_rc; /* don't care about result */
    }
    FD_LOG_ERR( ( "empty payload" ) );
  }

  fd_quic_config_t * config = &quic->config;

  uchar * cur_ptr = crypt_scratch;
  ulong   cur_sz  = crypt_scratch_sz;

  /* TODO much of this may be prepared ahead of time */
  fd_quic_pkt_t pkt;

  memcpy( pkt.eth->dst_addr, dst_mac_addr, 6 );
  memcpy( pkt.eth->src_addr, quic->config.link.src_mac_addr, 6 );
  pkt.eth->eth_type = 0x0800;

  pkt.ipv4->version  = 4;
  pkt.ipv4->ihl      = 5;
  pkt.ipv4->dscp     = config->net.dscp; /* could make this per-connection or per-stream */
  pkt.ipv4->ecn      = 0;                /* explicit congestion notification */
  pkt.ipv4->tot_len  = (ushort)( 20 + 8 + payload_sz );
  pkt.ipv4->id       = *ipv4_id++;
  pkt.ipv4->frag_off = 0x4000u; /* don't fragment */
  pkt.ipv4->ttl      = 64;      /* TODO make configurable */
  pkt.ipv4->protocol = FD_IP4_HDR_PROTOCOL_UDP;
  pkt.ipv4->check    = 0;
  pkt.ipv4->saddr    = config->net.ip_addr;
  pkt.ipv4->daddr    = dst_ipv4_addr;

  pkt.udp->srcport = src_udp_port;
  pkt.udp->dstport = dst_udp_port;
  pkt.udp->length  = (ushort)( 8 + payload_sz );
  pkt.udp->check   = 0x0000;

  /* todo use fd_util Ethernet / IPv4 impl */

  ulong rc = fd_quic_encode_eth( cur_ptr, cur_sz, pkt.eth );
  if ( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) )
    FD_LOG_ERR( ( "fd_quic_encode_eth failed with buffer overrun" ) );

  cur_ptr += rc;
  cur_sz -= rc;

  rc = fd_quic_encode_ipv4( cur_ptr, cur_sz, pkt.ipv4 );
  if ( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) )
    FD_LOG_ERR( ( "fd_quic_encode_ipv4 failed with buffer overrun" ) );

  /* calc checksum */
  fd_quic_net_ipv4_checksum( cur_ptr );

  cur_ptr += rc;
  cur_sz -= rc;

  rc = fd_quic_encode_udp( cur_ptr, cur_sz, pkt.udp );
  if ( FD_UNLIKELY( rc == FD_QUIC_PARSE_FAIL ) )
    FD_LOG_ERR( ( "fd_quic_encode_udp failed with buffer overrun" ) );

  cur_ptr += rc;
  cur_sz -= rc;

  /* need enough space for payload and tag */
  ulong tag_sz = FD_QUIC_CRYPTO_TAG_SZ;
  if ( FD_UNLIKELY( (ulong)payload_sz + tag_sz > cur_sz ) ) {
    FD_LOG_ERR( ( "%s : payload too big for buffer", __func__ ) );
  }
  fd_memcpy( cur_ptr, tx_buf, (ulong)payload_sz );

  cur_ptr += (ulong)payload_sz;
  cur_sz -= (ulong)payload_sz;

  fd_aio_pkt_info_t aio_buf = {
      .buf = crypt_scratch, .buf_sz = (ushort)( cur_ptr - crypt_scratch ) };
  return aio_buf;
}

int main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if ( cpu_idx >= fd_shmem_cpu_cnt() )
    cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc, &argv, "--page-sz", NULL, "gigantic" );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL );
  ulong        numa_idx =
      fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );
  char const * _dst_ip  = fd_env_strip_cmdline_cstr( &argc, &argv, "--dst-ip", NULL, NULL );
  uint         dst_port = fd_env_strip_cmdline_uint( &argc, &argv, "--dst-port", NULL, 9001U );
  char const * _gateway =
      fd_env_strip_cmdline_cstr( &argc, &argv, "--gateway", NULL, "00:00:00:00:00:00" );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if ( FD_UNLIKELY( !page_sz ) )
    FD_LOG_ERR( ( "unsupported --page-sz" ) );

  if ( FD_UNLIKELY( !_dst_ip ) )
    FD_LOG_ERR( ( "missing --dst-ip" ) );
  if ( FD_UNLIKELY( !dst_port ) )
    FD_LOG_ERR( ( "missing --dst-port" ) );

  if ( FD_UNLIKELY( !_gateway ) )
    FD_LOG_ERR( ( "missing --gateway" ) );
  uchar gateway[6] = { 0 };
  if ( FD_UNLIKELY( !fd_cstr_to_mac_addr( _gateway, gateway ) ) )
    FD_LOG_ERR( ( "invalid gateway \"%s\"", _gateway ) );

  uint dst_ip;
  if ( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _dst_ip, &dst_ip ) ) )
    FD_LOG_ERR( ( "invalid --dst-ip" ) );

  FD_LOG_NOTICE(
      ( "Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu",
        page_cnt,
        _page_sz,
        numa_idx )
  );
  fd_wksp_t * wksp =
      fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t quic_limits = { 0 };
  fd_quic_limits_from_env( &argc, &argv, &quic_limits );
  quic_limits.conn_id_sparsity = 4.0;

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  FD_LOG_NOTICE( ( "QUIC footprint: %lu bytes", quic_footprint ) );

  FD_LOG_NOTICE( ( "Creating client QUIC" ) );
  fd_quic_t * quic = fd_quic_new(
      fd_wksp_alloc_laddr( wksp, fd_quic_align(), fd_quic_footprint( &quic_limits ), 1UL ),
      &quic_limits
  );
  FD_TEST( quic );

  fd_quic_udpsock_t   _udpsock[1];
  fd_quic_udpsock_t * udpsock =
      fd_quic_udpsock_create( _udpsock, &argc, &argv, wksp, fd_quic_get_aio_net_rx( quic ) );
  FD_TEST( udpsock );

  fd_quic_config_t * client_cfg = &quic->config;
  client_cfg->role              = FD_QUIC_ROLE_CLIENT;
  FD_TEST( fd_quic_config_from_env( &argc, &argv, client_cfg ) );
  memcpy( client_cfg->link.dst_mac_addr, gateway, 6UL );
  client_cfg->net.ip_addr           = udpsock->listen_ip;
  client_cfg->net.ephem_udp_port.lo = (ushort)udpsock->listen_port;
  client_cfg->net.ephem_udp_port.hi = (ushort)( udpsock->listen_port + 1 );

  // ALPN fixes
  char cpy[11] = "\x0asolana-tpu"; // ALPN
  memcpy(client_cfg->alpns, cpy, 11);
  client_cfg->alpns_sz = 11; // number of bytes of ALPN - see spec

  if ( FD_UNLIKELY( argc > 1 ) )
    FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  (void)udpsock;
  fd_quic_set_aio_net_tx( quic, udpsock->aio );
  FD_TEST( fd_quic_init( quic ) );
  ulong packet_count = 0;

  /* Prepare the INITIAL packet */
  uchar *            tx_buf           = INITIAL_PKT;
  fd_quic_config_t * config           = &quic->config;
  ulong              tx_buf_sz        = INITIAL_PKT_LEN;
  uchar *            tx_ptr           = tx_buf + tx_buf_sz;
  ulong              crypt_scratch_sz = 2048;
  uchar              crypt_scratch[crypt_scratch_sz];

  ulong             tx_sz   = 0;
  ushort            ipv4_id = 1;
  fd_aio_pkt_info_t aio_buf = fd_aio_pkt_info_populate(
      quic,
      &tx_ptr,
      tx_buf,
      tx_buf_sz,
      &tx_sz,
      crypt_scratch,
      2048,
      config->link.dst_mac_addr,
      &ipv4_id,
      dst_ip,
      (ushort)udpsock->listen_port,
      (ushort)dst_port,
      1
  );

  /* Save the starting point of INITIAL packet */
  void * buf = aio_buf.buf;

  while ( 1 ) {
    aio_buf.buf = buf;
    int aio_rc  = fd_aio_send( &quic->aio_tx, &aio_buf, 1, NULL, 1 );
    if ( FD_UNLIKELY( aio_rc < 0 ) ) {
      FD_LOG_WARNING( ( "fd_aio_send error: %d", aio_rc ) );
    }

    if ( FD_UNLIKELY( packet_count % 1000000 == 0 ) ) {
      FD_LOG_NOTICE( ( "INITIAL packets spammed #%lu", packet_count ) );
    }
    packet_count++;
  }

  FD_TEST( fd_quic_fini( quic ) );

  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( quic ) ) );
  fd_quic_udpsock_destroy( udpsock );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}