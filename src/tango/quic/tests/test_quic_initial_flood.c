#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

#include <stdlib.h>

#include "../../xdp/fd_xdp.h"
#include "../../../ballet/sha512/fd_sha512.h"
#include "../../../ballet/ed25519/fd_ed25519.h"
#include "../../../util/fd_util.h"
#include "../../../util/net/fd_eth.h"
#include "../../../util/net/fd_ip4.h"

extern uchar pkt_full[];
extern ulong pkt_full_sz;

fd_quic_stream_t *cur_stream = NULL;

void my_stream_notify_cb(fd_quic_stream_t *stream, void *ctx, int type)
{
    (void)ctx;
    (void)type;
    FD_LOG_DEBUG(("notify_cb"));
    if (cur_stream == stream)
    {
        cur_stream = NULL;
    }
}

void my_stream_receive_cb(fd_quic_stream_t *stream,
                          void *ctx,
                          uchar const *data,
                          ulong data_sz,
                          ulong offset,
                          int fin)
{
    (void)ctx;
    (void)stream;
    (void)fin;

    FD_LOG_DEBUG(("received data from peer (size=%lu offset=%lu)", data_sz, offset));
    FD_LOG_HEXDUMP_DEBUG(("stream data", data, data_sz));
}

fd_quic_conn_t *client_conn = NULL;

int client_complete = 0;

/* Client handshake complete */
void my_handshake_complete(fd_quic_conn_t *conn, void *vp_context)
{
    (void)conn;
    (void)vp_context;

    FD_LOG_INFO(("client handshake complete"));
    client_complete = 1;
}

/* Connection closed */
void my_connection_closed(fd_quic_conn_t *conn, void *vp_context)
{
    (void)conn;
    (void)vp_context;

    FD_LOG_INFO(("client conn closed"));
    client_conn = NULL;
    client_complete = 1;
}

ulong test_clock(void *ctx)
{
    (void)ctx;
    return (ulong)fd_log_wallclock();
}

void run_quic_client(
    fd_quic_t *quic,
    fd_quic_udpsock_t const *udpsock,
    uint dst_ip,
    ushort dst_port)
{

    fd_quic_connect(quic, dst_ip, (ushort)dst_port, NULL);
    FD_LOG_NOTICE(("Connected!"));

    fd_quic_service(quic);
    FD_LOG_NOTICE(("Start Service!"));
    fd_quic_udpsock_service(udpsock);
    FD_LOG_NOTICE(("Start Udp Service!"));
}

int main(int argc, char **argv)
{
    fd_boot(&argc, &argv);

    ulong cpu_idx = fd_tile_cpu_id(fd_tile_idx());
    if (cpu_idx >= fd_shmem_cpu_cnt())
        cpu_idx = 0UL;

    char const *_page_sz = fd_env_strip_cmdline_cstr(&argc, &argv, "--page-sz", NULL, "gigantic");
    ulong page_cnt = fd_env_strip_cmdline_ulong(&argc, &argv, "--page-cnt", NULL, 1UL);
    ulong numa_idx = fd_env_strip_cmdline_ulong(&argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx));
    char const *_dst_ip = fd_env_strip_cmdline_cstr(&argc, &argv, "--dst-ip", NULL, NULL);
    uint dst_port = fd_env_strip_cmdline_uint(&argc, &argv, "--dst-port", NULL, 9001U);
    char const *_gateway = fd_env_strip_cmdline_cstr(&argc, &argv, "--gateway", NULL, "00:00:00:00:00:00");

    ulong page_sz = fd_cstr_to_shmem_page_sz(_page_sz);
    if (FD_UNLIKELY(!page_sz))
        FD_LOG_ERR(("unsupported --page-sz"));

    if (FD_UNLIKELY(!_dst_ip))
        FD_LOG_ERR(("missing --dst-ip"));
    if (FD_UNLIKELY(!dst_port))
        FD_LOG_ERR(("missing --dst-port"));

    if (FD_UNLIKELY(!_gateway))
        FD_LOG_ERR(("missing --gateway"));
    uchar gateway[6] = {0};
    if (FD_UNLIKELY(!fd_cstr_to_mac_addr(_gateway, gateway)))
        FD_LOG_ERR(("invalid gateway \"%s\"", _gateway));

    uint dst_ip;
    if (FD_UNLIKELY(!fd_cstr_to_ip4_addr(_dst_ip, &dst_ip)))
        FD_LOG_ERR(("invalid --dst-ip"));

    FD_LOG_NOTICE(("Creating workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx));
    fd_wksp_t *wksp = fd_wksp_new_anonymous(page_sz, page_cnt, fd_shmem_cpu_idx(numa_idx), "wksp", 0UL);
    FD_TEST(wksp);

    fd_quic_limits_t quic_limits = {0};
    fd_quic_limits_from_env(&argc, &argv, &quic_limits);
    quic_limits.conn_id_sparsity = 4.0;

    ulong quic_footprint = fd_quic_footprint(&quic_limits);
    FD_TEST(quic_footprint);
    FD_LOG_NOTICE(("QUIC footprint: %lu bytes", quic_footprint));

    FD_LOG_NOTICE(("Creating client QUIC"));
    fd_quic_t *quic = fd_quic_new(
        fd_wksp_alloc_laddr(wksp, fd_quic_align(), fd_quic_footprint(&quic_limits), 1UL),
        &quic_limits);
    FD_TEST(quic);

    fd_quic_udpsock_t _udpsock[1];
    fd_quic_udpsock_t *udpsock = fd_quic_udpsock_create(_udpsock, &argc, &argv, wksp, fd_quic_get_aio_net_rx(quic));
    FD_TEST(udpsock);

    fd_quic_config_t *client_cfg = &quic->config;
    client_cfg->role = FD_QUIC_ROLE_CLIENT;
    FD_TEST(fd_quic_config_from_env(&argc, &argv, client_cfg));
    memcpy(client_cfg->link.dst_mac_addr, gateway, 6UL);

    // ALPN fixes
    char cpy[11] = "\x0asolana-tpu"; // ALPN
    memcpy(client_cfg->alpns, cpy, 11);
    client_cfg->alpns_sz = 11; // number of bytes of ALPN - see spec

    client_cfg->net.ip_addr = udpsock->listen_ip;
    client_cfg->net.ephem_udp_port.lo = (ushort)udpsock->listen_port;
    client_cfg->net.ephem_udp_port.hi = (ushort)(udpsock->listen_port + 1);

    if (FD_UNLIKELY(argc > 1))
        FD_LOG_ERR(("unrecognized argument: %s", argv[1]));

    (void) udpsock;
    quic->cb.conn_hs_complete = my_handshake_complete;
    quic->cb.conn_final       = my_connection_closed;
    quic->cb.stream_receive   = my_stream_receive_cb;
    quic->cb.stream_notify    = my_stream_notify_cb;
    quic->cb.now              = test_clock;
    quic->cb.now_ctx          = NULL;
    fd_quic_set_aio_net_tx( quic, udpsock->aio );
    FD_TEST( fd_quic_init( quic ) );
    ulong packet_count = 0;
    while (1)
    {
        run_quic_client(quic, udpsock, dst_ip, (ushort)dst_port);
        if (FD_UNLIKELY(packet_count % 100000 == 0))
        {
            FD_LOG_NOTICE(("INITIAL packets spammed #%lu", packet_count));
        }
        packet_count++;
    }

    FD_TEST(fd_quic_fini(quic));

    fd_wksp_free_laddr(fd_quic_delete(fd_quic_leave(quic)));
    fd_quic_udpsock_destroy(udpsock);
    fd_wksp_delete_anonymous(wksp);

    FD_LOG_NOTICE(("pass"));
    fd_halt();
    return 0;
}
