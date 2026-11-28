//! HTTP/3 listener: QUIC (quinn) + h3, feeding the same request pipeline as
//! the TCP listeners.

use super::{respond, Body, BoxError, Edge};
use crate::store::Store;
use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::body::Frame;
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::mpsc;

type RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Request body fed from the QUIC receive stream.
struct ChannelBody(mpsc::Receiver<Result<Bytes, BoxError>>);

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0.poll_recv(cx).map(|item| item.map(|r| r.map(Frame::data)))
    }
}

/// Bind the QUIC endpoint (UDP) for HTTP/3.
pub fn endpoint(addr: SocketAddr, store: Arc<Store>) -> anyhow::Result<quinn::Endpoint> {
    let tls = super::tls::quic_server_config(store)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(200u32.into());
    transport.max_idle_timeout(Some(Duration::from_secs(60).try_into()?));
    // Visitors are often on long, lossy paths: BBR keeps its rate under random
    // loss where the default (loss-based) controller collapses, and larger
    // windows let a high-latency connection fill its bandwidth.
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport.send_window(16 * 1024 * 1024);
    transport.receive_window((16u32 * 1024 * 1024).into());
    transport.stream_receive_window((4u32 * 1024 * 1024).into());
    config.transport_config(Arc::new(transport));
    // the socket may come from the process before (see crate::handoff)
    let socket = crate::handoff::udp(addr)?;
    Ok(quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(config), socket, Arc::new(quinn::TokioRuntime))?)
}

pub async fn serve(endpoint: quinn::Endpoint, edge: Arc<Edge>) {
    serve_with_proxy(endpoint, edge, false).await;
}

pub async fn serve_with_proxy(endpoint: quinn::Endpoint, edge: Arc<Edge>, is_proxy: bool) {
    let port = endpoint.local_addr().map(|a| a.port()).unwrap_or(443);
    while let Some(incoming) = endpoint.accept().await {
        let edge = edge.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let peer = conn.remote_address();
            edge.measured(peer.ip(), conn.rtt());
            let Ok(mut h3) = h3::server::builder()
                .enable_extended_connect(true)
                .build::<_, Bytes>(h3_quinn::Connection::new(conn))
                .await
            else {
                return;
            };
            while let Ok(Some(resolver)) = h3.accept().await {
                let edge = edge.clone();
                tokio::spawn(async move {
                    if let Ok((req, stream)) = resolver.resolve_request().await {
                        let _ = serve_request(edge, peer, port, is_proxy, req, stream).await;
                    }
                });
            }
        });
    }
}

async fn serve_request(
    edge: Arc<Edge>,
    peer: SocketAddr,
    port: u16,
    is_proxy: bool,
    req: Request<()>,
    stream: RequestStream,
) -> Result<(), BoxError> {
    if req.method() == hyper::Method::CONNECT
        && req
            .extensions()
            .get::<h3::ext::Protocol>()
            .is_some_and(|p| p.as_str().eq_ignore_ascii_case("websocket"))
    {
        return serve_h3_websocket(edge, peer, port, is_proxy, req, stream).await;
    }
    let (mut send, mut recv) = stream.split();
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        loop {
            let item = match recv.recv_data().await {
                Ok(Some(mut buf)) => Ok(buf.copy_to_bytes(buf.remaining())),
                Ok(None) => break,
                Err(e) => Err(BoxError::from(e.to_string())),
            };
            let failed = item.is_err();
            if tx.send(item).await.is_err() || failed {
                break;
            }
        }
    });
    let body: Body = ChannelBody(rx).boxed();
    let mut req = req.map(|_| body);
    // QUIC is always TLS 1.3, and has no handshake without a server name to speak of
    req.extensions_mut().insert(super::TlsInfo { version: "TLSv1.3", sni: true, kex: String::new() });
    req.extensions_mut().insert(super::proxy::ListenerInfo { port, is_proxy, is_front: false });
    let resp = respond(edge, peer, true, req).await;

    let (parts, mut body) = resp.into_parts();
    send.send_response(Response::from_parts(parts, ())).await?;
    while let Some(frame) = body.frame().await {
        match frame?.into_data() {
            Ok(data) => send.send_data(data).await?,
            Err(other) => {
                if let Ok(trailers) = other.into_trailers() {
                    send.send_trailers(trailers).await?;
                }
            }
        }
    }
    send.finish().await?;
    Ok(())
}

async fn serve_h3_websocket(
    edge: Arc<Edge>,
    peer: SocketAddr,
    port: u16,
    is_proxy: bool,
    req: Request<()>,
    stream: RequestStream,
) -> Result<(), BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut send, mut recv) = stream.split();
    let listener = super::proxy::ListenerInfo { port, is_proxy, is_front: false };
    let (parts, _) = req.into_parts();
    let (ws_headers, origin_ws) = match super::open_upstream_websocket(&edge, peer.ip(), true, Some(&listener), &parts).await {
        Ok(res) => res,
        Err(e) => {
            let mut resp = Response::new(());
            *resp.status_mut() = hyper::StatusCode::from_u16(e.status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
            send.send_response(resp).await?;
            send.finish().await?;
            return Ok(());
        }
    };
    let mut ok_resp = Response::new(());
    *ok_resp.status_mut() = hyper::StatusCode::OK;
    if let Some(proto) = ws_headers.get("sec-websocket-protocol") {
        ok_resp.headers_mut().insert("sec-websocket-protocol", proto.clone());
    }
    send.send_response(ok_resp).await?;

    let (mut o_read, mut o_write) = tokio::io::split(hyper_util::rt::TokioIo::new(origin_ws));
    let idle = Duration::from_secs(300);
    let c2o = async {
        while let Ok(Some(mut buf)) = tokio::time::timeout(idle, recv.recv_data()).await? {
            let chunk = buf.copy_to_bytes(buf.remaining());
            o_write.write_all(&chunk).await?;
        }
        let _ = o_write.shutdown().await;
        Ok::<_, BoxError>(())
    };
    let o2c = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tokio::time::timeout(idle, o_read.read(&mut buf)).await??;
            if n == 0 {
                break;
            }
            send.send_data(Bytes::copy_from_slice(&buf[..n])).await?;
        }
        let _ = send.finish().await;
        Ok::<_, BoxError>(())
    };
    let _ = tokio::join!(c2o, o2c);
    Ok(())
}
