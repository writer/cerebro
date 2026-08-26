use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub(super) async fn accept_request(listener: &TcpListener) -> (TcpStream, String) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut request = vec![0; 4_096];
    let read = socket.read(&mut request).await.unwrap();
    (
        socket,
        String::from_utf8_lossy(&request[..read]).into_owned(),
    )
}

pub(super) fn assert_cluster_request(request: &str, account_id: &str) {
    assert!(request.starts_with(&format!(
        "GET /api/cluster/v1/accounts/{account_id}/clusters?"
    )));
    assert!(request.contains("page_size=250"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: apikey fixture-management-key")
    );
}

pub(super) async fn write_json(mut socket: TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    // Oversized-response coverage may close the client before the fixture has
    // finished writing. The client-side bound is the assertion under test.
    let _ = socket.write_all(response.as_bytes()).await;
}

pub(super) async fn write_rate_limit(mut socket: TcpStream) {
    socket
        .write_all(
            b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await
        .unwrap();
}
