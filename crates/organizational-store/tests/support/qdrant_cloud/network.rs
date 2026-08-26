use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

pub async fn spawn_cluster_provider() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let provider = tokio::spawn(async move {
        for request_index in 0..6 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4_096];
            let read = socket.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("GET /api/cluster/v1/accounts/account-durable/clusters?"));
            assert!(request.contains("page_size=250"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: apikey fixture-management-key")
            );
            let second_page = matches!(request_index, 1 | 3 | 5);
            if second_page {
                assert!(request.contains("page_token=page-2"));
            } else if request_index == 0 || request_index == 2 {
                assert!(request.contains("page_token=page-1"));
            } else {
                assert!(!request.contains("page_token="));
            }
            if request_index == 1 {
                socket
                    .write_all(
                        b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                continue;
            }
            let body = if second_page {
                r#"{"items":[{"id":"cluster-2","name":"Durable cluster two","status":"ready"}],"next_page_token":""}"#
            } else {
                r#"{"items":[{"id":"cluster-1","name":"Durable cluster one","status":"ready"}],"next_page_token":"page-2"}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (format!("http://{address}"), provider)
}
