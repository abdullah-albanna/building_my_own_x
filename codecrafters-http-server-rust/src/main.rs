use std::str::FromStr;
use std::{collections::HashMap, net::SocketAddr};

use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};

use anyhow::Context;

#[derive(Debug)]
enum HttpMethod {
    Get,
    Post,
}

impl FromStr for HttpMethod {
    type Err = HttpParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "GET" => Ok(Self::Get),
            "POST" => Ok(Self::Post),
            _ => Err(HttpParseError::InvalidMethod),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum HttpParseError {
    #[error("Unable to parse the request method")]
    InvalidMethod,

    #[error("Unable to parse the https version")]
    InvalidHttpVersion,
}

#[derive(Debug)]
enum HttpVersion {
    ZeroPointNine,
    OnePointZero,
    OnePointOne,
    Two,
    Three,
}

impl FromStr for HttpVersion {
    type Err = HttpParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s
            .split_terminator('/')
            .nth(1)
            .ok_or(HttpParseError::InvalidHttpVersion)?
        {
            "0.9" => Ok(Self::ZeroPointNine),
            "1.0" => Ok(Self::OnePointZero),
            "1.1" => Ok(Self::OnePointOne),
            "2" => Ok(Self::Two),
            "3" => Ok(Self::Three),
            _ => Err(HttpParseError::InvalidHttpVersion),
        }
    }
}

#[derive(Debug)]
struct HttpRequest {
    method: HttpMethod,
    path: Vec<String>,
    http_ver: HttpVersion,
    headers: HashMap<String, String>,
    body: Option<Vec<u8>>,
}

impl HttpRequest {
    async fn new(stream: &mut TcpStream) -> Result<HttpRequest, HttpParseError> {
        let mut buffer = BufReader::new(stream);

        let mut first_line = String::new();
        buffer.read_line(&mut first_line).await.unwrap();

        let mut splitted_line = first_line.split_whitespace();

        let method = HttpMethod::from_str(splitted_line.next().unwrap_or_default())?;

        let path = splitted_line
            .next()
            .unwrap_or("/")
            .split_terminator('/')
            .skip(1)
            .map(|s| s.to_string())
            .collect();

        let http_ver = HttpVersion::from_str(splitted_line.next().unwrap_or_default())?;

        let mut headers = HashMap::new();
        let mut headers_line = String::new();
        while buffer.read_line(&mut headers_line).await.unwrap() > 0 {
            let line = headers_line.trim();

            if line.is_empty() {
                break;
            }

            let mut headers_parts = headers_line.splitn(2, ':');

            if let (Some(key), Some(value)) = (headers_parts.next(), headers_parts.next()) {
                headers.insert(
                    key.trim().to_string(),
                    value.trim().trim_matches(['\r', '\n']).to_string(),
                );
            }

            headers_line.clear();
        }

        let body = if let Some(content_size) = headers.get("Content-Length") {
            let content_size: usize = content_size.parse().unwrap();

            let mut body = vec![0; content_size];

            buffer.read_exact(&mut body).await.unwrap();

            Some(body)
        } else {
            None
        };

        Ok(HttpRequest {
            method,
            path,
            http_ver,
            headers,
            body,
        })
    }
}

async fn handle_stream(mut stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
    println!("Accepted connection from {}", addr);
    let http_request = HttpRequest::new(&mut stream)
        .await
        .context("parse http request")?;
    println!("{:#?}", http_request);

    let response = match http_request
        .path
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => "HTTP/1.1 200 OK\r\n\r\n",
        ["echo", echo] => &format!(
            "HTTP/1.1 200 Ok\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{echo}",
            echo.len()
        ),

        ["file", file]
            if matches!(http_request.method, HttpMethod::Post) && http_request.body.is_some() =>
        {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&format!("/tmp/{file}"))
                .await
                .unwrap();

            file.write_all(&http_request.body.unwrap()).await.unwrap();

            "HTTP/1.1 201 Created\r\n\r\n"
        }

        ["file", file] if fs::File::open(&format!("/tmp/{file}")).await.is_ok() => {
            let mut file = fs::File::open(&format!("/tmp/{file}")).await.unwrap();
            let mut content = String::new();
            file.read_to_string(&mut content).await.unwrap();

            &format!(
            "HTTP/1.1 200 Ok\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n{}",
                content.len(),
                content
            )
        }
        ["user-agent"] if http_request.headers.contains_key("User-Agent") => {
            let user_agent = http_request.headers.get("User-Agent").unwrap();

            &format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                user_agent.len(),
                user_agent
            )
        }
        _ => "HTTP/1.1 404 Not Found\r\n\r\n",
    };

    stream.write_all(response.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4221").await.unwrap();

    while let Ok((stream, addr)) = listener.accept().await {
        println!("accepted new connection");
        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream, addr).await {
                println!("Error handling the request, error: {e}");
            }
        });
    }

    Ok(())
}
