use std::collections::HashMap;
use std::net::TcpListener;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    str::FromStr,
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
            "Post" => Ok(Self::Post),
            _ => Err(HttpParseError::InvalidMethod),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum HttpParseError {
    #[error("Unable to parse the request method")]
    InvalidMethod,
}

#[derive(Debug)]
struct HttpRequest {
    method: HttpMethod,
    path: Vec<String>,
    http_ver: String,
    headers: HashMap<String, String>,
}

impl HttpRequest {
    fn new(stream: &mut TcpStream) -> Result<HttpRequest, HttpParseError> {
        let mut buffer = BufReader::new(stream);

        let mut first_line = String::new();
        buffer.read_line(&mut first_line).unwrap();

        let mut splitted_line = first_line.split_whitespace();

        let method = HttpMethod::from_str(splitted_line.next().unwrap_or_default())?;

        let path = splitted_line
            .next()
            .unwrap_or("/")
            .split_terminator('/')
            .skip(1)
            .map(|s| s.to_string())
            .collect();

        let http_ver = splitted_line.next().unwrap_or_default().to_string();

        let mut headers = HashMap::new();
        let mut headers_line = String::new();
        while buffer.read_line(&mut headers_line).unwrap() > 0 {
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

        Ok(HttpRequest {
            method,
            path,
            http_ver,
            headers,
        })
    }
}

fn handle_stream(mut stream: TcpStream) -> anyhow::Result<()> {
    let http_request = HttpRequest::new(&mut stream).context("parse http request")?;
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

    stream.write_all(response.as_bytes()).unwrap();
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:4221").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                println!("accepted new connection");
                handle_stream(stream)?;
            }
            Err(e) => {
                println!("error: {}", e);
            }
        }
    }

    Ok(())
}
