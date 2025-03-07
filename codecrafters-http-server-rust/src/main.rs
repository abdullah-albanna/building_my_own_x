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
struct HttpRequest<'a> {
    method: HttpMethod,
    path: Vec<&'a str>,
    http_ver: &'a str,
}

impl<'a> HttpRequest<'a> {
    fn new(line: &'a str) -> Result<HttpRequest<'a>, HttpParseError> {
        let mut splitted_line = line.split_whitespace();
        let method = HttpMethod::from_str(splitted_line.next().unwrap_or_default())?;
        let path = splitted_line
            .next()
            .unwrap_or("/")
            .split_terminator('/')
            .skip(1)
            .collect();

        let http_ver = splitted_line.next().unwrap_or_default();

        Ok(HttpRequest {
            method,
            path,
            http_ver,
        })
    }
}

fn handle_stream(mut stream: TcpStream) -> anyhow::Result<()> {
    let mut buffer_read = BufReader::new(&stream);
    let mut first_line = String::new();
    buffer_read.read_line(&mut first_line).unwrap();

    let http_request = HttpRequest::new(&first_line).context("parse http request")?;

    let response = if matches!(http_request.method, HttpMethod::Get)
        && http_request.path.is_empty()
        && http_request.http_ver == "HTTP/1.1"
    {
        "HTTP/1.1 200 OK\r\n\r\n"
    } else if matches!(http_request.method, HttpMethod::Get)
        && http_request.path.len() > 1
        && http_request.http_ver == "HTTP/1.1"
    {
        match http_request.path.as_slice() {
            ["echo", echo] => &format!(
                "HTTP/1.1 200 Ok\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\n{echo}"
            ),
            _ => "HTTP/1.1 404 Not Found\r\n\r\n",
        }
    } else {
        "HTTP/1.1 404 Not Found\r\n\r\n"
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
