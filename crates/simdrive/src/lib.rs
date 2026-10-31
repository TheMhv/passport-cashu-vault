//! KeyOS simulator screen driver over `foundation-passport-drive mcp --sim`.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};

pub const REJECT: (u32, u32) = (124, 742);
pub const APPROVE: (u32, u32) = (356, 742);
pub const DONE: (u32, u32) = (240, 742);

const PIN_DIGITS: [(u32, u32); 10] = [
    (240, 756),
    (85, 535),
    (240, 535),
    (395, 535),
    (85, 608),
    (240, 608),
    (395, 608),
    (85, 682),
    (240, 682),
    (395, 682),
];
const PIN_UNLOCK: (u32, u32) = (395, 756);
const KEY_INTERVAL: Duration = Duration::from_millis(300);
const SCREEN_TIMEOUT: Duration = Duration::from_secs(20);

pub struct Screen {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    shots: PathBuf,
    taken: u32,
}

impl Screen {
    pub fn new(drive: PathBuf, shots: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&shots)
            .map_err(|e| format!("cannot create {}: {e}", shots.display()))?;
        let mut child = Command::new(&drive)
            .args(["mcp", "--sim"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot run {}: {e}", drive.display()))?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        let mut screen = Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            shots,
            taken: 0,
        };
        screen.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "cashu-vault-simdrive", "version": env!("CARGO_PKG_VERSION") }
            }),
        )?;
        screen.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))?;
        screen.tool("connect", json!({}))?;
        Ok(screen)
    }

    fn send(&mut self, message: Value) -> Result<(), String> {
        writeln!(self.stdin, "{message}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| format!("passport-drive went away: {e}"))
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))?;
        loop {
            let mut line = String::new();
            let read = self
                .stdout
                .read_line(&mut line)
                .map_err(|e| format!("passport-drive went away: {e}"))?;
            if read == 0 {
                return Err("passport-drive exited".to_owned());
            }
            let Ok(reply) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if reply["id"] != json!(id) {
                continue;
            }
            if let Some(error) = reply.get("error") {
                return Err(format!("passport-drive {method}: {error}"));
            }
            return Ok(reply["result"].clone());
        }
    }

    fn tool(&mut self, name: &str, arguments: Value) -> Result<Vec<Value>, String> {
        let result = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )?;
        let content = result["content"].as_array().cloned().unwrap_or_default();
        if result["isError"] == json!(true) {
            let text: Vec<&str> = content
                .iter()
                .filter_map(|item| item["text"].as_str())
                .collect();
            return Err(format!("passport-drive {name}: {}", text.join(" ")));
        }
        Ok(content)
    }

    pub fn tap(&mut self, (x, y): (u32, u32)) -> Result<(), String> {
        self.tool("tap", json!({ "x": x, "y": y })).map(|_| ())
    }

    pub fn clear_logs(&mut self) -> Result<(), String> {
        self.tool("clear_logs", json!({})).map(|_| ())
    }

    pub fn log_lines(&mut self, filter: &str) -> Result<Vec<String>, String> {
        let content = self.tool("get_logs", json!({ "filter": filter, "max_lines": 100 }))?;
        Ok(content
            .iter()
            .filter_map(|item| item["text"].as_str())
            .flat_map(str::lines)
            .filter(|line| line.contains(filter))
            .map(str::to_owned)
            .collect())
    }

    pub fn wait_for_log(&mut self, needle: &str) -> Result<(), String> {
        let deadline = Instant::now() + SCREEN_TIMEOUT;
        while self.log_lines(needle)?.is_empty() {
            if Instant::now() >= deadline {
                return Err(format!(
                    "no log line with {needle:?} within {SCREEN_TIMEOUT:?}"
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    pub fn capture(&mut self) -> Result<Vec<u8>, String> {
        let content = self.tool("screenshot", json!({}))?;
        let data = content
            .iter()
            .find(|item| item["type"] == "image")
            .and_then(|item| item["data"].as_str())
            .ok_or("passport-drive screenshot: no image")?;
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| format!("passport-drive screenshot: {e}"))
    }

    pub fn enter_pin(&mut self, pin: &str) -> Result<(), String> {
        for digit in pin.chars() {
            let index = digit
                .to_digit(10)
                .ok_or_else(|| format!("PIN {pin:?} is not all digits"))?;
            self.tap(PIN_DIGITS[index as usize])?;
            std::thread::sleep(KEY_INTERVAL);
        }
        self.tap(PIN_UNLOCK)
    }

    pub fn shot(&mut self, name: &str) -> Result<PathBuf, String> {
        let png = self.capture()?;
        self.taken += 1;
        let path = self.shots.join(format!("{:02}-{name}.png", self.taken));
        std::fs::write(&path, &png)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(path)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = self.tool("disconnect", json!({}));
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn read_qr(path: &Path) -> Result<String, String> {
    let png = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    read_qr_png(&png).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn read_qr_png(png: &[u8]) -> Result<String, String> {
    let image = image::load_from_memory(png)
        .map_err(|e| format!("not a screenshot: {e}"))?
        .to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
        image.width() as usize,
        image.height() as usize,
        |x, y| image.get_pixel(x as u32, y as u32).0[0],
    );
    let grids = prepared.detect_grids();
    let grid = grids.first().ok_or("no QR code on the screen")?;
    grid.decode()
        .map(|(_, text)| text)
        .map_err(|e| format!("QR code decode failed: {e}"))
}
