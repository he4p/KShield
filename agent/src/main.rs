use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap, RingBuf};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf};
use serde::{Deserialize, Serialize};
use ureq::Agent;

const EVENT_KIND_EXEC: u8 = 1;
const EVENT_KIND_CONNECT: u8 = 2;
const EVENT_ACTION_OBSERVE: u8 = 0;
const EVENT_ACTION_ALLOW: u8 = 1;
const EVENT_ACTION_BLOCK: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct BpfEvent {
    ts_ns: u64,
    pid: u32,
    uid: u32,
    kind: u8,
    action: u8,
    _pad: u16,
    ipv4_be: u32,
    port_be: u16,
    _pad2: u16,
    comm: [u8; 16],
}

const BPF_EVENT_SIZE: usize = 44;

#[derive(Debug, Clone)]
struct Settings {
    manager_url: String,
    bpf_object: PathBuf,
    poll_ms: u64,
    policy_sync_secs: u64,
}

#[derive(Debug, Serialize)]
struct RegisterRequest {
    hostname: String,
    ip: String,
    kernel: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    agent_id: String,
}

#[derive(Debug, Deserialize)]
struct PolicyResponse {
    blocked_ipv4: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EventPayload {
    agent_id: String,
    ts: String,
    event_type: String,
    action: String,
    severity: String,
    pid: u32,
    uid: u32,
    comm: String,
    dst_ip: String,
    dst_port: u16,
}

fn parse_settings() -> Result<Settings> {
    let mut manager_url = "http://127.0.0.1:8080".to_string();
    let mut bpf_object = PathBuf::from("agent/bpf/kshield.bpf.o");
    let mut poll_ms = 150_u64;
    let mut policy_sync_secs = 12_u64;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--manager-url" => {
                i += 1;
                manager_url = args
                    .get(i)
                    .cloned()
                    .ok_or_else(|| anyhow!("--manager-url requires a value"))?;
            }
            "--bpf-object" => {
                i += 1;
                let value = args
                    .get(i)
                    .cloned()
                    .ok_or_else(|| anyhow!("--bpf-object requires a value"))?;
                bpf_object = PathBuf::from(value);
            }
            "--poll-ms" => {
                i += 1;
                let value = args
                    .get(i)
                    .cloned()
                    .ok_or_else(|| anyhow!("--poll-ms requires a value"))?;
                poll_ms = value.parse::<u64>().context("invalid --poll-ms value")?;
            }
            "--policy-sync-secs" => {
                i += 1;
                let value = args
                    .get(i)
                    .cloned()
                    .ok_or_else(|| anyhow!("--policy-sync-secs requires a value"))?;
                policy_sync_secs = value
                    .parse::<u64>()
                    .context("invalid --policy-sync-secs value")?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            unknown => return Err(anyhow!("unknown arg: {unknown}")),
        }
        i += 1;
    }

    Ok(Settings {
        manager_url,
        bpf_object,
        poll_ms,
        policy_sync_secs,
    })
}

fn print_help() {
    println!("kshield-agent");
    println!("  --manager-url <url>       default http://127.0.0.1:8080");
    println!("  --bpf-object <path>       default agent/bpf/kshield.bpf.o");
    println!("  --poll-ms <ms>            default 150");
    println!("  --policy-sync-secs <sec>  default 12");
}

fn require_root() -> Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Err(anyhow!("kshield-agent must run as root"));
    }
    Ok(())
}

fn hostname_string() -> String {
    hostname::get()
        .ok()
        .and_then(|v| v.into_string().ok())
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn kernel_string() -> String {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-kernel".to_string())
}

fn local_ip_string() -> String {
    local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn now_rfc3339_approx() -> String {
    // Keep dependencies minimal: manager also timestamps ingestion time.
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();
    format!("{seconds}")
}

fn register(agent: &Agent, settings: &Settings) -> Result<String> {
    let req = RegisterRequest {
        hostname: hostname_string(),
        ip: local_ip_string(),
        kernel: kernel_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let url = format!("{}/api/v1/agents/register", settings.manager_url);
    let resp = agent
        .post(&url)
        .send_json(serde_json::to_value(req)?)
        .context("failed to register agent")?;
    let parsed: RegisterResponse = resp.into_json().context("invalid register response")?;
    Ok(parsed.agent_id)
}

fn sync_policy(
    agent: &Agent,
    settings: &Settings,
    agent_id: &str,
    blocked_map: &mut HashMap<aya::maps::MapData, u32, u8>,
) -> Result<()> {
    let url = format!("{}/api/v1/policy/{}", settings.manager_url, agent_id);
    let resp = agent.get(&url).call().context("policy request failed")?;
    let policy: PolicyResponse = resp.into_json().context("invalid policy payload")?;

    let mut parsed_ips = Vec::new();
    for ip in policy.blocked_ipv4 {
        let parsed = ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("invalid blocked ipv4 from manager: {ip}"))?;
        parsed_ips.push(u32::from_be_bytes(parsed.octets()));
    }

    let existing_keys: Vec<u32> = blocked_map.keys().filter_map(Result::ok).collect();
    for key in existing_keys {
        let _ = blocked_map.remove(&key);
    }
    for key in parsed_ips {
        blocked_map.insert(key, 1_u8, 0)?;
    }
    Ok(())
}

fn cstr_bytes_to_string(buf: &[u8]) -> String {
    let pos = buf.iter().position(|v| *v == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..pos]).to_string()
}

fn convert_event(agent_id: &str, evt: &BpfEvent) -> EventPayload {
    let (event_type, action, severity) = match (evt.kind, evt.action) {
        (EVENT_KIND_EXEC, EVENT_ACTION_OBSERVE) => ("execve", "observe", "medium"),
        (EVENT_KIND_CONNECT, EVENT_ACTION_ALLOW) => ("socket_connect", "allow", "low"),
        (EVENT_KIND_CONNECT, EVENT_ACTION_BLOCK) => ("socket_connect", "block", "high"),
        _ => ("unknown", "observe", "info"),
    };

    let dst_ip = if evt.ipv4_be == 0 {
        String::new()
    } else {
        Ipv4Addr::from(evt.ipv4_be.to_be_bytes()).to_string()
    };

    EventPayload {
        agent_id: agent_id.to_string(),
        ts: now_rfc3339_approx(),
        event_type: event_type.to_string(),
        action: action.to_string(),
        severity: severity.to_string(),
        pid: evt.pid,
        uid: evt.uid,
        comm: cstr_bytes_to_string(&evt.comm),
        dst_ip,
        dst_port: u16::from_be(evt.port_be),
    }
}

fn parse_event(buf: &[u8]) -> Option<BpfEvent> {
    if buf.len() < BPF_EVENT_SIZE {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(buf[0..8].try_into().ok()?);
    let pid = u32::from_ne_bytes(buf[8..12].try_into().ok()?);
    let uid = u32::from_ne_bytes(buf[12..16].try_into().ok()?);
    let kind = buf[16];
    let action = buf[17];
    let _pad = u16::from_ne_bytes(buf[18..20].try_into().ok()?);
    let ipv4_be = u32::from_ne_bytes(buf[20..24].try_into().ok()?);
    let port_be = u16::from_ne_bytes(buf[24..26].try_into().ok()?);
    let _pad2 = u16::from_ne_bytes(buf[26..28].try_into().ok()?);
    let mut comm = [0_u8; 16];
    comm.copy_from_slice(&buf[28..44]);

    Some(BpfEvent {
        ts_ns,
        pid,
        uid,
        kind,
        action,
        _pad,
        ipv4_be,
        port_be,
        _pad2,
        comm,
    })
}

fn post_events(agent: &Agent, settings: &Settings, payloads: &[EventPayload]) -> Result<()> {
    if payloads.is_empty() {
        return Ok(());
    }
    let url = format!("{}/api/v1/events", settings.manager_url);
    let _resp = agent
        .post(&url)
        .send_json(serde_json::json!({ "events": payloads }))
        .context("failed to post event batch")?;
    Ok(())
}

fn main() -> Result<()> {
    let settings = parse_settings()?;
    require_root()?;

    let http = Agent::new();
    let agent_id = register(&http, &settings)?;
    println!("registered agent_id={agent_id}");

    let mut bpf = Ebpf::load_file(&settings.bpf_object)
        .with_context(|| format!("failed loading {}", settings.bpf_object.display()))?;

    {
        let program: &mut TracePoint = bpf
            .program_mut("observe_execve")
            .ok_or_else(|| anyhow!("program observe_execve not found"))?
            .try_into()
            .context("observe_execve type cast failed")?;
        program.load().context("load observe_execve failed")?;
        program
            .attach("syscalls", "sys_enter_execve")
            .context("attach sys_enter_execve failed")?;
    }

    {
        let btf = Btf::from_sys_fs().context("BTF not available in /sys/kernel/btf/vmlinux")?;
        let program: &mut Lsm = bpf
            .program_mut("enforce_socket_connect")
            .ok_or_else(|| anyhow!("program enforce_socket_connect not found"))?
            .try_into()
            .context("enforce_socket_connect type cast failed")?;
        program
            .load("socket_connect", &btf)
            .context("load LSM program failed")?;
        program.attach().context("attach LSM program failed")?;
    }

    let events_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("EVENTS map not found"))?;
    let mut ringbuf =
        RingBuf::try_from(events_map).context("failed to create ring buffer reader")?;

    let blocked_map = bpf
        .take_map("BLOCKED_IPV4")
        .ok_or_else(|| anyhow!("BLOCKED_IPV4 map not found"))?;
    let mut blocked_ipv4 = HashMap::<_, u32, u8>::try_from(blocked_map)
        .context("failed to open BLOCKED_IPV4 map")?;

    let mut last_policy_sync = Instant::now() - Duration::from_secs(settings.policy_sync_secs + 1);
    let mut pending_events: Vec<EventPayload> = Vec::with_capacity(128);
    loop {
        if last_policy_sync.elapsed() >= Duration::from_secs(settings.policy_sync_secs) {
            if let Err(err) = sync_policy(&http, &settings, &agent_id, &mut blocked_ipv4) {
                eprintln!("policy sync error: {err:#}");
            }
            last_policy_sync = Instant::now();
        }

        let mut consumed = false;
        while let Some(item) = ringbuf.next() {
            let Some(evt) = parse_event(&item) else {
                continue;
            };
            let payload = convert_event(&agent_id, &evt);
            pending_events.push(payload);
            if pending_events.len() >= 128 {
                if let Err(err) = post_events(&http, &settings, &pending_events) {
                    eprintln!("event post error: {err:#}");
                }
                pending_events.clear();
            }
            consumed = true;
        }

        if !pending_events.is_empty() {
            if let Err(err) = post_events(&http, &settings, &pending_events) {
                eprintln!("event post error: {err:#}");
            }
            pending_events.clear();
        }

        if !consumed {
            thread::sleep(Duration::from_millis(settings.poll_ms));
        }
    }
}
