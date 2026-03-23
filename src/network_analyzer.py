#!/usr/bin/env python3
"""
Network Traffic Analyzer
========================
PCAP and HAR file analysis assistant powered by LLM.
Analyzes network captures and provides troubleshooting insights.

Features:
- PCAP file parsing with deep packet inspection
- HAR file analysis for HTTP traffic
- LLM-powered insights and recommendations
- Clean professional UI
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
import requests

# PCAP analysis
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP, Raw, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# HAR analysis
try:
    from haralyzer import HarParser
    HARALYZER_AVAILABLE = True
except ImportError:
    HARALYZER_AVAILABLE = False

# ============================================================================
# CONFIGURATION
# ============================================================================

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1")
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/data/network-analyzer/uploads")
SESSIONS_FOLDER = os.environ.get("SESSIONS_FOLDER", "/data/network-analyzer/sessions")
PORT = int(os.environ.get("PORT", "8080"))
# Maximum total upload size in bytes; 0 means unlimited (default).
# Set MAX_UPLOAD_MB env var to a positive integer to impose a cap.
_max_upload_mb = int(os.environ.get("MAX_UPLOAD_MB", "0"))
MAX_CONTENT_LENGTH = _max_upload_mb * 1024 * 1024 if _max_upload_mb > 0 else None
# Maximum number of characters of analysis JSON forwarded to the LLM in a
# single request.  Large analyses are truncated and the model is informed.
LLM_CONTEXT_CHAR_LIMIT = int(os.environ.get("LLM_CONTEXT_CHAR_LIMIT", "12000"))

# ============================================================================
# INITIALIZE
# ============================================================================

app = Flask(__name__)
if MAX_CONTENT_LENGTH:
    app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SESSIONS_FOLDER, exist_ok=True)

# Conversation history
conversations = {}


def save_session(conversation_id, file_name=None, analysis=None, messages=None,
                 file_names=None):
    """Persist session data to a JSON file on disk.

    ``file_names`` is an optional list of file names uploaded in the most
    recent batch.  When provided it is *appended* to the session's cumulative
    file list rather than replacing it, so the full history is preserved.
    ``file_name`` (singular) is kept for backwards-compatibility and is
    treated the same as ``file_names=[file_name]``.
    """
    session_path = os.path.join(SESSIONS_FOLDER, f"{conversation_id}.json")
    # Load existing or start fresh
    if os.path.exists(session_path):
        with open(session_path, 'r') as f:
            data = json.load(f)
    else:
        data = {
            "id": conversation_id,
            "created": datetime.utcnow().isoformat() + "Z",
            "file_name": None,
            "file_type": None,
            "file_names": [],
            "analysis": None,
            "messages": []
        }
    # Ensure cumulative list field exists for older sessions
    if "file_names" not in data:
        data["file_names"] = [data["file_name"]] if data.get("file_name") else []
    data["updated"] = datetime.utcnow().isoformat() + "Z"

    # Normalise new names into a list
    new_names = []
    if file_names:
        new_names = list(file_names)
    elif file_name:
        new_names = [file_name]

    if new_names:
        # Update legacy singular fields using the first/last file for compat
        last = new_names[-1]
        data["file_name"] = last
        ext = last.rsplit('.', 1)[-1].lower() if '.' in last else ''
        data["file_type"] = "pcap" if ext in ('pcap', 'cap') else "har" if ext == 'har' else ext
        # Append all new names to cumulative list
        data["file_names"].extend(new_names)

    if analysis is not None:
        data["analysis"] = analysis
    if messages is not None:
        data["messages"] = messages
    with open(session_path, 'w') as f:
        json.dump(data, f, indent=2)


def load_session(conversation_id):
    """Load session data from disk."""
    session_path = os.path.join(SESSIONS_FOLDER, f"{conversation_id}.json")
    if os.path.exists(session_path):
        with open(session_path, 'r') as f:
            return json.load(f)
    return None


def list_sessions():
    """List all saved sessions, newest first."""
    sessions = []
    for fname in os.listdir(SESSIONS_FOLDER):
        if fname.endswith('.json'):
            fpath = os.path.join(SESSIONS_FOLDER, fname)
            try:
                with open(fpath, 'r') as f:
                    data = json.load(f)
                sessions.append({
                    "id": data.get("id", fname[:-5]),
                    "file_name": data.get("file_name"),
                    "file_names": data.get("file_names", [data["file_name"]] if data.get("file_name") else []),
                    "file_type": data.get("file_type"),
                    "created": data.get("created"),
                    "updated": data.get("updated"),
                    "message_count": len(data.get("messages", []))
                })
            except Exception:
                pass
    sessions.sort(key=lambda s: s.get("updated") or s.get("created") or "", reverse=True)
    return sessions

# ============================================================================
# SYSTEM PROMPT - Network Analysis Expert
# ============================================================================

SYSTEM_PROMPT = """You are a Network Traffic Analysis Expert specializing in Azure networking troubleshooting.

Your capabilities:
- Analyze PCAP packet captures for connectivity issues, latency, drops, and protocol problems
- Analyze HAR files for HTTP/HTTPS issues, slow requests, failed API calls
- Identify common patterns: TCP retransmissions, RST floods, DNS failures, TLS issues
- Provide actionable troubleshooting steps based on the data

When analyzing data, focus on:
1. **Anomalies**: Unusual traffic patterns, high error rates, connection failures
2. **Performance**: Latency issues, slow requests, timeouts
3. **Security**: Suspicious traffic, unusual ports, potential attacks
4. **Root Cause**: What's causing the issue and how to fix it

Always provide:
- Clear summary of findings
- Specific problems identified
- Actionable next steps
- Relevant Azure networking context when applicable

Format your response with clear sections and bullet points for readability."""

# ============================================================================
# PCAP ANALYSIS FUNCTIONS
# ============================================================================

def analyze_pcap_detailed(filepath: str) -> dict:
    """Deep analysis of PCAP file."""
    if not SCAPY_AVAILABLE:
        return {"error": "scapy not installed. Run: pip install scapy"}
    
    try:
        packets = rdpcap(filepath)
        
        # Basic stats
        stats = {
            "file_name": Path(filepath).name,
            "total_packets": len(packets),
            "capture_duration_sec": 0,
            "protocols": {"tcp": 0, "udp": 0, "icmp": 0, "arp": 0, "dns": 0, "other": 0},
            "tcp_flags": {"syn": 0, "syn_ack": 0, "ack": 0, "rst": 0, "fin": 0, "psh": 0},
            "issues_detected": [],
            "conversations": {},
            "top_talkers": {},
            "ports_used": set(),
            "dns_queries": [],
            "http_requests": [],
            "retransmissions": 0,
            "errors": []
        }
        
        first_time = None
        last_time = None
        seen_seqs = {}
        
        for pkt in packets:
            try:
                # Track time
                if hasattr(pkt, 'time'):
                    if first_time is None:
                        first_time = float(pkt.time)
                    last_time = float(pkt.time)
                
                # Layer 2 - ARP
                if ARP in pkt:
                    stats["protocols"]["arp"] += 1
                    continue
                
                # Layer 3 - IP
                if IP not in pkt:
                    stats["protocols"]["other"] += 1
                    continue
                
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Track talkers
                stats["top_talkers"][src_ip] = stats["top_talkers"].get(src_ip, 0) + 1
                
                # Layer 4 - TCP
                if TCP in pkt:
                    stats["protocols"]["tcp"] += 1
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    flags = pkt[TCP].flags
                    
                    stats["ports_used"].add(dport)
                    
                    # Track TCP flags
                    if flags & 0x02:  # SYN
                        if flags & 0x10:  # SYN-ACK
                            stats["tcp_flags"]["syn_ack"] += 1
                        else:
                            stats["tcp_flags"]["syn"] += 1
                    if flags & 0x10:  # ACK
                        stats["tcp_flags"]["ack"] += 1
                    if flags & 0x04:  # RST
                        stats["tcp_flags"]["rst"] += 1
                    if flags & 0x01:  # FIN
                        stats["tcp_flags"]["fin"] += 1
                    if flags & 0x08:  # PSH
                        stats["tcp_flags"]["psh"] += 1
                    
                    # Track conversations
                    conv_key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
                    if conv_key not in stats["conversations"]:
                        stats["conversations"][conv_key] = {"packets": 0, "bytes": 0, "rst": False}
                    stats["conversations"][conv_key]["packets"] += 1
                    stats["conversations"][conv_key]["bytes"] += len(pkt)
                    if flags & 0x04:
                        stats["conversations"][conv_key]["rst"] = True
                    
                    # Detect retransmissions (simplified)
                    seq = pkt[TCP].seq
                    seq_key = (src_ip, dst_ip, sport, dport, seq)
                    if seq_key in seen_seqs:
                        stats["retransmissions"] += 1
                    else:
                        seen_seqs[seq_key] = True
                    
                    # HTTP detection
                    if HTTPRequest in pkt:
                        try:
                            host = pkt[HTTPRequest].Host.decode() if pkt[HTTPRequest].Host else ""
                            path = pkt[HTTPRequest].Path.decode() if pkt[HTTPRequest].Path else ""
                            method = pkt[HTTPRequest].Method.decode() if pkt[HTTPRequest].Method else ""
                            stats["http_requests"].append(f"{method} {host}{path}")
                        except:
                            pass
                
                # Layer 4 - UDP
                elif UDP in pkt:
                    stats["protocols"]["udp"] += 1
                    dport = pkt[UDP].dport
                    stats["ports_used"].add(dport)
                    
                    # DNS
                    if DNS in pkt and pkt[DNS].qr == 0:  # Query
                        stats["protocols"]["dns"] += 1
                        try:
                            qname = pkt[DNS].qd.qname.decode().rstrip('.')
                            stats["dns_queries"].append(qname)
                        except:
                            pass
                
                # Layer 4 - ICMP
                elif ICMP in pkt:
                    stats["protocols"]["icmp"] += 1
                    icmp_type = pkt[ICMP].type
                    if icmp_type == 3:  # Destination Unreachable
                        stats["errors"].append(f"ICMP Dest Unreachable: {src_ip} -> {dst_ip}")
                    elif icmp_type == 11:  # Time Exceeded
                        stats["errors"].append(f"ICMP Time Exceeded: {src_ip}")
                
                else:
                    stats["protocols"]["other"] += 1
                    
            except Exception as e:
                continue
        
        # Calculate duration
        if first_time and last_time:
            stats["capture_duration_sec"] = round(last_time - first_time, 2)
        
        # Identify issues
        issues = []
        
        # High RST count
        rst_ratio = stats["tcp_flags"]["rst"] / max(stats["protocols"]["tcp"], 1)
        if rst_ratio > 0.1:
            issues.append(f"⚠️ High RST ratio ({rst_ratio:.1%}) - connections being forcibly closed")
        
        # Retransmissions
        retrans_ratio = stats["retransmissions"] / max(stats["protocols"]["tcp"], 1)
        if retrans_ratio > 0.05:
            issues.append(f"⚠️ High retransmission rate ({retrans_ratio:.1%}) - possible packet loss or latency")
        
        # Incomplete handshakes
        if stats["tcp_flags"]["syn"] > stats["tcp_flags"]["syn_ack"] * 1.5:
            issues.append("⚠️ Many unanswered SYN packets - possible connection failures or firewall blocking")
        
        # ICMP errors
        if stats["errors"]:
            issues.append(f"⚠️ {len(stats['errors'])} ICMP errors detected")
        
        stats["issues_detected"] = issues
        
        # Convert sets to lists and limit sizes
        stats["ports_used"] = sorted(list(stats["ports_used"]))[:30]
        stats["dns_queries"] = list(set(stats["dns_queries"]))[:20]
        stats["http_requests"] = stats["http_requests"][:20]
        
        # Top talkers - top 10
        stats["top_talkers"] = dict(sorted(stats["top_talkers"].items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Conversation summary
        conv_summary = []
        for conv, data in sorted(stats["conversations"].items(), key=lambda x: x[1]["packets"], reverse=True)[:10]:
            src, dst = conv
            conv_summary.append({
                "src": f"{src[0]}:{src[1]}",
                "dst": f"{dst[0]}:{dst[1]}",
                "packets": data["packets"],
                "bytes": data["bytes"],
                "rst": data["rst"]
            })
        stats["top_conversations"] = conv_summary
        del stats["conversations"]
        
        return stats
        
    except Exception as e:
        return {"error": str(e)}


def analyze_har_detailed(filepath: str) -> dict:
    """Deep analysis of HAR file."""
    if not HARALYZER_AVAILABLE:
        return {"error": "haralyzer not installed. Run: pip install haralyzer"}
    
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            har_data = json.load(f)
        
        entries = har_data.get("log", {}).get("entries", [])
        
        stats = {
            "file_name": Path(filepath).name,
            "total_requests": len(entries),
            "methods": {},
            "status_codes": {},
            "domains": {},
            "content_types": {},
            "timing": {
                "total_time_ms": 0,
                "avg_time_ms": 0,
                "slowest_requests": [],
                "blocked_time_ms": 0,
                "dns_time_ms": 0,
                "connect_time_ms": 0,
                "ssl_time_ms": 0,
                "wait_time_ms": 0
            },
            "errors": {
                "4xx_count": 0,
                "5xx_count": 0,
                "failed_requests": [],
                "timeouts": []
            },
            "sizes": {
                "total_request_bytes": 0,
                "total_response_bytes": 0,
                "largest_responses": []
            },
            "issues_detected": []
        }
        
        request_times = []
        
        for entry in entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            timings = entry.get("timings", {})
            
            # Method
            method = req.get("method", "UNKNOWN")
            stats["methods"][method] = stats["methods"].get(method, 0) + 1
            
            # URL and domain
            url = req.get("url", "")
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
                stats["domains"][domain] = stats["domains"].get(domain, 0) + 1
            except:
                domain = "unknown"
            
            # Status code
            status = resp.get("status", 0)
            status_group = f"{status // 100}xx"
            stats["status_codes"][status_group] = stats["status_codes"].get(status_group, 0) + 1
            
            # Errors
            if 400 <= status < 500:
                stats["errors"]["4xx_count"] += 1
                stats["errors"]["failed_requests"].append({
                    "url": url[:100],
                    "status": status,
                    "statusText": resp.get("statusText", "")
                })
            elif status >= 500:
                stats["errors"]["5xx_count"] += 1
                stats["errors"]["failed_requests"].append({
                    "url": url[:100],
                    "status": status,
                    "statusText": resp.get("statusText", "")
                })
            
            # Content type
            content_type = resp.get("content", {}).get("mimeType", "unknown")
            content_type = content_type.split(";")[0]  # Remove charset
            stats["content_types"][content_type] = stats["content_types"].get(content_type, 0) + 1
            
            # Timing
            total_time = entry.get("time", 0)
            request_times.append((url[:80], total_time))
            stats["timing"]["total_time_ms"] += total_time
            
            # Detailed timings
            stats["timing"]["blocked_time_ms"] += max(timings.get("blocked", 0), 0)
            stats["timing"]["dns_time_ms"] += max(timings.get("dns", 0), 0)
            stats["timing"]["connect_time_ms"] += max(timings.get("connect", 0), 0)
            stats["timing"]["ssl_time_ms"] += max(timings.get("ssl", 0), 0)
            stats["timing"]["wait_time_ms"] += max(timings.get("wait", 0), 0)
            
            # Sizes
            req_size = req.get("headersSize", 0) + req.get("bodySize", 0)
            resp_size = resp.get("headersSize", 0) + resp.get("content", {}).get("size", 0)
            stats["sizes"]["total_request_bytes"] += max(req_size, 0)
            stats["sizes"]["total_response_bytes"] += max(resp_size, 0)
            
            # Check for timeout (> 30 sec)
            if total_time > 30000:
                stats["errors"]["timeouts"].append({
                    "url": url[:100],
                    "time_ms": total_time
                })
        
        # Calculate averages
        if stats["total_requests"] > 0:
            stats["timing"]["avg_time_ms"] = round(stats["timing"]["total_time_ms"] / stats["total_requests"], 2)
        
        # Top 10 slowest requests
        request_times.sort(key=lambda x: x[1], reverse=True)
        stats["timing"]["slowest_requests"] = [{"url": u, "time_ms": round(t, 2)} for u, t in request_times[:10]]
        
        # Top 5 domains
        stats["domains"] = dict(sorted(stats["domains"].items(), key=lambda x: x[1], reverse=True)[:5])
        
        # Limit error lists
        stats["errors"]["failed_requests"] = stats["errors"]["failed_requests"][:10]
        stats["errors"]["timeouts"] = stats["errors"]["timeouts"][:5]
        
        # Round timing values
        for key in ["total_time_ms", "blocked_time_ms", "dns_time_ms", "connect_time_ms", "ssl_time_ms", "wait_time_ms"]:
            stats["timing"][key] = round(stats["timing"][key], 2)
        
        # Identify issues
        issues = []
        
        error_rate = (stats["errors"]["4xx_count"] + stats["errors"]["5xx_count"]) / max(stats["total_requests"], 1)
        if error_rate > 0.1:
            issues.append(f"⚠️ High error rate ({error_rate:.1%}) - many requests failing")
        
        if stats["timing"]["avg_time_ms"] > 2000:
            issues.append(f"⚠️ Slow average response time ({stats['timing']['avg_time_ms']:.0f}ms)")
        
        if stats["timing"]["dns_time_ms"] > 1000:
            issues.append(f"⚠️ High DNS lookup time ({stats['timing']['dns_time_ms']:.0f}ms total)")
        
        if stats["timing"]["ssl_time_ms"] > 2000:
            issues.append(f"⚠️ High SSL/TLS handshake time ({stats['timing']['ssl_time_ms']:.0f}ms total)")
        
        if stats["errors"]["timeouts"]:
            issues.append(f"⚠️ {len(stats['errors']['timeouts'])} requests timed out (>30s)")
        
        stats["issues_detected"] = issues
        
        return stats
        
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# LLM QUERY HELPERS
# ============================================================================

def _truncate_analysis(analysis_data: dict) -> str:
    """Serialise analysis_data to JSON and truncate if needed.

    Very large PCAP/HAR files produce huge analysis dicts that exceed the
    model's context window.  We cap the serialised representation at
    ``LLM_CONTEXT_CHAR_LIMIT`` characters and append a note so the model
    knows the data was trimmed.
    """
    raw = json.dumps(analysis_data, indent=2)
    if len(raw) <= LLM_CONTEXT_CHAR_LIMIT:
        return raw
    truncated = raw[:LLM_CONTEXT_CHAR_LIMIT]
    # Close any open JSON structure gracefully so the block is valid-looking
    truncated += "\n... [truncated – file is large; shown first "
    truncated += f"{LLM_CONTEXT_CHAR_LIMIT} chars of {len(raw)} total]"
    return truncated


def _merge_analyses(analyses: list) -> dict:
    """Merge a list of per-file analysis dicts into a single summary dict.

    The merged structure keeps each file's data under its own key so the LLM
    receives all relevant context in one call.
    """
    if len(analyses) == 1:
        return analyses[0]
    merged = {"files": {}, "file_count": len(analyses)}
    for a in analyses:
        name = a.get("file_name", f"file_{len(merged['files']) + 1}")
        merged["files"][name] = a
    return merged


# ============================================================================
# LLM QUERY
# ============================================================================

def query_llm(prompt: str, analysis_data: dict = None, conversation_id: str = None) -> str:
    """Query Ollama LLM for analysis insights."""
    
    messages = []
    
    # Add conversation history
    if conversation_id and conversation_id in conversations:
        history = conversations[conversation_id][-6:]
        messages.extend(history)
    
    # Build context with analysis data (truncated if necessary)
    context = ""
    if analysis_data:
        serialised = _truncate_analysis(analysis_data)
        context = f"\n\n[ANALYSIS DATA]\n```json\n{serialised}\n```\n"
    
    user_content = prompt + context
    messages.append({"role": "user", "content": user_content})
    
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": OLLAMA_MODEL,
                "messages": [{"role": "system", "content": SYSTEM_PROMPT}] + messages,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "num_ctx": 8192
                }
            },
            timeout=120
        )
        response.raise_for_status()
        result = response.json()
        assistant_response = result.get("message", {}).get("content", "No response from model.")
        
        # Store in conversation history
        if conversation_id:
            if conversation_id not in conversations:
                conversations[conversation_id] = []
            conversations[conversation_id].append({"role": "user", "content": prompt})
            conversations[conversation_id].append({"role": "assistant", "content": assistant_response})
            conversations[conversation_id] = conversations[conversation_id][-10:]
            # Persist to disk
            save_session(conversation_id, messages=conversations[conversation_id])
        
        return assistant_response
        
    except Exception as e:
        return f"Error querying LLM: {str(e)}"


# ============================================================================
# HTML TEMPLATE - Network Analyzer UI
# ============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analyzer</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --accent: #3b82f6;
            --accent-light: #60a5fa;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border: #475569;
            --success: #22c55e;
            --warning: #f59e0b;
            --error: #ef4444;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .logo {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }
        
        .header-text h1 {
            font-size: 1.5rem;
            font-weight: 600;
        }
        
        .header-text p {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }
        
        .status {
            margin-left: auto;
            display: flex;
            gap: 1rem;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: var(--bg-primary);
            border-radius: 8px;
            font-size: 0.875rem;
        }
        
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        
        .status-dot.green { background: var(--success); }
        .status-dot.red { background: var(--error); }

        .new-session-btn {
            margin-left: 1rem;
            padding: 0.5rem 1.1rem;
            background: linear-gradient(135deg, #0078d4, #005a9e);
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.4rem;
            transition: background 0.2s, transform 0.1s, box-shadow 0.2s;
            white-space: nowrap;
        }
        .new-session-btn:hover {
            background: linear-gradient(135deg, #1a8ae6, #0078d4);
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(0, 120, 212, 0.4);
        }
        .new-session-btn:active {
            transform: translateY(0);
        }

        /* History toggle */
        .history-toggle-btn {
            margin-left: 0.5rem;
            padding: 0.5rem 1.1rem;
            background: var(--bg-primary);
            color: var(--text-primary);
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 0.875rem;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.4rem;
            transition: background 0.2s, border-color 0.2s;
            white-space: nowrap;
        }
        .history-toggle-btn:hover {
            background: var(--bg-tertiary);
            border-color: var(--accent);
        }
        .history-toggle-btn.active {
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }

        /* History sidebar */
        .history-panel {
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            width: 280px;
            min-width: 280px;
            display: none;
            flex-direction: column;
            overflow: hidden;
        }
        .history-panel.open {
            display: flex;
        }
        .history-header {
            padding: 1rem 1rem 0.75rem;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .history-list {
            flex: 1;
            overflow-y: auto;
            padding: 0.5rem;
        }
        .history-item {
            padding: 0.75rem 0.85rem;
            border-radius: 8px;
            cursor: pointer;
            margin-bottom: 0.35rem;
            transition: background 0.15s;
            border: 1px solid transparent;
        }
        .history-item:hover {
            background: var(--bg-tertiary);
        }
        .history-item.active {
            background: rgba(59, 130, 246, 0.15);
            border-color: var(--accent);
        }
        .history-item .hi-file {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-primary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }
        .history-item .hi-file .hi-icon {
            flex-shrink: 0;
        }
        .history-item .hi-meta {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
            display: flex;
            justify-content: space-between;
        }
        .history-item .hi-delete {
            opacity: 0;
            color: var(--error);
            cursor: pointer;
            font-size: 0.8rem;
            padding: 2px 6px;
            border-radius: 4px;
            transition: opacity 0.15s, background 0.15s;
        }
        .history-item:hover .hi-delete {
            opacity: 1;
        }
        .history-item .hi-delete:hover {
            background: rgba(239, 68, 68, 0.15);
        }
        .history-empty {
            text-align: center;
            color: var(--text-secondary);
            padding: 2rem 1rem;
            font-size: 0.875rem;
        }

        /* Main container */
        .main {
            display: flex;
            height: calc(100vh - 80px);
        }
        .chat-and-panel {
            flex: 1;
            display: grid;
            grid-template-columns: 1fr 350px;
            min-width: 0;
        }
        
        /* Chat area */
        .chat-container {
            display: flex;
            flex-direction: column;
            border-right: 1px solid var(--border);
        }
        
        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 1.5rem;
        }
        
        .message {
            max-width: 85%;
            margin-bottom: 1.5rem;
            padding: 1rem 1.25rem;
            border-radius: 12px;
            line-height: 1.6;
        }
        
        .message.user {
            background: var(--accent);
            margin-left: auto;
            border-bottom-right-radius: 4px;
        }
        
        .message.assistant {
            background: var(--bg-secondary);
            border-bottom-left-radius: 4px;
        }
        
        .message pre {
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            margin: 0.5rem 0;
        }
        
        .message code {
            font-family: 'Cascadia Code', 'Consolas', monospace;
            font-size: 0.875rem;
        }
        
        .message h4 {
            margin: 1rem 0 0.5rem;
            color: var(--accent-light);
        }
        
        .message ul {
            margin-left: 1.5rem;
        }
        
        .message li {
            margin: 0.25rem 0;
        }
        
        .welcome {
            text-align: center;
            padding: 3rem;
            color: var(--text-secondary);
        }
        
        .welcome h2 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
            color: var(--text-primary);
        }
        
        .welcome-features {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin-top: 2rem;
            text-align: left;
        }
        
        .feature-card {
            background: var(--bg-secondary);
            padding: 1.25rem;
            border-radius: 12px;
            border: 1px solid var(--border);
        }
        
        .feature-card h3 {
            color: var(--accent-light);
            font-size: 1rem;
            margin-bottom: 0.5rem;
        }
        
        .feature-card p {
            font-size: 0.875rem;
        }
        
        /* Input area */
        .input-area {
            padding: 1.5rem;
            background: var(--bg-secondary);
            border-top: 1px solid var(--border);
        }
        
        .upload-zone {
            border: 2px dashed var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            margin-bottom: 1rem;
            transition: all 0.2s;
            cursor: pointer;
        }
        
        .upload-zone:hover,
        .upload-zone.dragover {
            border-color: var(--accent);
            background: rgba(59, 130, 246, 0.1);
        }
        
        .upload-icon {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }
        
        .upload-text {
            color: var(--text-secondary);
            font-size: 0.875rem;
        }
        
        .upload-text strong {
            color: var(--accent-light);
        }
        
        .file-info {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1rem;
            background: var(--bg-tertiary);
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        
        .file-info .name {
            flex: 1;
            font-size: 0.875rem;
        }
        
        .file-info .remove {
            cursor: pointer;
            color: var(--error);
        }
        
        .input-row {
            display: flex;
            gap: 0.75rem;
        }
        
        .input-row textarea {
            flex: 1;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 0.875rem 1rem;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 0.95rem;
            resize: none;
            height: 50px;
        }
        
        .input-row textarea:focus {
            outline: none;
            border-color: var(--accent);
        }
        
        .input-row button {
            padding: 0 1.5rem;
            background: var(--accent);
            border: none;
            border-radius: 10px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .input-row button:hover {
            background: var(--accent-light);
        }
        
        .input-row button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        /* Analysis panel */
        .analysis-panel {
            background: var(--bg-secondary);
            padding: 1.5rem;
            overflow-y: auto;
            overflow-x: hidden;
            min-width: 0;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .panel-title {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border);
        }
        
        .analysis-card {
            background: var(--bg-primary);
            border-radius: 10px;
            padding: 1rem;
            margin-bottom: 1rem;
            word-wrap: break-word;
            overflow-wrap: break-word;
            min-width: 0;
        }
        
        .analysis-card h4 {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }
        
        .analysis-card .value {
            font-size: 1.5rem;
            font-weight: 600;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0.5rem;
        }
        
        .stat-item {
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border-radius: 8px;
        }
        
        .stat-item label {
            display: block;
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }
        
        .stat-item span {
            font-size: 1rem;
            font-weight: 600;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .issues-list {
            margin-top: 1rem;
        }
        
        .issue-item {
            padding: 0.75rem;
            background: rgba(239, 68, 68, 0.1);
            border-left: 3px solid var(--error);
            border-radius: 0 8px 8px 0;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .issue-item.warning {
            background: rgba(245, 158, 11, 0.1);
            border-left-color: var(--warning);
        }
        
        .loading {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-secondary);
        }
        
        .loading-dots {
            display: flex;
            gap: 4px;
        }
        
        .loading-dots span {
            width: 8px;
            height: 8px;
            background: var(--accent);
            border-radius: 50%;
            animation: bounce 1.4s infinite ease-in-out;
        }
        
        .loading-dots span:nth-child(1) { animation-delay: -0.32s; }
        .loading-dots span:nth-child(2) { animation-delay: -0.16s; }
        
        @keyframes bounce {
            0%, 80%, 100% { transform: scale(0); }
            40% { transform: scale(1); }
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--bg-tertiary);
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">&#x1F4E1;</div>
        <div class="header-text">
            <h1>Network Traffic Analyzer</h1>
            <p>PCAP & HAR Analysis powered by LLM</p>
        </div>
        <div class="status">
            <div class="status-item">
                <span class="status-dot green" id="llm-status"></span>
                <span>LLM Ready</span>
            </div>
            <div class="status-item">
                <span class="status-dot {{ 'green' if scapy else 'red' }}" id="pcap-status"></span>
                <span>PCAP {{ 'Ready' if scapy else 'N/A' }}</span>
            </div>
            <div class="status-item">
                <span class="status-dot {{ 'green' if har else 'red' }}" id="har-status"></span>
                <span>HAR {{ 'Ready' if har else 'N/A' }}</span>
            </div>
            <button class="new-session-btn" onclick="newSession()" title="Start a new analysis session">&#x1F504; New Session</button>
            <button class="history-toggle-btn" id="history-toggle" onclick="toggleHistory()" title="Session History">&#x1F4CB; History</button>
        </div>
    </div>
    
    <div class="main">
        <div class="history-panel" id="history-panel">
            <div class="history-header">
                <span>&#x1F4C2; Session History</span>
            </div>
            <div class="history-list" id="history-list">
                <div class="history-empty">No previous sessions</div>
            </div>
        </div>
        <div class="chat-and-panel">
        <div class="chat-container">
            <div class="chat-messages" id="chat-messages">
                <div class="welcome">
                    <h2>&#x1F50D; Network Traffic Analyzer</h2>
                    <p>Upload PCAP or HAR files for deep analysis and AI-powered insights</p>
                    
                    <div class="welcome-features">
                        <div class="feature-card">
                            <h3>&#x1F4E6; PCAP Analysis</h3>
                            <p>TCP/UDP breakdown, connection tracking, retransmissions, RST analysis, DNS queries</p>
                        </div>
                        <div class="feature-card">
                            <h3>&#x1F310; HAR Analysis</h3>
                            <p>HTTP status codes, response times, failed requests, timeout detection</p>
                        </div>
                        <div class="feature-card">
                            <h3>&#x1F916; AI Insights</h3>
                            <p>Automated issue detection, root cause analysis, troubleshooting steps</p>
                        </div>
                        <div class="feature-card">
                            <h3>&#x2601;&#xFE0F; Azure Focus</h3>
                            <p>Optimized for Azure networking scenarios and cloud troubleshooting</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="input-area">
                <input type="file" id="file-input" accept=".pcap,.cap,.har" style="display:none;" multiple onchange="onFileSelected(this)">
                <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()">
                    <div class="upload-icon">&#x1F4C1;</div>
                    <div class="upload-text">
                        <strong>Click to upload</strong> or drag & drop<br>
                        PCAP, CAP, or HAR files &mdash; multiple files allowed
                    </div>
                </div>
                
                <div class="file-info" id="file-info" style="display: none;">
                    <span>&#x1F4CE;</span>
                    <span class="name" id="file-name"></span>
                    <span class="remove" onclick="removeFile()">&times;</span>
                </div>
                
                <div class="input-row">
                    <textarea id="message-input" placeholder="Ask about the analysis or describe what you're troubleshooting..." onkeypress="handleKeyPress(event)"></textarea>
                    <button id="send-btn" onclick="sendMessage()">Analyze</button>
                </div>
            </div>
        </div>
        
        <div class="analysis-panel" id="analysis-panel">
            <div class="panel-title">&#x1F4CA; Latest Analysis</div>
            <div id="analysis-content">
                <p style="color: var(--text-secondary); text-align: center; padding: 2rem;">
                    Upload a file to see analysis results
                </p>
            </div>
        </div>
        </div><!-- end chat-and-panel -->
    </div>
    
    <script>
        let uploadedFile = null;
        let uploadedFiles = [];  // supports multiple files
        let conversationId = 'session_' + Date.now();
        let isLoading = false;
        let lastAnalysis = null;
        let historyOpen = false;

        // ---------- History Panel ----------
        function toggleHistory() {
            historyOpen = !historyOpen;
            document.getElementById('history-panel').classList.toggle('open', historyOpen);
            document.getElementById('history-toggle').classList.toggle('active', historyOpen);
            if (historyOpen) loadHistory();
        }

        async function loadHistory() {
            try {
                const resp = await fetch('/sessions');
                const sessions = await resp.json();
                renderHistory(sessions);
            } catch(e) {
                console.error('Failed to load history', e);
            }
        }

        function renderHistory(sessions) {
            const list = document.getElementById('history-list');
            if (!sessions || sessions.length === 0) {
                list.innerHTML = '<div class="history-empty">No previous sessions</div>';
                return;
            }
            list.innerHTML = sessions.map(s => {
                const icon = s.file_type === 'pcap' || s.file_type === 'cap' ? '&#x1F4E6;' : s.file_type === 'har' ? '&#x1F310;' : '&#x1F4AC;';
                const name = s.file_name || 'Chat session';
                const dt = s.updated || s.created || '';
                const ago = dt ? timeAgo(dt) : '';
                const msgs = s.message_count || 0;
                const isActive = s.id === conversationId;
                return `<div class="history-item ${isActive ? 'active' : ''}" onclick="loadSession('${s.id}')">
                    <div class="hi-file"><span class="hi-icon">${icon}</span> ${escHtml(name)}</div>
                    <div class="hi-meta">
                        <span>${ago} &middot; ${msgs} msg${msgs !== 1 ? 's' : ''}</span>
                        <span class="hi-delete" onclick="event.stopPropagation(); deleteSession('${s.id}')" title="Delete">&#x1F5D1;</span>
                    </div>
                </div>`;
            }).join('');
        }

        function escHtml(t) {
            const d = document.createElement('div'); d.textContent = t; return d.innerHTML;
        }

        function timeAgo(iso) {
            const diff = (Date.now() - new Date(iso).getTime()) / 1000;
            if (diff < 60) return 'just now';
            if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
            if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
            if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
            return new Date(iso).toLocaleDateString();
        }

        async function loadSession(sid) {
            try {
                const resp = await fetch('/sessions/' + sid);
                if (!resp.ok) return;
                const data = await resp.json();

                // Switch to this session
                conversationId = data.id;
                lastAnalysis = data.analysis;
                uploadedFile = null;
                uploadedFiles = [];
                isLoading = false;
                removeFile();

                // Rebuild chat messages
                const messagesEl = document.getElementById('chat-messages');
                messagesEl.innerHTML = '';
                if (data.messages && data.messages.length > 0) {
                    data.messages.forEach(m => {
                        const msgEl = document.createElement('div');
                        msgEl.className = 'message ' + m.role;
                        msgEl.innerHTML = formatMarkdown(m.content);
                        messagesEl.appendChild(msgEl);
                    });
                    scrollToBottom();
                } else {
                    messagesEl.innerHTML = getWelcomeHtml();
                }

                // Rebuild analysis panel
                if (data.analysis) {
                    updateAnalysisPanel(data.analysis);
                } else {
                    document.getElementById('analysis-content').innerHTML =
                        '<p style="color: var(--text-secondary); text-align: center; padding: 2rem;">Upload a file to see analysis results</p>';
                }

                // Re-render history to highlight active
                loadHistory();

                document.getElementById('message-input').value = '';
                document.getElementById('send-btn').disabled = false;
            } catch(e) {
                console.error('Failed to load session', e);
            }
        }

        async function deleteSession(sid) {
            if (!confirm('Delete this session?')) return;
            try {
                await fetch('/sessions/' + sid, { method: 'DELETE' });
                if (sid === conversationId) newSession();
                loadHistory();
            } catch(e) {
                console.error('Failed to delete session', e);
            }
        }

        function getWelcomeHtml() {
            return `<div class="welcome">
                    <h2>&#x1F50D; Network Traffic Analyzer</h2>
                    <p>Upload PCAP or HAR files for deep analysis and AI-powered insights</p>
                    <div class="welcome-features">
                        <div class="feature-card"><h3>&#x1F4E6; PCAP Analysis</h3><p>TCP/UDP breakdown, connection tracking, retransmissions, RST analysis, DNS queries</p></div>
                        <div class="feature-card"><h3>&#x1F310; HAR Analysis</h3><p>HTTP status codes, response times, failed requests, timeout detection</p></div>
                        <div class="feature-card"><h3>&#x1F916; AI Insights</h3><p>Automated issue detection, root cause analysis, troubleshooting steps</p></div>
                        <div class="feature-card"><h3>&#x2601;&#xFE0F; Azure Focus</h3><p>Optimized for Azure networking scenarios and cloud troubleshooting</p></div>
                    </div>
                </div>`;
        }

        // Load history on startup
        setTimeout(loadHistory, 500);

        function newSession() {
            // Clear server-side conversation history for this session
            fetch('/clear', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({conversation_id: conversationId})
            }).catch(() => {});

            // Generate new session id
            conversationId = 'session_' + Date.now();
            uploadedFile = null;
            uploadedFiles = [];
            lastAnalysis = null;
            isLoading = false;

            // Reset file upload UI
            removeFile();

            // Reset chat area — restore welcome content
            document.getElementById('chat-messages').innerHTML = getWelcomeHtml();

            // Reset analysis panel
            document.getElementById('analysis-content').innerHTML =
                '<p style="color: var(--text-secondary); text-align: center; padding: 2rem;">Upload a file to see analysis results</p>';

            // Reset input
            document.getElementById('message-input').value = '';
            document.getElementById('send-btn').disabled = false;

            // Refresh history sidebar
            if (historyOpen) loadHistory();
        }

        function onFileSelected(input) {
            var files = Array.from(input.files);
            if (files.length > 0) setFiles(files);
        }
        
        // Drag and drop
        var uploadZone = document.getElementById('upload-zone');
        
        uploadZone.addEventListener('dragover', function(e) {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });
        
        uploadZone.addEventListener('dragleave', function() {
            uploadZone.classList.remove('dragover');
        });
        
        uploadZone.addEventListener('drop', function(e) {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            var files = Array.from(e.dataTransfer.files);
            if (files.length > 0) setFiles(files);
        });
        
        function setFiles(files) {
            const validExts = ['.pcap', '.cap', '.har'];
            const invalid = files.filter(f => !validExts.includes('.' + f.name.split('.').pop().toLowerCase()));
            if (invalid.length > 0) {
                alert('Unsupported file type(s): ' + invalid.map(f => f.name).join(', ') + '. Please upload PCAP, CAP, or HAR files only.');
                return;
            }

            // Merge with any already-queued files (avoid duplicates by name+size)
            const existingKeys = new Set(uploadedFiles.map(f => f.name + ':' + f.size));
            files.forEach(f => { if (!existingKeys.has(f.name + ':' + f.size)) uploadedFiles.push(f); });
            uploadedFile = uploadedFiles[0] || null;  // keep legacy compat

            const label = uploadedFiles.length === 1
                ? uploadedFiles[0].name
                : uploadedFiles.length + ' files selected: ' + uploadedFiles.map(f => f.name).join(', ');
            document.getElementById('file-name').textContent = label;
            document.getElementById('file-info').style.display = 'flex';
            document.getElementById('upload-zone').style.display = 'none';
        }

        // setFile is a convenience wrapper used by drag-and-drop and any other
        // single-file callers; it delegates to the multi-file setFiles().
        function setFile(file) { setFiles([file]); }
        
        function removeFile() {
            uploadedFile = null;
            uploadedFiles = [];
            document.getElementById('file-info').style.display = 'none';
            document.getElementById('upload-zone').style.display = 'block';
            document.getElementById('file-input').value = '';
        }
        
        function handleKeyPress(event) {
            if (event.key === 'Enter' && !event.shiftKey) {
                event.preventDefault();
                sendMessage();
            }
        }
        
        async function sendMessage() {
            if (isLoading) return;
            
            const input = document.getElementById('message-input');
            let message = input.value.trim();
            
            if (!message && uploadedFiles.length === 0) return;
            
            if (!message && uploadedFiles.length > 0) {
                message = uploadedFiles.length === 1
                    ? "Analyze this file and identify any issues or anomalies."
                    : `Analyze these ${uploadedFiles.length} files and identify any issues or anomalies.`;
            }
            
            isLoading = true;
            document.getElementById('send-btn').disabled = true;
            input.value = '';
            
            // Show user message
            addMessage(message, 'user');
            
            // Show loading
            const loadingEl = document.createElement('div');
            loadingEl.className = 'message assistant';
            loadingEl.innerHTML = '<div class="loading"><div class="loading-dots"><span></span><span></span><span></span></div> Analyzing...</div>';
            document.getElementById('chat-messages').appendChild(loadingEl);
            scrollToBottom();
            
            try {
                const formData = new FormData();
                formData.append('message', message);
                formData.append('conversation_id', conversationId);
                
                if (uploadedFiles.length > 0) {
                    uploadedFiles.forEach(f => formData.append('file', f));
                    uploadedFile = null;
                    uploadedFiles = [];
                    removeFile();
                }
                
                const resp = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await resp.json();
                loadingEl.remove();
                
                if (data.error) {
                    addMessage('Error: ' + data.error, 'assistant');
                } else {
                    addMessage(data.response, 'assistant');
                    
                    if (data.analysis) {
                        lastAnalysis = data.analysis;
                        updateAnalysisPanel(data.analysis);
                    }
                    // Refresh history after successful analysis
                    if (historyOpen) loadHistory();
                }
            } catch (e) {
                loadingEl.remove();
                addMessage('Error: Could not reach the server.', 'assistant');
            }
            
            isLoading = false;
            document.getElementById('send-btn').disabled = false;
        }
        
        function addMessage(content, role) {
            const messagesEl = document.getElementById('chat-messages');
            
            // Remove welcome if present
            const welcome = messagesEl.querySelector('.welcome');
            if (welcome) welcome.remove();
            
            const msgEl = document.createElement('div');
            msgEl.className = `message ${role}`;
            msgEl.innerHTML = formatMarkdown(content);
            messagesEl.appendChild(msgEl);
            scrollToBottom();
        }
        
        function formatMarkdown(text) {
            // Code blocks
            text = text.replace(/```(\w*)\\n?([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
            // Inline code
            text = text.replace(/`([^`]+)`/g, '<code>$1</code>');
            // Bold
            text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
            // Headers
            text = text.replace(/^### (.+)$/gm, '<h4>$1</h4>');
            text = text.replace(/^## (.+)$/gm, '<h4>$1</h4>');
            // Bullet points
            text = text.replace(/^- (.+)$/gm, '\\u2022 $1');
            // Line breaks
            text = text.replace(/\\n/g, '<br>');
            return text;
        }
        
        function updateAnalysisPanel(analysis) {
            const panel = document.getElementById('analysis-content');
            let html = '';
            
            // Multi-file merged analysis
            if (analysis.files && analysis.file_count !== undefined) {
                html = `<div class="analysis-card"><h4>Files Analyzed</h4><div class="value">${analysis.file_count}</div></div>`;
                Object.entries(analysis.files).forEach(([name, fa]) => {
                    html += `<div class="analysis-card"><h4 style="word-break:break-all;">${escHtml(name)}</h4>`;
                    if (fa.total_packets !== undefined) {
                        html += `<div class="stat-grid">
                            <div class="stat-item"><label>Packets</label><span>${fa.total_packets.toLocaleString()}</span></div>
                            <div class="stat-item"><label>Duration</label><span>${fa.capture_duration_sec}s</span></div>
                            <div class="stat-item"><label>TCP</label><span>${fa.protocols?.tcp || 0}</span></div>
                            <div class="stat-item"><label>RST</label><span style="color:${fa.tcp_flags?.rst > 10 ? 'var(--error)' : 'inherit'}">${fa.tcp_flags?.rst || 0}</span></div>
                        </div>`;
                    } else if (fa.total_requests !== undefined) {
                        html += `<div class="stat-grid">
                            <div class="stat-item"><label>Requests</label><span>${fa.total_requests}</span></div>
                            <div class="stat-item"><label>Avg ms</label><span>${fa.timing?.avg_time_ms || 0}</span></div>
                            <div class="stat-item"><label>4xx</label><span style="color:${fa.errors?.['4xx_count'] > 0 ? 'var(--warning)' : 'inherit'}">${fa.errors?.['4xx_count'] || 0}</span></div>
                            <div class="stat-item"><label>5xx</label><span style="color:${fa.errors?.['5xx_count'] > 0 ? 'var(--error)' : 'inherit'}">${fa.errors?.['5xx_count'] || 0}</span></div>
                        </div>`;
                    }
                    if (fa.issues_detected && fa.issues_detected.length > 0) {
                        fa.issues_detected.forEach(issue => { html += `<div class="issue-item warning" style="margin-top:4px">${issue}</div>`; });
                    }
                    html += '</div>';
                });
            } else if (analysis.total_packets !== undefined) {
                // PCAP Analysis
                html = `
                    <div class="analysis-card">
                        <h4>File</h4>
                        <div class="value">${analysis.file_name || 'PCAP'}</div>
                    </div>
                    <div class="analysis-card">
                        <h4>Total Packets</h4>
                        <div class="value">${analysis.total_packets.toLocaleString()}</div>
                    </div>
                    <div class="analysis-card">
                        <h4>Duration</h4>
                        <div class="value">${analysis.capture_duration_sec}s</div>
                    </div>
                    <div class="analysis-card">
                        <h4>Protocols</h4>
                        <div class="stat-grid">
                            <div class="stat-item"><label>TCP</label><span>${analysis.protocols?.tcp || 0}</span></div>
                            <div class="stat-item"><label>UDP</label><span>${analysis.protocols?.udp || 0}</span></div>
                            <div class="stat-item"><label>ICMP</label><span>${analysis.protocols?.icmp || 0}</span></div>
                            <div class="stat-item"><label>DNS</label><span>${analysis.protocols?.dns || 0}</span></div>
                        </div>
                    </div>
                    <div class="analysis-card">
                        <h4>TCP Flags</h4>
                        <div class="stat-grid">
                            <div class="stat-item"><label>SYN</label><span>${analysis.tcp_flags?.syn || 0}</span></div>
                            <div class="stat-item"><label>RST</label><span style="color: ${analysis.tcp_flags?.rst > 10 ? 'var(--error)' : 'inherit'}">${analysis.tcp_flags?.rst || 0}</span></div>
                            <div class="stat-item"><label>FIN</label><span>${analysis.tcp_flags?.fin || 0}</span></div>
                            <div class="stat-item"><label>Retrans</label><span style="color: ${analysis.retransmissions > 10 ? 'var(--warning)' : 'inherit'}">${analysis.retransmissions || 0}</span></div>
                        </div>
                    </div>
                `;
                
                if (analysis.issues_detected && analysis.issues_detected.length > 0) {
                    html += '<div class="issues-list">';
                    analysis.issues_detected.forEach(issue => {
                        html += `<div class="issue-item warning">${issue}</div>`;
                    });
                    html += '</div>';
                }
                
            } else if (analysis.total_requests !== undefined) {
                // HAR Analysis
                html = `
                    <div class="analysis-card">
                        <h4>File</h4>
                        <div class="value">${analysis.file_name || 'HAR'}</div>
                    </div>
                    <div class="analysis-card">
                        <h4>Total Requests</h4>
                        <div class="value">${analysis.total_requests}</div>
                    </div>
                    <div class="analysis-card">
                        <h4>Avg Response Time</h4>
                        <div class="value">${analysis.timing?.avg_time_ms || 0}ms</div>
                    </div>
                    <div class="analysis-card">
                        <h4>Status Codes</h4>
                        <div class="stat-grid">
                            ${Object.entries(analysis.status_codes || {}).map(([k, v]) => 
                                `<div class="stat-item"><label>${k}</label><span style="color: ${k.startsWith('4') || k.startsWith('5') ? 'var(--error)' : 'inherit'}">${v}</span></div>`
                            ).join('')}
                        </div>
                    </div>
                    <div class="analysis-card">
                        <h4>Errors</h4>
                        <div class="stat-grid">
                            <div class="stat-item"><label>4xx</label><span style="color: ${analysis.errors?.['4xx_count'] > 0 ? 'var(--warning)' : 'inherit'}">${analysis.errors?.['4xx_count'] || 0}</span></div>
                            <div class="stat-item"><label>5xx</label><span style="color: ${analysis.errors?.['5xx_count'] > 0 ? 'var(--error)' : 'inherit'}">${analysis.errors?.['5xx_count'] || 0}</span></div>
                        </div>
                    </div>
                `;
                
                if (analysis.issues_detected && analysis.issues_detected.length > 0) {
                    html += '<div class="issues-list">';
                    analysis.issues_detected.forEach(issue => {
                        html += `<div class="issue-item warning">${issue}</div>`;
                    });
                    html += '</div>';
                }
            }
            
            panel.innerHTML = html;
        }
        
        function scrollToBottom() {
            const el = document.getElementById('chat-messages');
            el.scrollTop = el.scrollHeight;
        }
    </script>
</body>
</html>
""".replace("{{ 'green' if scapy else 'red' }}", "green" if SCAPY_AVAILABLE else "red").replace("{{ 'Ready' if scapy else 'N/A' }}", "Ready" if SCAPY_AVAILABLE else "N/A").replace("{{ 'green' if har else 'red' }}", "green" if HARALYZER_AVAILABLE else "red").replace("{{ 'Ready' if har else 'N/A' }}", "Ready" if HARALYZER_AVAILABLE else "N/A")


# ============================================================================
# ROUTES
# ============================================================================

@app.route("/")
def index():
    response = app.make_response(render_template_string(HTML_TEMPLATE))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "model": OLLAMA_MODEL,
        "scapy_available": SCAPY_AVAILABLE,
        "haralyzer_available": HARALYZER_AVAILABLE
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        message = request.form.get("message", "")
        conversation_id = request.form.get("conversation_id", "default")

        # Accept files posted under either the key "file" (browser UI) or
        # "files" (API / curl clients using the plural form).
        uploaded_files = request.files.getlist("file") + request.files.getlist("files")
        # Filter out empty file entries (browser may send blank entries)
        uploaded_files = [f for f in uploaded_files if f and f.filename]

        analyses = []
        processed_names = []

        for file in uploaded_files:
            filename = file.filename.lower()
            safe_name = f"{hashlib.md5(filename.encode()).hexdigest()}_{Path(filename).name}"
            filepath = os.path.join(UPLOAD_FOLDER, safe_name)
            file.save(filepath)

            if filename.endswith(('.pcap', '.cap')):
                file_analysis = analyze_pcap_detailed(filepath)
            elif filename.endswith('.har'):
                file_analysis = analyze_har_detailed(filepath)
            else:
                return jsonify({"error": f"Unsupported file type '{Path(file.filename).suffix}'. Use PCAP, CAP, or HAR."}), 400

            if file_analysis and "error" in file_analysis:
                return jsonify({"error": file_analysis["error"]}), 400

            analyses.append(file_analysis)
            processed_names.append(file.filename)

        # Merge all per-file analyses into one structure for the LLM
        analysis = _merge_analyses(analyses) if analyses else None

        if analysis:
            # Persist cumulative file names and latest analysis to session
            save_session(conversation_id, file_names=processed_names, analysis=analysis)

        # If no message but files uploaded, generate default prompt
        if not message and analysis:
            if len(processed_names) == 1:
                message = "Analyze this capture and identify any issues, anomalies, or troubleshooting insights."
            else:
                message = (
                    f"Analyze these {len(processed_names)} captures and identify any issues, "
                    "anomalies, or troubleshooting insights."
                )

        if not message:
            return jsonify({"error": "Please provide a message or upload a file."}), 400

        # Query LLM
        response = query_llm(message, analysis, conversation_id)

        return jsonify({
            "response": response,
            "analysis": analysis,
            "file_count": len(processed_names),
            "file_names": processed_names
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/clear", methods=["POST"])
def clear():
    data = request.get_json(silent=True) or {}
    cid = data.get("conversation_id")
    if cid and cid in conversations:
        del conversations[cid]
    elif not cid:
        conversations.clear()
    return jsonify({"status": "cleared"})


@app.route("/sessions", methods=["GET"])
def get_sessions():
    return jsonify(list_sessions())


@app.route("/sessions/<session_id>", methods=["GET"])
def get_session(session_id):
    data = load_session(session_id)
    if data:
        return jsonify(data)
    return jsonify({"error": "Session not found"}), 404


@app.route("/sessions/<session_id>", methods=["DELETE"])
def delete_session(session_id):
    session_path = os.path.join(SESSIONS_FOLDER, f"{session_id}.json")
    if os.path.exists(session_path):
        os.remove(session_path)
    if session_id in conversations:
        del conversations[session_id]
    return jsonify({"status": "deleted"})


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print("Network Traffic Analyzer")
    print(f"{'='*60}")
    print(f"PCAP Analysis: {'✓ Available' if SCAPY_AVAILABLE else '✗ Not Available (pip install scapy)'}")
    print(f"HAR Analysis:  {'✓ Available' if HARALYZER_AVAILABLE else '✗ Not Available (pip install haralyzer)'}")
    print(f"LLM Model:     {OLLAMA_MODEL}")
    print(f"Upload Limit:  {'Unlimited' if not MAX_CONTENT_LENGTH else str(_max_upload_mb) + ' MB'}")
    print(f"LLM Context:   {LLM_CONTEXT_CHAR_LIMIT} chars max per analysis")
    print(f"Server:        http://0.0.0.0:{PORT}")
    print(f"{'='*60}\n")
    
    app.run(host="0.0.0.0", port=PORT, debug=False)
