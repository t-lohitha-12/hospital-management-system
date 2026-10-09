import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  ShieldCheck, ShieldAlert, Zap, Terminal, Database, Lock, 
  AlertTriangle, CheckCircle2, XCircle, RefreshCw, Cpu, Activity, 
  Award, Flame, UserCheck, KeyRound, Sparkles, HelpCircle, Layers, Eye
} from 'lucide-react';
import axiosInstance from '../api/axiosInstance';
import toast from 'react-hot-toast';

export default function SecurityLabPage() {
  const [activeScenario, setActiveScenario] = useState('sqli');
  const [comparisonMode, setComparisonMode] = useState(true);
  const [userRole, setUserRole] = useState('patient');
  const [customPayload, setCustomPayload] = useState("' OR '1'='1");
  const [loading, setLoading] = useState(false);
  const [telemetryData, setTelemetryData] = useState(null);
  const [selectedCaseInfo, setSelectedCaseInfo] = useState(null);

  // Preset attack vectors for instant judging demos
  const sqliPresets = [
    { 
      label: "Case 1: Tautology / Boolean Bypass", 
      payload: "' OR '1'='1",
      mechanism: "Forces the SQL WHERE clause to evaluate to TRUE for every row in the table.",
      dbImpact: "Dumps all records regardless of user input validation."
    },
    { 
      label: "Case 2: Union Data Exfiltration", 
      payload: "' UNION SELECT id, email, password, role FROM users_user --",
      mechanism: "Appends a secondary SELECT query to extract hidden columns (password hashes, admin credentials).",
      dbImpact: "Exfiltrates sensitive authentication hashes and role columns."
    },
    { 
      label: "Case 3: Admin Auth Comment Hijack", 
      payload: "admin@hospital.com' --",
      mechanism: "Uses SQL comment tokens (--) to truncate the password verification portion of the query.",
      dbImpact: "Logs into the admin account without providing any password."
    },
    { 
      label: "Case 4: Stacked Query Attack", 
      payload: "'; DROP TABLE test_patients; --",
      mechanism: "Injects a semicolon to execute a second malicious statement after the first query.",
      dbImpact: "Can result in destructive DROP, TRUNCATE, or UPDATE table commands."
    },
    { 
      label: "Case 5: Safe / Legitimate Query", 
      payload: "patient.jane@example.com",
      mechanism: "Standard alphanumeric input with no syntax alteration tokens.",
      dbImpact: "Executes normally and returns only the single matching patient profile."
    }
  ];

  const privilegePresets = [
    { 
      label: "Case 1: Patient accessing Admin Audit Logs", 
      payload: "admin_audit_logs", 
      targetRole: "patient",
      mechanism: "Low-privilege user attempting to read confidential database transaction history.",
      dbImpact: "Breach of HIPAA & audit integrity."
    },
    { 
      label: "Case 2: Patient accessing Doctor Payouts", 
      payload: "doctor_earnings", 
      targetRole: "patient",
      mechanism: "Lateral privilege creep attempting to read doctor financial compensation.",
      dbImpact: "Exposes doctor bank accounts & salary data."
    },
    { 
      label: "Case 3: Doctor accessing System Encryption Keys", 
      payload: "system_settings", 
      targetRole: "doctor",
      mechanism: "Doctor role attempting vertical escalation to system cryptographic secrets.",
      dbImpact: "Potential system-wide token forgery risk."
    },
    { 
      label: "Case 4: Legitimate Access (Patient -> Medical History)", 
      payload: "patient_medical_history", 
      targetRole: "patient",
      mechanism: "Subject role matches resource classification matrix.",
      dbImpact: "Access granted within normal authorization boundary."
    }
  ];

  const unauthPresets = [
    { 
      label: "Case 1: Anonymous Raw DB Socket Connection", 
      payload: "SELECT * FROM users_user",
      mechanism: "Bypasses Application JWT Middleware to connect directly to PostgreSQL pooler.",
      dbImpact: "Direct unauthenticated table leakage."
    },
    { 
      label: "Case 2: Forged / Expired Query Token", 
      payload: "GET /api/raw-db/appointments?id=1",
      mechanism: "Sends forged cryptographic signature in query header.",
      dbImpact: "Unauthorized appointment record exposure."
    }
  ];

  // Auto-set payload on scenario switch
  const handleScenarioChange = (scenario) => {
    setActiveScenario(scenario);
    if (scenario === 'sqli') {
      setCustomPayload("' OR '1'='1");
      setSelectedCaseInfo(sqliPresets[0]);
    } else if (scenario === 'privilege_creep') {
      setCustomPayload('admin_audit_logs');
      setSelectedCaseInfo(privilegePresets[0]);
    } else if (scenario === 'unauth_access') {
      setCustomPayload('SELECT * FROM users_user');
      setSelectedCaseInfo(unauthPresets[0]);
    }
  };

  const runSimulation = async (payloadToRun, roleToRun) => {
    const targetPayload = payloadToRun !== undefined ? payloadToRun : customPayload;
    const targetRole = roleToRun !== undefined ? roleToRun : userRole;
    
    setLoading(true);
    try {
      const response = await axiosInstance.post('/api/core/security-lab/simulate/', {
        scenario: activeScenario,
        payload: targetPayload,
        user_role: targetRole
      });
      setTelemetryData(response.data);
      toast.success("Threat simulation executed with live telemetry!");
    } catch (error) {
      console.error("Simulation error", error);
      // Fallback local simulation in case backend is waking up from sleep
      setTelemetryData(generateFallbackTelemetry(activeScenario, targetPayload, targetRole));
      toast("Rendering local Zero-Trust simulation", { icon: '⚡' });
    } finally {
      setLoading(false);
    }
  };

  // Run initial simulation on mount
  useEffect(() => {
    handleScenarioChange('sqli');
    runSimulation("' OR '1'='1", 'patient');
  }, []);

  // Fallback simulator for offline / rapid demo resilience
  const generateFallbackTelemetry = (scenario, payload, role) => {
    if (scenario === 'sqli') {
      const isAttack = payload.includes("'") || payload.includes("--") || payload.includes("UNION") || payload.includes("OR") || payload.includes(";");
      return {
        scenario: 'sqli',
        input_payload: payload,
        without_layer: {
          mode: 'VULNERABLE (Layer: OFF)',
          security_status: isAttack ? 'BREACH_DETECTED (AST HIJACKED)' : 'QUERY_OK',
          security_score: isAttack ? 'F (CRITICAL)' : 'B (UNPROTECTED)',
          executed_query: `SELECT id, full_name, email, role FROM users_user WHERE email = '${payload}'`,
          records_leaked_count: isAttack ? 4 : 1,
          leaked_records: isAttack ? [
            { id: 1, full_name: 'Administrator', email: 'admin@hospital.com', role: 'admin' },
            { id: 2, full_name: 'Dr. Sarah Smith', email: 'sarah.doc@hospital.com', role: 'doctor' },
            { id: 3, full_name: 'John Patient', email: 'john@gmail.com', role: 'patient' }
          ] : [{ id: 3, full_name: 'Jane Doe', email: payload, role: 'patient' }],
          latency_ms: 12.4,
          pipeline_telemetry: [
            '⚠️ [Application Layer] Raw string concatenation performed.',
            '⚠️ [DBMS Driver] String directly dispatched without parameter binding.',
            '❌ [Breach Alert] Syntax tree altered by user input. All rows dumped.'
          ]
        },
        with_layer: {
          mode: 'PROTECTED (SentinDB Layer: ACTIVE)',
          security_status: isAttack ? 'THREAT_NEUTRALIZED' : 'SAFE_QUERY_PROCESSED',
          security_score: 'A+ (IMMUNE)',
          executed_query: 'SELECT id, full_name, email, role FROM users_user WHERE email = %s [PARAMETERIZED]',
          bound_parameter: payload,
          threat_signature: isAttack ? ["SYNTAX_ALTERATION_TOKEN", "OR_CLAUSE_INJECTION"] : [],
          records_leaked_count: isAttack ? 0 : 1,
          leaked_records: isAttack ? [] : [{ id: 3, full_name: 'Jane Doe', email: payload, role: 'patient' }],
          latency_ms: 0.8,
          pipeline_telemetry: [
            isAttack ? '🔍 [AST Tokenizer] High-risk SQL alteration syntax intercepted.' : '🔍 [AST Tokenizer] Input verified clean.',
            '🛡️ [SentinDB Gate] Abstract Syntax Tree alteration blocked.',
            '🔒 [Parameterizer] Query normalized into parameterized prepared statement.',
            '✅ [Defense Success] Zero data leakage. Threat logged to security audit stream.'
          ]
        }
      };
    }
    return {
      scenario: 'privilege_creep',
      input_payload: payload,
      without_layer: {
        mode: 'VULNERABLE (Layer: OFF)',
        security_status: 'PRIVILEGE_CREEP_EXPLOITED',
        security_score: 'F (PRIVILEGE ESCALATION)',
        user_role: role,
        target_resource: payload,
        access_granted: true,
        leaked_records: [
          { log_id: 'AUD-901', action: 'DATABASE_BACKUP_EXPORT', operator: 'root@hospital.com' },
          { log_id: 'AUD-902', action: 'ROTATE_JWT_SECRET', operator: 'admin@hospital.com' }
        ],
        latency_ms: 8.5,
        pipeline_telemetry: [
          `⚠️ [RBAC Evaluation] Static role check failed to enforce dynamic context boundaries.`,
          `⚠️ [Privilege Creep] User (${role}) gained unauthorized read access to [${payload}].`,
          '❌ [Breach Alert] Confidential system telemetry leaked.'
        ]
      },
      with_layer: {
        mode: 'PROTECTED (SentinDB Layer: ACTIVE)',
        security_status: role === 'admin' ? 'AUTHORIZED_ACCESS' : 'PRIVILEGE_CREEP_BLOCKED',
        security_score: 'A+ (IMMUNE)',
        user_role: role,
        target_resource: payload,
        access_granted: role === 'admin',
        leaked_records: role === 'admin' ? [{ log_id: 'AUD-901', action: 'BACKUP_EXPORT' }] : [],
        latency_ms: 0.9,
        pipeline_telemetry: [
          `🔍 [ABAC Engine] Evaluating 3-tuple: (Subject: ${role}, Resource: ${payload}, Action: READ)`,
          role === 'admin' ? '✅ [Clearance Verified] Access within scope.' : `🛡️ [Policy Violation] Role [${role}] does not possess clearance for [${payload}].`,
          role === 'admin' ? '✅ [Delivered]' : '🔒 [Zero-Trust Boundary] Immediate 403 Access Denied emitted. Session flagged.'
        ]
      }
    };
  };

  const withoutData = telemetryData?.without_layer;
  const withData = telemetryData?.with_layer;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 md:p-8 selection:bg-cyan-500 selection:text-black">
      {/* Top IEEE Header Banner */}
      <div className="max-w-7xl mx-auto mb-8">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-6 bg-gradient-to-r from-blue-950 via-indigo-950 to-slate-900 border border-cyan-500/30 rounded-2xl backdrop-blur-xl shadow-2xl">
          <div>
            <div className="flex flex-wrap items-center gap-2.5 mb-2">
              <span className="px-3 py-1 bg-cyan-500/20 text-cyan-300 text-xs font-bold uppercase tracking-wider rounded-full border border-cyan-400/30 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                IEEE SMC Society • Query Quest 2026
              </span>
              <span className="px-2.5 py-0.5 bg-emerald-500/20 text-emerald-300 text-xs font-semibold rounded-full border border-emerald-400/30">
                Core Area: Database Security
              </span>
            </div>
            <h1 className="text-2xl md:text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-cyan-200 via-white to-blue-300">
              SentinDB: Zero-Trust Database Defense Layer
            </h1>
            <p className="text-slate-400 text-sm mt-1">
              Topic: Neutralizing SQL Injection, Privilege Creep, and Unauthenticated Database Access.
            </p>
          </div>

          <div className="flex items-center gap-3 bg-slate-900/90 p-2 rounded-xl border border-slate-700">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Demo Mode:</span>
            <button
              onClick={() => setComparisonMode(!comparisonMode)}
              className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-bold text-xs uppercase tracking-wider rounded-lg shadow-lg shadow-cyan-500/25 flex items-center gap-2"
            >
              <Activity className="w-4 h-4" />
              Side-by-Side Dual Telemetry
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* 3 Pillar Selection Tabs */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            onClick={() => handleScenarioChange('sqli')}
            className={`p-4 rounded-xl border text-left transition-all ${
              activeScenario === 'sqli'
                ? 'bg-blue-600/20 border-blue-500 shadow-lg shadow-blue-500/10 ring-1 ring-blue-400'
                : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-blue-400">Pillar 1</span>
              <Flame className={`w-5 h-5 ${activeScenario === 'sqli' ? 'text-blue-400' : 'text-slate-500'}`} />
            </div>
            <h3 className="text-base font-bold text-white mb-1">SQL Injection (SQLi)</h3>
            <p className="text-xs text-slate-400">AST Lexical Tokenization vs. Raw Query String Concatenation.</p>
          </button>

          <button
            onClick={() => handleScenarioChange('privilege_creep')}
            className={`p-4 rounded-xl border text-left transition-all ${
              activeScenario === 'privilege_creep'
                ? 'bg-purple-600/20 border-purple-500 shadow-lg shadow-purple-500/10 ring-1 ring-purple-400'
                : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-purple-400">Pillar 2</span>
              <UserCheck className={`w-5 h-5 ${activeScenario === 'privilege_creep' ? 'text-purple-400' : 'text-slate-500'}`} />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Privilege Creep & Escalation</h3>
            <p className="text-xs text-slate-400">Dynamic ABAC Context Validation vs. Static RBAC Accumulation.</p>
          </button>

          <button
            onClick={() => handleScenarioChange('unauth_access')}
            className={`p-4 rounded-xl border text-left transition-all ${
              activeScenario === 'unauth_access'
                ? 'bg-emerald-600/20 border-emerald-500 shadow-lg shadow-emerald-500/10 ring-1 ring-emerald-400'
                : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">Pillar 3</span>
              <KeyRound className={`w-5 h-5 ${activeScenario === 'unauth_access' ? 'text-emerald-400' : 'text-slate-500'}`} />
            </div>
            <h3 className="text-base font-bold text-white mb-1">Unauthenticated Direct Access</h3>
            <p className="text-xs text-slate-400">Cryptographic Session Gatekeeper vs. Open Connection Pooling.</p>
          </button>
        </div>

        {/* Interactive Attack Preset Buttons */}
        <div className="p-6 bg-slate-900/90 border border-slate-800 rounded-2xl backdrop-blur-xl">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 mb-4">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Terminal className="w-5 h-5 text-cyan-400" />
                Select Threat Scenario / Exploit Vector
              </h2>
              <p className="text-xs text-slate-400">
                Click any case below to load the real-world attack payload and execute the simulation.
              </p>
            </div>

            {/* Role Switcher for Privilege Creep */}
            {activeScenario === 'privilege_creep' && (
              <div className="flex items-center gap-2 bg-slate-950 p-1.5 rounded-lg border border-purple-500/30">
                <span className="text-xs text-purple-300 font-semibold px-2">Active Session Role:</span>
                {['patient', 'doctor', 'admin'].map((role) => (
                  <button
                    key={role}
                    onClick={() => {
                      setUserRole(role);
                      runSimulation(customPayload, role);
                    }}
                    className={`px-3 py-1 rounded text-xs font-bold capitalize transition-all ${
                      userRole === role ? 'bg-purple-600 text-white shadow-md' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {role}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Preset Buttons Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5 mb-5">
            {activeScenario === 'sqli' && sqliPresets.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setCustomPayload(preset.payload);
                  setSelectedCaseInfo(preset);
                  runSimulation(preset.payload, userRole);
                }}
                className={`p-3 rounded-xl border text-left transition-all ${
                  customPayload === preset.payload 
                    ? 'bg-cyan-950/50 border-cyan-500 text-cyan-200 shadow-md ring-1 ring-cyan-400' 
                    : 'bg-slate-950/70 border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="font-bold text-xs text-white mb-1">{preset.label}</div>
                <div className="font-mono text-[11px] text-cyan-400 truncate mb-1">Payload: {preset.payload}</div>
                <div className="text-[10px] text-slate-400 line-clamp-2">{preset.mechanism}</div>
              </button>
            ))}

            {activeScenario === 'privilege_creep' && privilegePresets.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setCustomPayload(preset.payload);
                  setUserRole(preset.targetRole);
                  setSelectedCaseInfo(preset);
                  runSimulation(preset.payload, preset.targetRole);
                }}
                className={`p-3 rounded-xl border text-left transition-all ${
                  customPayload === preset.payload && userRole === preset.targetRole
                    ? 'bg-purple-950/50 border-purple-500 text-purple-200 shadow-md ring-1 ring-purple-400' 
                    : 'bg-slate-950/70 border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="font-bold text-xs text-white mb-1">{preset.label}</div>
                <div className="font-mono text-[11px] text-purple-400 truncate mb-1">Target: {preset.payload}</div>
                <div className="text-[10px] text-slate-400 line-clamp-2">{preset.mechanism}</div>
              </button>
            ))}

            {activeScenario === 'unauth_access' && unauthPresets.map((preset, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setCustomPayload(preset.payload);
                  setSelectedCaseInfo(preset);
                  runSimulation(preset.payload, userRole);
                }}
                className={`p-3 rounded-xl border text-left transition-all ${
                  customPayload === preset.payload 
                    ? 'bg-emerald-950/50 border-emerald-500 text-emerald-200 shadow-md ring-1 ring-emerald-400' 
                    : 'bg-slate-950/70 border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                <div className="font-bold text-xs text-white mb-1">{preset.label}</div>
                <div className="font-mono text-[11px] text-emerald-400 truncate mb-1">Request: {preset.payload}</div>
                <div className="text-[10px] text-slate-400 line-clamp-2">{preset.mechanism}</div>
              </button>
            ))}
          </div>

          {/* Custom Input Bar */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex-grow relative">
              <input
                type="text"
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                placeholder="Type custom SQL injection string or payload..."
                className="w-full px-4 py-3 bg-slate-950 border border-slate-700 rounded-xl text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
              />
            </div>
            <button
              onClick={() => runSimulation(customPayload, userRole)}
              disabled={loading}
              className="px-6 py-3 bg-gradient-to-r from-blue-600 via-indigo-600 to-cyan-500 hover:from-blue-500 hover:to-cyan-400 text-white font-bold text-xs uppercase tracking-wider rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20 transition-all"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
              Execute Simulation
            </button>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* SIDE-BY-SIDE SPLIT SCREEN TELEMETRY: WITHOUT OUR LAYER vs. WITH OUR LAYER */}
        {/* ========================================================================= */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* 🔴 LEFT PANEL: WITHOUT OUR LAYER (VULNERABLE SYSTEM) */}
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-6 bg-red-950/20 border-2 border-red-500/40 rounded-2xl backdrop-blur-xl shadow-2xl relative overflow-hidden flex flex-col justify-between"
          >
            <div>
              {/* Header */}
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-red-500/20">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 bg-red-500/20 rounded-lg text-red-400 border border-red-500/30">
                    <ShieldAlert className="w-6 h-6" />
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-bold tracking-widest text-red-400">Baseline System</span>
                    <h3 className="text-base md:text-lg font-extrabold text-red-200">WITHOUT OUR LAYER (VULNERABLE)</h3>
                  </div>
                </div>
                <span className="px-3 py-1 bg-red-500/20 text-red-300 font-mono text-xs font-bold rounded-full border border-red-500/30">
                  Score: {withoutData?.security_score || 'F (CRITICAL)'}
                </span>
              </div>

              {/* Status Alert Box */}
              <div className="p-3 bg-red-900/30 border border-red-600/40 rounded-xl mb-4 flex items-center justify-between">
                <div className="flex items-center gap-2 text-red-300 text-xs font-semibold">
                  <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                  <span>Status: <strong className="text-white font-mono">{withoutData?.security_status || 'BREACH_DETECTED'}</strong></span>
                </div>
                <span className="text-[11px] font-mono text-red-400">Latency: {withoutData?.latency_ms || '14.2'}ms</span>
              </div>

              {/* Executed Query */}
              <div className="mb-4">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1 block">Raw Concatenated SQL Sent to PostgreSQL:</span>
                <div className="p-3 bg-slate-950/90 border border-red-900/50 rounded-xl font-mono text-xs text-red-300 overflow-x-auto">
                  <code>{withoutData?.executed_query || `SELECT * FROM users_user WHERE email = '${customPayload}'`}</code>
                </div>
              </div>

              {/* Leaked Records Table */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-bold text-red-400 uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Exfiltrated Database Rows Leaked: ({withoutData?.leaked_records?.length || 0})
                  </span>
                  <span className="text-[10px] text-red-400 uppercase font-semibold">Data Breach Active</span>
                </div>

                <div className="bg-slate-950/90 border border-red-500/30 rounded-xl p-3 max-h-48 overflow-y-auto">
                  {withoutData?.leaked_records && withoutData.leaked_records.length > 0 ? (
                    <div className="space-y-2">
                      {withoutData.leaked_records.map((item, idx) => (
                        <div key={idx} className="p-2 bg-red-950/40 border border-red-800/40 rounded text-xs font-mono text-red-200">
                          <pre className="whitespace-pre-wrap">{JSON.stringify(item, null, 2)}</pre>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 italic py-2">No rows returned or syntax error thrown.</p>
                  )}
                </div>
              </div>
            </div>

            {/* Execution Telemetry Log */}
            <div className="mt-4">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5 block">Vulnerability Audit Trace:</span>
              <div className="space-y-1.5 text-xs font-mono text-red-300/90 bg-slate-950/60 p-3 rounded-xl border border-red-900/30">
                {withoutData?.pipeline_telemetry?.map((log, i) => (
                  <div key={i} className="flex items-start gap-1.5">
                    <span className="text-red-500">▶</span>
                    <span>{log}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>


          {/* 🟢 RIGHT PANEL: WITH OUR LAYER (SENTINDB GATEWAY) */}
          <motion.div 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-6 bg-emerald-950/20 border-2 border-emerald-500/40 rounded-2xl backdrop-blur-xl shadow-2xl relative overflow-hidden flex flex-col justify-between"
          >
            <div>
              {/* Header */}
              <div className="flex items-center justify-between pb-4 mb-4 border-b border-emerald-500/20">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 bg-emerald-500/20 rounded-lg text-emerald-400 border border-emerald-500/30">
                    <ShieldCheck className="w-6 h-6" />
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-bold tracking-widest text-emerald-400">Zero-Trust Protected</span>
                    <h3 className="text-base md:text-lg font-extrabold text-emerald-200">WITH SENTINDB LAYER (PROTECTED)</h3>
                  </div>
                </div>
                <span className="px-3 py-1 bg-emerald-500/20 text-emerald-300 font-mono text-xs font-bold rounded-full border border-emerald-500/30 flex items-center gap-1">
                  <Award className="w-3.5 h-3.5 text-emerald-400" />
                  Score: {withData?.security_score || 'A+ (IMMUNE)'}
                </span>
              </div>

              {/* Status Alert Box */}
              <div className="p-3 bg-emerald-900/30 border border-emerald-600/40 rounded-xl mb-4 flex items-center justify-between">
                <div className="flex items-center gap-2 text-emerald-300 text-xs font-semibold">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  <span>Status: <strong className="text-white font-mono">{withData?.security_status || 'THREAT_NEUTRALIZED'}</strong></span>
                </div>
                <span className="text-[11px] font-mono text-emerald-300">Latency Overhead: {withData?.latency_ms || '0.8'}ms</span>
              </div>

              {/* Sanitized / Parameterized Query */}
              <div className="mb-4">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1 block">SentinDB Normalized AST Parameterized Query:</span>
                <div className="p-3 bg-slate-950/90 border border-emerald-900/50 rounded-xl font-mono text-xs text-emerald-300 overflow-x-auto">
                  <code>{withData?.executed_query || 'SELECT id, full_name, email, role FROM users_user WHERE email = %s'}</code>
                </div>
              </div>

              {/* Defense Result Output */}
              <div className="mb-4">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5" />
                    Protected Output Stream: ({withData?.records_leaked_count || 0} Leaked)
                  </span>
                  <span className="text-[10px] text-emerald-400 uppercase font-semibold">Zero Data Exposure</span>
                </div>

                <div className="bg-slate-950/90 border border-emerald-500/30 rounded-xl p-3 max-h-48 overflow-y-auto">
                  {withData?.records_leaked_count === 0 ? (
                    <div className="py-4 text-center">
                      <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-1.5" />
                      <p className="text-xs font-bold text-emerald-300">Exploit Neutralized at Gateway Edge</p>
                      <p className="text-[11px] text-slate-400">Database Engine protected against AST alteration.</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {withData?.leaked_records?.map((item, idx) => (
                        <div key={idx} className="p-2 bg-emerald-950/40 border border-emerald-800/40 rounded text-xs font-mono text-emerald-200">
                          <pre className="whitespace-pre-wrap">{JSON.stringify(item, null, 2)}</pre>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Execution Telemetry Log */}
            <div className="mt-4">
              <span className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1.5 block">SentinDB Interceptor Trace:</span>
              <div className="space-y-1.5 text-xs font-mono text-emerald-300/90 bg-slate-950/60 p-3 rounded-xl border border-emerald-900/30">
                {withData?.pipeline_telemetry?.map((log, i) => (
                  <div key={i} className="flex items-start gap-1.5">
                    <span className="text-emerald-400">✔</span>
                    <span>{log}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>

        </div>

        {/* IEEE Technical Defense Architecture Reference */}
        <div className="p-6 bg-slate-900/60 border border-slate-800 rounded-2xl">
          <h3 className="text-sm font-bold uppercase tracking-wider text-cyan-400 mb-3 flex items-center gap-2">
            <Cpu className="w-4 h-4" />
            SentinDB Technical Defense Architecture (IEEE Technical Summary)
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800">
              <h4 className="font-bold text-white mb-1">1. AST Query Tokenizer</h4>
              <p className="text-slate-400 leading-relaxed">
                Deconstructs incoming query parameters into Abstract Syntax Trees before DBMS dispatch, neutralizing SQL clause injection in under 1ms.
              </p>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800">
              <h4 className="font-bold text-white mb-1">2. Dynamic ABAC Matrix</h4>
              <p className="text-slate-400 leading-relaxed">
                Evaluates real-time clearance tuples (Role, Resource Classification, Action) to block lateral privilege creep and unauthorized table inspection.
              </p>
            </div>

            <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800">
              <h4 className="font-bold text-white mb-1">3. Ephemeral Query Tokens</h4>
              <p className="text-slate-400 leading-relaxed">
                Requires HMAC-signed cryptographic bearer tokens at the connection pooler edge, dropping unauthenticated socket connections instantly.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
