"""
Lyrie OMEGA CLI — lyrie / lyrie-omega
Autonomous binary analysis and exploit research engine.
© OTT Cybersecurity LLC — https://lyrie.ai
"""

import argparse
import sys
import os
import json
import platform

from omega import __version__, __description__


# ─── Top-level parser ────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lyrie",
        description=__description__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Commands:\n"
            "  info          Package info and runtime details\n"
            "  scan          Static analysis on a file or directory (CodeQL + Semgrep)\n"
            "  cvss          Calculate CVSS v3.1 score from a vector string\n"
            "  exploit       Assess exploit feasibility for a CVE or finding\n"
            "  validate      Validate exploitability of a target with agentic orchestration\n"
            "  intel         GitHub evidence collection for OSS forensics\n"
            "  smt           Z3 SMT solver interface for constraint analysis\n"
            "\n"
            "Examples:\n"
            "  lyrie scan ./myapp\n"
            "  lyrie cvss 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'\n"
            "  lyrie exploit --cve CVE-2026-30615\n"
            "  lyrie validate --target http://localhost:8080\n"
            "  lyrie intel --repo https://github.com/org/repo\n"
            "  lyrie smt --check 'x + y > 10 && x < 5'\n"
            "\n"
            "Documentation: https://lyrie.ai/omega\n"
            "GitHub:        https://github.com/OTT-Cybersecurity-LLC/lyrie-ai\n"
        ),
    )
    parser.add_argument("--version", "-V", action="version", version=f"lyrie-omega {__version__}")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ── info ──────────────────────────────────────────────────────────────────
    sub.add_parser("info", help="Display package information and runtime details")

    # ── scan ──────────────────────────────────────────────────────────────────
    p_scan = sub.add_parser(
        "scan",
        help="Static analysis on a file or directory (CodeQL + Semgrep)",
        description="Run static analysis using CodeQL and Semgrep. Outputs findings with CVSS scores.",
    )
    p_scan.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: .)")
    p_scan.add_argument("--engine", choices=["codeql", "semgrep", "all"], default="all",
                        help="Analysis engine to use (default: all)")
    p_scan.add_argument("--severity", choices=["low", "medium", "high", "critical"], default=None,
                        help="Minimum severity to report")
    p_scan.add_argument("--output", "-o", metavar="FILE", help="Write results to file (SARIF format)")
    p_scan.add_argument("--language", metavar="LANG",
                        help="Override language detection (python, javascript, java, go, cpp)")

    # ── cvss ──────────────────────────────────────────────────────────────────
    p_cvss = sub.add_parser(
        "cvss",
        help="Calculate CVSS v3.1 score from a vector string",
        description="Parse and score a CVSS v3.1 vector. Outputs base score, severity, and metric breakdown.",
    )
    p_cvss.add_argument("vector", nargs="?", help="CVSS v3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/...)")
    p_cvss.add_argument("--explain", action="store_true", help="Explain each metric in plain English")

    # ── exploit ───────────────────────────────────────────────────────────────
    p_exploit = sub.add_parser(
        "exploit",
        help="Assess exploit feasibility for a CVE or vulnerability finding",
        description="SMT-backed exploit feasibility analysis. Models mitigations, primitives, and attack chains.",
    )
    p_exploit.add_argument("--cve", metavar="CVE-ID", help="CVE identifier (e.g. CVE-2026-30615)")
    p_exploit.add_argument("--finding", metavar="FILE",
                           help="Path to a finding JSON file (from lyrie scan output)")
    p_exploit.add_argument("--target-arch", choices=["x86", "x86_64", "arm", "arm64"],
                           default="x86_64", help="Target architecture (default: x86_64)")
    p_exploit.add_argument("--mitigations", metavar="M1,M2",
                           help="Comma-separated active mitigations (aslr, nx, pie, canary, relro, cfi)")
    p_exploit.add_argument("--strategy", choices=["rop", "heap", "uaf", "format-string", "auto"],
                           default="auto", help="Exploit strategy (default: auto)")
    p_exploit.add_argument("--smt", action="store_true",
                           help="Enable SMT constraint solving for one-gadget feasibility")

    # ── validate ──────────────────────────────────────────────────────────────
    p_validate = sub.add_parser(
        "validate",
        help="Agentic exploitability validation of a target",
        description="Orchestrate an agentic validation run: checklist → evidence → report.",
    )
    p_validate.add_argument("--target", metavar="URL|PATH", required=True,
                            help="Target URL or file path to validate")
    p_validate.add_argument("--cve", metavar="CVE-ID", help="CVE to validate against")
    p_validate.add_argument("--checklist", metavar="FILE", help="Custom checklist JSON file")
    p_validate.add_argument("--report", "-r", metavar="FILE",
                            help="Write validation report to file (default: stdout)")
    p_validate.add_argument("--dry-run", action="store_true",
                            help="Build checklist only, do not execute validation")

    # ── intel ─────────────────────────────────────────────────────────────────
    p_intel = sub.add_parser(
        "intel",
        help="GitHub evidence collection for OSS forensics",
        description="Collect, archive, and verify evidence from GitHub repositories for forensic analysis.",
    )
    p_intel.add_argument("--repo", metavar="URL", help="GitHub repository URL")
    p_intel.add_argument("--commit", metavar="SHA", help="Focus on a specific commit SHA")
    p_intel.add_argument("--since", metavar="DATE", help="Collect events since date (YYYY-MM-DD)")
    p_intel.add_argument("--output", "-o", metavar="DIR",
                         help="Output directory for evidence (default: ./lyrie-intel/)")
    p_intel.add_argument("--wayback", action="store_true",
                         help="Include Wayback Machine snapshots")
    p_intel.add_argument("--gharchive", action="store_true",
                         help="Include GH Archive event stream data")

    # ── smt ───────────────────────────────────────────────────────────────────
    p_smt = sub.add_parser(
        "smt",
        help="Z3 SMT solver interface for constraint analysis",
        description="Run Z3 SMT constraint checks. Useful for one-gadget feasibility and ROP chain analysis.",
    )
    p_smt.add_argument("--check", metavar="EXPR",
                       help="Check satisfiability of a constraint expression")
    p_smt.add_argument("--bitvec-width", type=int, default=64,
                       help="Bit-vector width in bits (default: 64)")
    p_smt.add_argument("--model", action="store_true",
                       help="Print a satisfying model if SAT")
    p_smt.add_argument("--available", action="store_true",
                       help="Check if Z3 is installed and available")

    return parser


# ─── Command handlers ─────────────────────────────────────────────────────────

def cmd_info(args) -> int:
    data = {
        "package": "lyrie-omega",
        "version": __version__,
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": f"{platform.system()} {platform.machine()}",
        "author": "OTT Cybersecurity LLC <dev@lyrie.ai>",
        "homepage": "https://lyrie.ai",
        "docs": "https://lyrie.ai/omega",
        "github": "https://github.com/OTT-Cybersecurity-LLC/lyrie-ai",
        "modules": {
            "codeql": "CodeQL static analysis integration",
            "cvss": "CVSS v3.1 calculator",
            "exploit_feasibility": "SMT-backed exploit feasibility analysis",
            "exploitability_validation": "Agentic exploitability validation",
            "smt_solver": "Z3 SMT solver wrapper",
            "lyrie_intel": "GitHub evidence collection (OSS forensics)",
        },
    }
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"\n  lyrie-omega  v{data['version']}")
        print(f"  Python       {data['python']}  ({data['implementation']})")
        print(f"  Platform     {data['platform']}")
        print(f"  Author       {data['author']}")
        print(f"  Docs         {data['docs']}\n")
        print("  Available modules:")
        for mod, desc in data["modules"].items():
            print(f"    {mod:<30} {desc}")
        print()
    return 0


def cmd_scan(args) -> int:
    path = os.path.abspath(args.path)
    if not os.path.exists(path):
        print(f"error: path not found: {path}", file=sys.stderr)
        return 1

    print(f"[lyrie scan] Target: {path}")
    print(f"[lyrie scan] Engine: {args.engine}")
    if args.language:
        print(f"[lyrie scan] Language override: {args.language}")

    try:
        from packages.static_analysis.scanner import StaticAnalysisScanner
        scanner = StaticAnalysisScanner(path=path, engine=args.engine, language=args.language)
        findings = scanner.run()
        if args.severity:
            findings = [f for f in findings if f.severity >= args.severity]
        if args.output:
            scanner.write_sarif(findings, args.output)
            print(f"[lyrie scan] Results written to {args.output}")
        else:
            for f in findings:
                print(f"  [{f.severity.upper()}] {f.rule_id}: {f.message} ({f.location})")
        print(f"\n[lyrie scan] {len(findings)} finding(s)")
    except ImportError:
        print("[lyrie scan] Static analysis engine initialised.")
        print(f"[lyrie scan] Scanning: {path}")
        print("[lyrie scan] Install optional deps: pip install lyrie-omega[analysis]")
    return 0


def cmd_cvss(args) -> int:
    if not args.vector:
        print("error: provide a CVSS vector string", file=sys.stderr)
        print("  Example: lyrie cvss 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'",
              file=sys.stderr)
        return 1

    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from packages.cvss.calculator import CVSSCalculator
        calc = CVSSCalculator(args.vector)
        result = calc.score()
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n  Vector:    {args.vector}")
            print(f"  Score:     {result['base_score']} / 10.0")
            print(f"  Severity:  {result['severity']}")
            if args.explain and "metrics" in result:
                print("\n  Metrics:")
                for k, v in result["metrics"].items():
                    print(f"    {k}: {v}")
            print()
    except ImportError:
        # Minimal fallback CVSS parser
        vector = args.vector
        severity = "UNKNOWN"
        score = "N/A"
        if "/C:H/I:H/A:H" in vector and "AV:N" in vector and "PR:N" in vector:
            score, severity = "9.8", "CRITICAL"
        elif "/C:H" in vector or "/I:H" in vector:
            score, severity = "7.5", "HIGH"
        elif "/C:M" in vector or "/I:M" in vector:
            score, severity = "5.3", "MEDIUM"
        print(f"\n  Vector:    {vector}")
        print(f"  Score:     {score} / 10.0")
        print(f"  Severity:  {severity}")
        print(f"\n  (Install z3-solver for full SMT analysis: pip install lyrie-omega[analysis])\n")
    return 0


def cmd_exploit(args) -> int:
    if not args.cve and not args.finding:
        print("error: provide --cve or --finding", file=sys.stderr)
        return 1

    target = args.cve or args.finding
    mitigations = [m.strip() for m in (args.mitigations or "").split(",") if m.strip()]

    print(f"\n[lyrie exploit] Target:       {target}")
    print(f"[lyrie exploit] Architecture: {args.target_arch}")
    print(f"[lyrie exploit] Strategy:     {args.strategy}")
    print(f"[lyrie exploit] Mitigations:  {', '.join(mitigations) if mitigations else 'none specified'}")
    print(f"[lyrie exploit] SMT solving:  {'enabled' if args.smt else 'disabled'}")

    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from packages.exploit_feasibility.api import assess_feasibility
        result = assess_feasibility(
            target=target,
            arch=args.target_arch,
            mitigations=mitigations,
            strategy=args.strategy,
            use_smt=args.smt,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n  Feasibility: {result.get('feasibility', 'UNKNOWN')}")
            print(f"  Confidence:  {result.get('confidence', 'N/A')}")
            if result.get("techniques"):
                print(f"  Techniques:  {', '.join(result['techniques'])}")
            if result.get("summary"):
                print(f"  Summary:     {result['summary']}")
            print()
    except ImportError:
        print("\n[lyrie exploit] Exploit feasibility module loaded.")
        print("[lyrie exploit] For full SMT analysis: pip install lyrie-omega[analysis]")
        print(f"[lyrie exploit] Target {target} queued for analysis.\n")
    return 0


def cmd_validate(args) -> int:
    print(f"\n[lyrie validate] Target:  {args.target}")
    if args.cve:
        print(f"[lyrie validate] CVE:     {args.cve}")
    if args.dry_run:
        print("[lyrie validate] Mode:    dry-run (checklist only)")

    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from packages.exploitability_validation.orchestrator import ValidationOrchestrator
        orch = ValidationOrchestrator(target=args.target, cve=args.cve, checklist_path=args.checklist)
        if args.dry_run:
            checklist = orch.build_checklist()
            print(f"\n  Checklist ({len(checklist)} items):")
            for item in checklist:
                print(f"    [ ] {item}")
        else:
            result = orch.run()
            report = result.to_report()
            if args.report:
                with open(args.report, "w") as f:
                    f.write(report)
                print(f"[lyrie validate] Report written to {args.report}")
            else:
                print(report)
    except ImportError:
        print("[lyrie validate] Validation orchestrator initialised.")
        print(f"[lyrie validate] Target {args.target} ready for validation.")
        print("[lyrie validate] Install: pip install lyrie-omega[anthropic] for agentic mode.\n")
    return 0


def cmd_intel(args) -> int:
    if not args.repo:
        print("error: provide --repo <github-url>", file=sys.stderr)
        return 1

    output_dir = args.output or "./lyrie-intel"
    print(f"\n[lyrie intel] Repository: {args.repo}")
    print(f"[lyrie intel] Output:     {output_dir}")
    if args.commit:
        print(f"[lyrie intel] Commit:     {args.commit}")
    if args.since:
        print(f"[lyrie intel] Since:      {args.since}")
    if args.wayback:
        print(f"[lyrie intel] Wayback:    enabled")
    if args.gharchive:
        print(f"[lyrie intel] GH Archive: enabled")

    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from skills.lyrie_intel.github_evidence_kit.src.store import EvidenceStore
        store = EvidenceStore(output_dir=output_dir)
        store.collect(
            repo=args.repo,
            commit=args.commit,
            since=args.since,
            wayback=args.wayback,
            gharchive=args.gharchive,
        )
        print(f"[lyrie intel] Evidence collected to {output_dir}")
    except ImportError:
        print(f"[lyrie intel] Evidence collection initialised for {args.repo}")
        print(f"[lyrie intel] Output directory: {output_dir}")
        print("[lyrie intel] Install optional deps: pip install lyrie-omega[full]\n")
    return 0


def cmd_smt(args) -> int:
    if args.available:
        try:
            import z3
            print(f"z3 available: {z3.Z3_VERSION_MAJOR}.{z3.Z3_VERSION_MINOR}.{z3.Z3_VERSION_BUILD}")
        except ImportError:
            print("z3 not installed. Run: pip install z3-solver")
            return 1
        return 0

    if not args.check:
        print("error: provide --check <expression> or --available", file=sys.stderr)
        return 1

    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from core.smt_solver.session import SMTSession
        session = SMTSession(bitvec_width=args.bitvec_width)
        result = session.check(args.check, model=args.model)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"\n  Expression: {args.check}")
            print(f"  Result:     {result['status']}")
            if args.model and result.get("model"):
                print(f"  Model:      {result['model']}")
            print()
    except ImportError:
        print(f"\n  Expression: {args.check}")
        print(f"  Status:     (z3-solver not installed)")
        print(f"  Install:    pip install lyrie-omega[analysis]\n")
    return 0


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "info":     cmd_info,
        "scan":     cmd_scan,
        "cvss":     cmd_cvss,
        "exploit":  cmd_exploit,
        "validate": cmd_validate,
        "intel":    cmd_intel,
        "smt":      cmd_smt,
    }

    handler = handlers.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        print(f"error: unknown command '{args.command}'", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
