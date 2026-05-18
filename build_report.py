import os

files = [
    ("Introduction & Core Overview", "docs/index.md"),
    ("System Architecture", "docs/architecture.md"),
    ("Security Dashboard & Controller API Reference", "docs/api-reference.md"),
    ("Out-of-the-Box Protection: Preloaded Detectors", "docs/current-detectors.md"),
    ("Extensibility Guide: Writing Custom Rules", "docs/extensibility.md"),
    ("Detector Engine Capabilities & Syntax", "docs/detectors.md"),
    ("Advanced Operations: Signature Antivirus with LSM", "docs/signature-av-lsm.md"),
    ("Future Roadmap & Extension Plan", "docs/extension-plan.md")
]

out = []
out.append("""---
title: "Ataree Workflows: A Comprehensive eBPF-based Linux Runtime Security Framework"
author: "Academic Project Report"
date: "\\\\today"
abstract: |
  As cloud-native environments and microservice architectures continue to dominate the modern digital landscape, the requirement for robust, low-overhead introspection within the Linux kernel has grown exponentially. Standard user-space protections are increasingly evaded by sophisticated kernel-level exploit methodologies and hardware-adjacent vulnerabilities limit the efficacy of generic endpoint security solutions. This report details the theoretical formulation, architectural design, and deployment implementation of **Ataree**, a modernized Linux Runtime Security mechanism. Ataree strategically consolidates the structural documentation robustness of the `ataree` project and the low-level execution power of the `KShield` agent-manager paradigm. The resulting framework provides unparalleled introspection via enhanced Berkeley Packet Filter (eBPF) technologies, leveraging direct hooks into kernel tracepoints, network stacks, and Linux Security Modules (LSM) to deliver real-time telemetry streaming and automated enforcement configurations. The system boasts an extensible TOML-based 0-day detection suite and a deeply optimized, glassmorphic UX backend dashboard deployed over a secure, authenticated REST API.
---

\\newpage
""")

for title, path in files:
    if not os.path.exists(path):
        continue
    with open(path, "r") as f:
        content = f.read()
    
    # Strip existing top-level headers to avoid markdown depth issues
    lines = content.split('\n')
    lines = [l for l in lines if not l.startswith('# ')]
    
    out.append(f"# {title}\n")
    
    # Leave room for illustration
    out.append("""
\\begin{figure}[h]
\\centering
\\vspace{5cm}
\\caption{Illustration mapping the logical boundary of the """ + title + """ implementation.}
\\end{figure}
""")
    
    out.append("\n".join(lines))
    out.append("\n\\clearpage\n")

with open("all_docs.md", "w") as f:
    f.write("\n\n".join(out))

print("[*] all_docs.md built successfully.")

import subprocess
res = subprocess.run([
    "pandoc", "all_docs.md", 
    "-o", "report.tex", 
    "-s", 
    "--toc", 
    "--number-sections", 
    "-V", "documentclass=report", 
    "-V", "geometry:margin=1in", 
    "-V", "fontsize=12pt"
], capture_output=True, text=True)

if res.returncode == 0:
    print("[*] Pandoc successfully generated report.tex")
else:
    print("[-] Pandoc failed!")
    print(res.stderr)
