import json
import os

def render_html():
    with open('report.json', 'r') as f:
        data = json.load(f)

    # Prepare data for Chart.js
    perf = data.get('perf_samples', [])
    labels = [round(s['ts_s'] - perf[0]['ts_s'], 1) for s in perf] if perf else []
    
    sys_cpu = [s['system_cpu_percent'] for s in perf]
    mgr_cpu = [s.get('manager_cpu_percent', 0) for s in perf]
    agt_cpu = [s.get('agent_cpu_percent', 0) for s in perf]
    
    mgr_mem = [s.get('manager_rss_kb', 0) / 1024 for s in perf]
    agt_mem = [s.get('agent_rss_kb', 0) / 1024 for s in perf]

    tests = data.get('tests', [])
    tests_html = ""
    for t in tests:
        status_color = "#10b981" if t["ok"] else "#ef4444"
        status_text = "PASS" if t["ok"] else "FAIL"
        
        tests_html += f"""
        <tr class="border-b border-gray-700 bg-gray-800">
            <td class="py-3 px-4 font-medium">{t['id']}</td>
            <td class="py-3 px-4">{t['label']}</td>
            <td class="py-3 px-4 text-center">
                <span class="px-2 py-1 rounded text-xs font-bold text-white bg-[{status_color}]">{status_text}</span>
            </td>
            <td class="py-3 px-4">{t['classification']}</td>
            <td class="py-3 px-4">{'<br>'.join(t.get('expected_detectors', []))}</td>
            <td class="py-3 px-4">{'<br>'.join(t.get('observed_detectors', []))}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KShield Benchmark Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; }}
        .card {{ background: #1e293b; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); padding: 24px; }}
        .metric-value {{ font-size: 2rem; font-weight: 700; background: -webkit-linear-gradient(45deg, #3b82f6, #06b6d4); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .metric-label {{ font-size: 0.875rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; margin-bottom: 8px; }}
    </style>
</head>
<body class="p-8">
    <div class="max-w-7xl mx-auto">
        <header class="mb-10 flex justify-between items-center pb-6 border-b border-gray-800">
            <div>
                <h1 class="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-emerald-400">KShield Benchmark Report</h1>
                <p class="text-gray-400 mt-2">Executed on {data.get('ts')} | Manager: {data.get('manager_url')}</p>
            </div>
            <div class="text-right">
                <span class="inline-block px-4 py-2 rounded-full bg-blue-900 text-blue-200 font-semibold text-sm border border-blue-700">
                    Mode: {str(data.get('mode')).upper()}
                </span>
            </div>
        </header>

        <!-- Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
            <div class="card">
                <div class="metric-label">Accuracy</div>
                <div class="metric-value">{data['confusion']['Accuracy']*100:.1f}%</div>
                <div class="text-sm text-emerald-400 mt-2">TP: {data['confusion']['TP']} | TN: {data['confusion']['TN']}</div>
            </div>
            <div class="card">
                <div class="metric-label">Avg Latency</div>
                <div class="metric-value">{data.get('detection_latency_ms_avg', 0):.1f} ms</div>
                <div class="text-sm text-gray-400 mt-2">Time to detection</div>
            </div>
            <div class="card">
                <div class="metric-label">Throughput</div>
                <div class="metric-value">{data.get('throughput_events_per_sec', 0):.0f}/s</div>
                <div class="text-sm text-gray-400 mt-2">Events processed</div>
            </div>
            <div class="card">
                <div class="metric-label">CPU Overhead</div>
                <div class="metric-value">{data.get('cpu_overhead_percent', 0):.2f}%</div>
                <div class="text-sm text-gray-400 mt-2">Sys Avg: {data['avg_system_cpu_percent']:.1f}%</div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-10">
            <!-- CPU Chart -->
            <div class="card h-96">
                <h3 class="text-lg font-semibold mb-4 text-gray-200">CPU Usage Over Time (%)</h3>
                <div class="relative h-full pb-8">
                    <canvas id="cpuChart"></canvas>
                </div>
            </div>
            <!-- Mem Chart -->
            <div class="card h-96">
                <h3 class="text-lg font-semibold mb-4 text-gray-200">Memory Usage (RSS MB)</h3>
                <div class="relative h-full pb-8">
                    <canvas id="memChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Details Table -->
        <div class="card overflow-hidden">
            <h3 class="text-lg font-semibold mb-6 text-gray-200">Detection Matrix & Test Results</h3>
            <div class="overflow-x-auto rounded-lg">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-gray-900 border-b-2 border-gray-700 text-gray-300">
                            <th class="py-4 px-4 font-semibold text-sm">Test ID</th>
                            <th class="py-4 px-4 font-semibold text-sm">Description</th>
                            <th class="py-4 px-4 font-semibold text-sm text-center">Status</th>
                            <th class="py-4 px-4 font-semibold text-sm">Class</th>
                            <th class="py-4 px-4 font-semibold text-sm">Expected</th>
                            <th class="py-4 px-4 font-semibold text-sm">Observed</th>
                        </tr>
                    </thead>
                    <tbody class="text-sm">
                        {tests_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        const labels = {json.dumps(labels)};
        
        // CPU Chart
        new Chart(document.getElementById('cpuChart'), {{
            type: 'line',
            data: {{
                labels: labels,
                datasets: [
                    {{ label: 'System CPU', data: {json.dumps(sys_cpu)}, borderColor: '#64748b', backgroundColor: 'rgba(100,116,139,0.1)', fill: true, tension: 0.4 }},
                    {{ label: 'Manager CPU', data: {json.dumps(mgr_cpu)}, borderColor: '#3b82f6', tension: 0.4 }},
                    {{ label: 'Agent CPU', data: {json.dumps(agt_cpu)}, borderColor: '#10b981', tension: 0.4 }}
                ]
            }},
            options: {{ responsive: true, maintainAspectRatio: false, color: '#94a3b8',
                scales: {{ 
                    x: {{ grid: {{ color: '#334155' }}, title: {{ display: true, text: 'Time (s)', color: '#94a3b8' }} }},
                    y: {{ grid: {{ color: '#334155' }}, beginAtZero: true }}
                }}
            }}
        }});

        // Mem Chart
        new Chart(document.getElementById('memChart'), {{
            type: 'line',
            data: {{
                labels: labels,
                datasets: [
                    {{ label: 'Manager RSS (MB)', data: {json.dumps(mgr_mem)}, borderColor: '#8b5cf6', backgroundColor: 'rgba(139,92,246,0.2)', fill: true, tension: 0.4 }},
                    {{ label: 'Agent RSS (MB)', data: {json.dumps(agt_mem)}, borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,0.2)', fill: true, tension: 0.4 }}
                ]
            }},
            options: {{ responsive: true, maintainAspectRatio: false, color: '#94a3b8',
                scales: {{ 
                    x: {{ grid: {{ color: '#334155' }} }},
                    y: {{ grid: {{ color: '#334155' }}, beginAtZero: true }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

    with open('benchmark_report.html', 'w') as f:
        f.write(html)
    print("Report generated at benchmark_report.html")

if __name__ == '__main__':
    render_html()
