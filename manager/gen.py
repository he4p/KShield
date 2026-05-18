import os
import tomllib

out = ["# Current Detectors\n\nHere are all the out-of-the-box detectors available in Unified Shield:\n"]
detectors_dir = "detectors"

for f in sorted(os.listdir(detectors_dir)):
    if f.endswith(".toml"):
        with open(os.path.join(detectors_dir, f), "rb") as fd:
            data = tomllib.load(fd)
            out.append(f"- **{data.get('name', f)}**: {data.get('description', '')}")

with open("../docs/current-detectors.md", "w") as fd:
    fd.write("\n".join(out))
