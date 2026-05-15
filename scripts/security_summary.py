import os
import json

summary = {"high": 0, "medium": 0, "low": 0}

# Example: ZAP report parsing
if os.path.exists("report_json.json"):
    try:
        with open("report_json.json") as f:
            zap = json.load(f)
            alerts = zap.get("site", [{}])[0].get("alerts", [])
            for a in alerts:
                risk = a.get("riskdesc", "").lower()
                if "high" in risk:
                    summary["high"] += 1
                elif "medium" in risk:
                    summary["medium"] += 1
                else:
                    summary["low"] += 1
    except:
        pass

score = summary["high"] * 5 + summary["medium"] * 2 + summary["low"]

if score > 20:
    status = "CRITICAL"
elif score > 10:
    status = "HIGH"
elif score > 5:
    status = "MEDIUM"
else:
    status = "LOW"

with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
    f.write("## 🔐 Security Summary\n")
    f.write(f"- High: {summary['high']}\n")
    f.write(f"- Medium: {summary['medium']}\n")
    f.write(f"- Low: {summary['low']}\n")
    f.write(f"- Overall Risk: **{status}**\n")

print(summary)

# Optional hard fail
if status == "CRITICAL":
    exit(1)