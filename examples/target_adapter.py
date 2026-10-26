"""Copy this file and implement analyse() using your existing local RE agent.

ral init --target-command 'python /absolute/path/to/your_adapter.py'
ral check
This template does not pretend to analyse a binary before you connect it.
"""
import json
import sys


def analyse(binary, prompt, seed):
    # Replace with your agent's real call. Record only tools actually invoked
    # and outputs delivered to the model. Send diagnostic logs to stderr.
    raise NotImplementedError("Connect your agent in analyse(binary, prompt, seed)")


def main():
    request = json.load(sys.stdin)
    if request.get("protocol") != "ral.target.v1":
        raise ValueError("unsupported RAL protocol")
    report, calls = analyse(request["binary"], request["task"]["prompt"], request["seed"])
    json.dump({"protocol": "ral.target.v1", "report": report, "calls": calls}, sys.stdout)


if __name__ == "__main__":
    main()
