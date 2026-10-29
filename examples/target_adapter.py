"""Copy this file and implement analyse() using your existing local RE agent.

Install Blindsight in the adapter's Python environment, then:
ral check --target-command 'python /absolute/path/to/your_adapter.py'
Set RAL_ADAPTER_LOG=/absolute/path/adapter.log to retain private diagnostics.
This template does not pretend to analyse a binary before you connect it.
"""
from blindsight.adapter import serve

def analyse(binary, prompt, seed):
    # Replace with your agent's real call. Record only tools actually invoked
    # and outputs delivered to the model. Send diagnostic logs to stderr.
    raise NotImplementedError("Connect your agent in analyse(binary, prompt, seed)")


if __name__ == "__main__":
    serve(analyse)
