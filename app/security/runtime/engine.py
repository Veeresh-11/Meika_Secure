# app/security/runtime/engine.py

class RuntimeEngine:
    def __init__(self, ssot):
        self.ssot = ssot

    def handle(self, action, context):
        return self.ssot.execute(action, context)
