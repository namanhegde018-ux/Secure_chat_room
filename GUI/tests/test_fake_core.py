from gui.fake_core import FakeCore


class Sink:
    def __init__(self):
        self.events = []

    def __getattr__(self, name):
        if name.startswith("on_"):
            return lambda event: self.events.append((name, event))
        raise AttributeError(name)


def test_fake_core_exposes_expected_actions_and_events():
    sink = Sink()
    core = FakeCore(sink)
    core.connect()
    core.invite("Alice")
    core.accept({})
    core.send_message("hello")
    core.request_export("report.pdf")
    core.decide_export({"name": "report.pdf"}, True)
    core.end_session()
    names = [name for name, _event in sink.events]
    assert names == ["on_invite_received", "on_session_started", "on_message", "on_export_request", "on_export_decision", "on_session_ended"]
