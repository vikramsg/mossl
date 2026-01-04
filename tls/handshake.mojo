"""TLS 1.3 handshake state machine skeleton (Stage 0)."""

struct HandshakeEngine(Movable):
    var state: Int
    var verified: Bool

    fn __init__(out self):
        # 0=Init, 1=ClientHelloSent, 2=ServerFlightReceived, 3=Verified, 4=FinishedSent
        self.state = 0
        self.verified = False

    fn send_client_hello(mut self) -> Bool:
        if self.state != 0:
            return False
        self.state = 1
        return True

    fn receive_server_flight(mut self) -> Bool:
        if self.state != 1:
            return False
        self.state = 2
        return True

    fn verify_certificate(mut self, ok: Bool) -> Bool:
        if self.state != 2:
            return False
        if not ok:
            return False
        self.state = 3
        self.verified = True
        return True

    fn send_finished(mut self) -> Bool:
        if self.state != 3:
            return False
        self.state = 4
        return True

    fn handshake_complete(self) -> Bool:
        return self.state == 4 and self.verified

    fn can_send_application_data(self) -> Bool:
        return self.handshake_complete()
