@fieldwise_init
struct State(Stringable, EqualityComparable, ImplicitlyCopyable):
    var _value: Int

    alias INIT = 0
    alias SYN_SENT = 1
    alias SYN_RCVD = 2
    alias ESTABLISHED = 3



    fn __eq__(self, other: State) -> Bool:
        return self._value == other._value

    fn __ne__(self, other: State) -> Bool:
        return self._value != other._value

    fn __str__(self) -> String:
        if self._value == State.INIT: return "INIT"
        if self._value == State.SYN_SENT: return "SYN_SENT"
        if self._value == State.SYN_RCVD: return "SYN_RCVD"
        if self._value == State.ESTABLISHED: return "ESTABLISHED"
        return "UNKNOWN"

struct TCPModel(ImplicitlyCopyable):
    var client_state: State
    var server_state: State

    fn __init__(out self):
        self.client_state = State(State.INIT)
        self.server_state = State(State.INIT)



    fn send_syn(mut self) -> Bool:
        if self.client_state == State(State.INIT):
            self.client_state = State(State.SYN_SENT)
            return True
        return False

    fn receive_syn(mut self) -> Bool:
        if self.server_state == State(State.INIT) and self.client_state == State(State.SYN_SENT):
            self.server_state = State(State.SYN_RCVD)
            return True
        return False

    fn receive_syn_ack(mut self) -> Bool:
        if self.client_state == State(State.SYN_SENT):
            self.client_state = State(State.ESTABLISHED)
            return True
        return False

    fn step(mut self) -> Bool:
        # Try actions in an order that allows progress
        if self.send_syn():
            print("Action: SendSyn")
            return True
        if self.receive_syn():
            print("Action: ReceiveSyn")
            return True
        if self.receive_syn_ack():
            print("Action: ReceiveSynAck")
            return True
        return False
