from utils import Variant

@fieldwise_init
struct ValidationInProgress:
    var step: Int


@fieldwise_init
struct ValidationSuccess:
    var value: Int


@fieldwise_init
struct ValidationFailure:
    var message: String


alias ValidationState = Variant[
    ValidationInProgress, ValidationSuccess, ValidationFailure
]


fn parse_port(value: String) -> Variant[Int, Error]:
    """Parses a numeric port string or returns an Error."""
    if len(value) == 0:
        return Variant[Int, Error](Error("empty port"))
    var total = 0
    for i in range(len(value)):
        var c = value[i]
        if c < "0" or c > "9":
            return Variant[Int, Error](Error("non-digit in port"))
        total = total * 10 + (ord(c) - ord("0"))
    return Variant[Int, Error](total)


fn advance_state(var state: ValidationInProgress) -> ValidationState:
    """Consumes the state and returns the next typestate variant."""
    if state.step >= 2:
        return ValidationState(ValidationSuccess(state.step))
    return ValidationState(ValidationInProgress(state.step + 1))


fn main() raises:
    var parsed = parse_port("443")
    if parsed.isa[Int]():
        print("Port:", parsed[Int])
    else:
        print("Error:", parsed[Error])

    var state = ValidationState(ValidationInProgress(0))
    if state.isa[ValidationInProgress]():
        state = advance_state(state.unsafe_take[ValidationInProgress]()^)
    if state.isa[ValidationSuccess]():
        print("Validated:", state[ValidationSuccess].value)
