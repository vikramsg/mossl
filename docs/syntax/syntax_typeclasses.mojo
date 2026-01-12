# ===----------------------------------------------------------------------=== #
# 1. Traits (The "Typeclass" Equivalent)
# ===----------------------------------------------------------------------=== #

# A Trait defines a "contract" or "typeclass". 
# Static Dispatch: When you use a trait bound [T: SomeTrait], the compiler 
# generates a unique version of the function for each type T at compile-time.
# There is NO runtime lookup (vtable) overhead.
trait Summarizable:
    fn summarize(self) -> String: ...

# ===----------------------------------------------------------------------=== #
# 2. "Frozen" Dataclass Pattern
# ===----------------------------------------------------------------------=== #

# @fieldwise_init: Synthesizes a constructor __init__(id, username)
@fieldwise_init
struct UserRecord(Summarizable, Copyable, Movable, ImplicitlyCopyable):
    var id: Int
    var username: String

    # Explicitly implementation of lifecycle methods for the trait requirements.
    fn __moveinit__(out self, deinit existing: Self):
        self.id = existing.id
        self.username = existing.username^

    fn __copyinit__(out self, other: Self):
        self.id = other.id
        self.username = other.username

    # Implementation of the Summarizable "typeclass"
    fn summarize(self) -> String:
        return "User[" + String(self.id) + "]: " + self.username

# ===----------------------------------------------------------------------=== #
# 3. Generic Wrapper and Specialized Dispatch
# ===----------------------------------------------------------------------=== #

@fieldwise_init
struct Wrapper[T: Copyable & Movable & ImplicitlyCopyable](Copyable, Movable, ImplicitlyCopyable):
    var data: T

    fn __moveinit__(out self, deinit existing: Self):
        self.data = existing.data^

    fn __copyinit__(out self, other: Self):
        self.data = other.data

    # Since Mojo doesn't yet support 'self: Wrapper[U]' specialization inside 
    # the struct for non-conforming parameters, we use a standalone function 
    # to demonstrate Static Dispatch on the generic type.
    
# ===----------------------------------------------------------------------=== #
# 4. Static Dispatch in Action
# ===----------------------------------------------------------------------=== #

# STANDALONE GENERIC FUNCTION (The most powerful way to use Traits)
# This handles the "summarize if T is Summarizable" logic.
fn summarize_thing[T: Summarizable](thing: T) -> String:
    return thing.summarize()

# We can also specialize for the Wrapper!
# This function only exists for Wrappers whose content is Summarizable.
fn summarize_wrapper[T: Summarizable & Copyable & Movable & ImplicitlyCopyable](w: Wrapper[T]) -> String:
    return "Wrapped(" + w.data.summarize() + ")"

fn main() raises:
    print("--- Data Structures & Typeclasses (Traits) ---")

    var user = UserRecord(42, "MojoMaster")
    
    print("Direct call: ", user.summarize())

    # Static Dispatch: The compiler calls UserRecord.summarize directly.
    print("Static Dispatch (Generic Fn): ", summarize_thing(user))

    # Composition: Static Dispatch on the specialized Wrapper.
    var wrapped_user = Wrapper(user)
    print("Composition (Specialized Fn): ", summarize_wrapper(wrapped_user))