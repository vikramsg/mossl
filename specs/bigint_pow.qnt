module bigint_pow {
    type BigInt = List[int]

    // Simplified model for Quint: we use the built-in integers
    // and verify that the modular exponentiation logic holds.
    
    pure def mod_pow(base: int, exp: int, mod: int): int = {
        // This is just a specification of what we want
        // Quint built-in pow doesn't support 3 arguments
        // So we just model the property
        if (exp == 0) 1
        else if (exp % 2 == 0) {
            val half = mod_pow(base, exp / 2, mod)
            (half * half) % mod
        } else {
            (base * mod_pow(base, exp - 1, mod)) % mod
        }
    }

    var base: int
    var exp: int
    var mod: int
    var result: int

    action init = {
        all {
            base' = 3,
            exp' = 5,
            mod' = 13,
            result' = 0,
        }
    }

    action step = {
        all {
            result == 0,
            result' = mod_pow(base, exp, mod),
            base' = base,
            exp' = exp,
            mod' = mod,
        }
    }

    val correct_result = (result == 9 or result == 0)
}
