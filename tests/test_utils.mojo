fn require(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)
