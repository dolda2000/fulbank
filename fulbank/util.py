import operator

def pfxmatch(pfx, item):
    return str(item)[:len(pfx)] == pfx

def ipfxmatch(pfx, item):
    return str(item).upper()[:len(pfx)] == pfx.upper()

class ambiguous(LookupError):
    def __init__(self, a, b):
        super().__init__("ambigous match: %s and %s" % (a, b))
        self.a = a
        self.b = b

def find(seq, *, item=None, test=None, match=None, key=None, default=LookupError):
    if key is None:
        key = lambda o: o
    if match is None and item is not None:
        match = lambda o: test(item, o)
    if test is None:
        test = operator.eq
    found = None
    for thing in seq:
        if match(key(thing)):
            if found is None:
                found = thing
            else:
                if default is LookupError:
                    raise ambiguous(key(found), key(thing))
                else:
                    return default
    if found is not None:
        return found
    if default is LookupError:
        raise LookupError()
    else:
        return default
