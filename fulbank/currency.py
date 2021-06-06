class currency(object):
    def __init__(self, symbol):
        self.symbol = symbol

    def sformat(self, amount):
        return "%s %s" % (self.symbol, self.format(amount))

    def __repr__(self):
        return "#<currency %s>" % self.symbol

    @property
    def zero(self):
        return value(0, self)

    _known = {}
    @classmethod
    def define(cls, *args, **kwargs):
        self = cls(*args, **kwargs)
        cls._known[self.symbol] = self
    @classmethod
    def get(cls, symbol):
        return cls._known[symbol]

    def __reduce__(self):
        return _currency_restore, (type(self), self.symbol,)
def _currency_restore(cls, symbol):
    return cls.get(symbol)

class integral(currency):
    def __init__(self, symbol):
        super().__init__(symbol)

    def format(self, amount):
        return "%i" % amount

    def parse(self, text):
        return value(int(text), self)

class decimal(currency):
    def __init__(self, symbol, separator, thseparator, decimals=2):
        super().__init__(symbol)
        self.separator = separator
        self.thseparator = thseparator
        self.decimals = decimals

    def format(self, amount):
        if amount < 0:
            return "-" + self.format(-amount)
        bias = 10 ** self.decimals
        ip = amount // bias
        fp = amount - (ip * bias)
        return "%i.%0*i" % (ip, self.decimals, fp)

    def parse(self, text):
        def parse2(text):
            p = text.find(self.separator)
            bias = 10 ** self.decimals
            if p < 0:
                text = text.replace(self.thseparator)
                if not text.isdigit():
                    raise ValueError(text)
                return int(text) * bias
            else:
                if p != len(text) - 3:
                    raise ValueError(text)
                ip = text[:p].replace(self.thseparator, "")
                fp = text[p + 1:]
                if not (ip.isdigit() and fp.isdigit()):
                    raise ValueError(text)
                ip = int(ip)
                fp = int(fp)
                if fp >= bias:
                    raise ValueError(text)
                return (ip * bias) + fp
        if text[0:1] == "-":
            return value(-parse2(text[1:]), self)
        else:
            return value(parse2(text), self)

decimal.define("SEK", ",", " ")
decimal.define("USD", ".", ",")
integral.define("JPY")

class value(object):
    __slots__ = ["amount", "currency"]
    def __init__(self, amount, currency):
        self.amount = int(amount)
        self.currency = currency

    def __repr__(self):
        return "%s %s" % (self.currency.symbol, self.currency.format(self.amount))

    def __add__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot add %s to %s" % (other.currency.symbol, self.currency.symbol))
        return value(int(self.amount + other.amount), self.currency)
    def __sub__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot subtract %s from %s" % (other.currency.symbol, self.currency.symbol))
        return value(int(self.amount - other.amount), self.currency)
    def __mul__(self, other):
        return value(int(self.amount * other), self.currency)
    def __truediv__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot divide %s with %s" % (self.currency.symbol, other.currency.symbol))
        return self.amount / other.amount
    def __floordiv__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot divide %s with %s" % (self.currency.symbol, other.currency.symbol))
        return self.amount // other.amount
    def __mod__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot divide %s with %s" % (self.currency.symbol, other.currency.symbol))
        return value(int(self.amount % other.amount), self.currency)
    def __divmod__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot divide %s with %s" % (self.currency.symbol, other.currency.symbol))
        return (self.amount // other.amount, value(int(self.amount % other.amount), self.currency))
    def __neg__(self):
        return value(-self.amount, self.currency)

    def __eq__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot compare %s with %s" % (self.currency.symbol, other.currency.symbol))
        return self.amount == other.amount
    def __ne__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot compare %s with %s" % (self.currency.symbol, other.currency.symbol))
        return self.amount != other.amount
    def __lt__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot compare %s with %s" % (self.currency.symbol, other.currency.symbol))
        return self.amount < other.amount
    def __le__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot compare %s with %s" % (self.currency.symbol, other.currency.symbol))
        return self.amount <= other.amount
    def __gt__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot compare %s with %s" % (self.currency.symbol, other.currency.symbol))
        return self.amount > other.amount
    def __ge__(self, other):
        if self.currency != other.currency:
            raise ValueError("cannot compare %s with %s" % (self.currency.symbol, other.currency.symbol))
        return self.amount >= other.amount

    def __hash__(self):
        return hash(self.amount) + hash(self.currency)
