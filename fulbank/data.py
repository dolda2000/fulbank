import hashlib

def _localname(type):
    mod = type.__module__
    if mod.startswith("fulbank."):
        mod = mod[8:]
    return "%s.%s" % (mod, type.__name__)

class account(object):
    @property
    def number(self): raise NotImplementedError("account.number")
    @property
    def name(self): raise NotImplementedError("account.name")
    def transactions(self): raise NotImplementedError("account.transactions")

    def __repr__(self):
        return "#<%s %s: %r>" % (_localname(type(self)), self.number, self.name)

class txnaccount(account):
    @property
    def balance(self): raise NotImplementedError("txnaccount.balance")
    @property
    def clearing(self): raise NotImplementedError("txnaccount.clearing")
    @property
    def fullnumber(self): raise NotImplementedError("txnaccount.fullnumber")

class cardaccount(account):
    pass

class transaction(object):
    @property
    def value(self): raise NotImplementedError("transaction.value")
    @property
    def message(self): raise NotImplementedError("transaction.message")
    @property
    def date(self): raise NotImplementedError("transaction.date")

    @property
    def hash(self):
        dig = hashlib.sha256()
        dig.update(str(self.date.toordinal()).encode("ascii") + b"\0")
        dig.update(self.message.encode("utf-8") + b"\0")
        dig.update(str(self.value.amount).encode("ascii") + b"\0")
        dig.update(self.value.currency.symbol.encode("ascii") + b"\0")
        return dig.hexdigest()

    def __repr__(self):
        return "#<%s %s: %r>" % (_localname(type(self)), self.value, self.message)
