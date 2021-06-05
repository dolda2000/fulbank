import os, pwd, hashlib, pickle

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

class session(object):
    def save(self, filename):
        with open(filename, "wb") as fp:
            pickle.dump(self, fp)

    @staticmethod
    def load(filename):
        with open(filename, "rb") as fp:
            return pickle.load(fp)

def getsessnam(name):
    if name == "fsb":
        from . import fsb
        return fsb.session
    raise ValueError("no such known session type: " + name)

def _sesspath(name):
    return os.path.join(pwd.getpwuid(os.getuid()).pw_dir, ".cache/fulbank", name)

def defaultsess():
    ret = os.getenv("NETBANKSESS")
    if ret:
        return ret
    return "master"

def loadsess(name=None, default=FileNotFoundError):
    if name is None: name = defaultsess()
    path = _sesspath(name)
    if not os.path.exists(path):
        if default is FileNotFoundError:
            raise FileNotFoundError(name)
        return default
    return session.load(path)

def savesess(sess, name=None):
    if name is None: name = defaultsess()
    path = _sesspath(name)
    if sess is not None:
        sessdir = os.path.dirname(path)
        if not os.path.isdir(sessdir):
            os.makedirs(sessdir)
        return sess.save(_sesspath(name))
    else:
        if os.path.exists(path):
            os.unlink(path)

class savedsess(object):
    def __init__(self, name=None):
        if name is None: name = defaultsess()
        self.name = name
        self.sess = None

    def __enter__(self):
        self.sess = loadsess(self.name)
        return self.sess

    def __exit__(self):
        savesess(self.sess, name)
        self.sess = None
