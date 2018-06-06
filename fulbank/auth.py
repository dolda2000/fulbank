import sys, os, io, termios

class conv(object):
    msg_notice = 0
    msg_info = 1
    msg_debug = 2

    def error(self, msg):
        pass
    def message(self, msg, level=0):
        pass
    def prompt(self, prompt, echo, default=None):
        return default

class termconv(conv):
    def __init__(self, ifp, ofp):
        self.ifp = ifp
        self.ofp = ofp

    def error(self, msg):
        self.ofp.write("%s\n" % (msg,))
        self.ofp.flush()
    def message(self, msg, level=0):
        if level <= self.msg_info:
            self.ofp.write("%s\n" % (msg,))
            self.ofp.flush()
    def prompt(self, prompt, echo, default=None):
        if echo:
            self.ofp.write(prompt)
            self.ofp.flush()
            ret = self.ifp.readline()
            assert ret[-1] == '\n'
            return ret[:-1]
        else:
            attr = termios.tcgetattr(self.ifp.fileno())
            bka = list(attr)
            try:
                attr[3] &= ~termios.ECHO
                termios.tcflush(self.ifp.fileno(), termios.TCIOFLUSH)
                termios.tcsetattr(self.ifp.fileno(), termios.TCSANOW, attr)
                self.ofp.write(prompt)
                self.ofp.flush()
                ret = self.ifp.readline()
                self.ofp.write("\n")
                assert ret[-1] == '\n'
                return ret[:-1]
            finally:
                termios.tcsetattr(self.ifp.fileno(), termios.TCSANOW, bka)

class ctermconv(termconv):
    def __init__(self, fp):
        super().__init__(fp, fp)
        self.cfp = fp

    def close(self):
        self.cfp.close()
    def __enter__(self):
        return self
    def __exit__(self, *excinfo):
        self.close()
        return False

null = conv()
stdioconv = termconv(sys.stdin, sys.stdout)

def ttyconv():
    return ctermconv(io.TextIOWrapper(io.FileIO(os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY), "r+")))

def default():
    return null
