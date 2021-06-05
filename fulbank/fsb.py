import json, http.cookiejar, binascii, time, datetime, pickle, urllib.error, io
from PIL import Image
from urllib import request, parse
from bs4 import BeautifulSoup as soup
from . import currency, auth, data
soupify = lambda cont: soup(cont, "html.parser")

apibase = "https://online.swedbank.se/TDE_DAP_Portal_REST_WEB/api/"
loginurl = "https://online.swedbank.se/app/privat/login"
serviceid = "B7dZHQcY78VRVz9l"

class fmterror(Exception):
    pass

class autherror(auth.autherror):
    pass

class jsonerror(Exception):
    def __init__(self, code, data, headers):
        self.code = code
        self.data = data
        self.headers = headers

    @classmethod
    def fromerr(cls, err):
        cs = err.headers.get_content_charset()
        if cs is None:
            cs = "utf-8"
        data = json.loads(err.read().decode(cs))
        return cls(err.code, data, err.headers)

def resolve(d, keys, default=fmterror):
    def err(key):
        if default is fmterror:
            raise fmterror(key)
        return default
    def rec(d, keys):
        if len(keys) == 0:
            return d
        if isinstance(d, dict):
            if keys[0] not in d:
                return err(keys[0])
            return rec(d[keys[0]], keys[1:])
        elif isinstance(d, list):
            if not 0 <= keys[0] < len(d):
                return err(keys[0])
            return rec(d[keys[0]], keys[1:])
        else:
            return err(keys[0])
    return rec(d, keys)

def linkurl(ln):
    if ln[0] != '/':
        raise fmterror("unexpected link url: " + ln)
    return parse.urljoin(apibase, ln[1:])

def getdsid():
    with request.urlopen(loginurl) as resp:
        if resp.code != 200:
            raise fmterror("Unexpected HTTP status code: " + str(resp.code))
        doc = soupify(resp.read())
    dsel = doc.find("div", id="cust-sess-id")
    if not dsel or not dsel.has_attr("value"):
        raise fmterror("DSID DIV not on login page")
    return dsel["value"]

def base64(data):
    return binascii.b2a_base64(data).decode("ascii").strip().rstrip("=")

class transaction(data.transaction):
    def __init__(self, account, data):
        self.account = account
        self._data = data

    _datefmt = "%Y-%m-%d"

    @property
    def value(self): return currency.currency.get(resolve(self._data, ("currency",))).parse(resolve(self._data, ("amount",)))
    @property
    def message(self): return resolve(self._data, ("description",))
    @property
    def date(self):
        p = time.strptime(resolve(self._data, ("accountingDate",)), self._datefmt)
        return datetime.date(p.tm_year, p.tm_mon, p.tm_mday)

class txnaccount(data.txnaccount):
    def __init__(self, sess, id, idata):
        self.sess = sess
        self.id = id
        self._data = None
        self._idata = idata

    @property
    def data(self):
        if self._data is None:
            self._data = self.sess._jreq("v5/engagement/account/" + self.id)
        return self._data

    @property
    def number(self): return resolve(self.data, ("accountNumber",))
    @property
    def clearing(self): return resolve(self.data, ("clearingNumber",))
    @property
    def fullnumber(self): return resolve(self.data, ("fullyFormattedNumber",))
    @property
    def balance(self): return currency.currency.get(resolve(self.data, ("balance", "currencyCode"))).parse(resolve(self.data, ("balance", "amount")))
    @property
    def name(self): return resolve(self._idata, ("name",))

    def transactions(self):
        pagesz = 50
        page = 1
        while True:
            data = self.sess._jreq("v5/engagement/transactions/" + self.id, transactionsPerPage=pagesz, page=page)
            txlist = resolve(data, ("transactions",))
            if len(txlist) < 1:
                break
            for tx in txlist:
                yield transaction(self, tx)
            page += 1

class cardtransaction(data.transaction):
    def __init__(self, account, data):
        self.account = account
        self._data = data

    _datefmt = "%Y-%m-%d"

    @property
    def value(self):
        am = resolve(self._data, ("localAmount",))
        return currency.currency.get(resolve(am, ("currencyCode",))).parse(resolve(am, ("amount",)))
    @property
    def message(self): return resolve(self._data, ("description",))
    @property
    def date(self):
        p = time.strptime(resolve(self._data, ("date",)), self._datefmt)
        return datetime.date(p.tm_year, p.tm_mon, p.tm_mday)

class cardaccount(data.cardaccount):
    def __init__(self, sess, id, idata):
        self.sess = sess
        self.id = id
        self._data = None
        self._idata = idata

    @property
    def data(self):
        if self._data is None:
            self._data = self.sess._jreq("v5/engagement/cardaccount/" + self.id)
        return self._data

    @property
    def number(self): return resolve(self.data, ("cardAccount", "cardNumber"))
    @property
    def balance(self):
        cc = resolve(self.data, ("transactions", 0, "localAmount", "currencyCode"))
        return currency.currency.get(cc).parse(resolve(self.data, ("cardAccount", "currentBalance")))
    @property
    def name(self): return resolve(self._idata, ("name",))

    def transactions(self):
        pagesz = 50
        page = 1
        while True:
            data = self.sess._jreq("v5/engagement/cardaccount/" + self.id, transactionsPerPage=pagesz, page=page)
            txlist = resolve(data, ("transactions",))
            if len(txlist) < 1:
                break
            for tx in txlist:
                yield cardtransaction(self, tx)
            page += 1

class session(object):
    def __init__(self, dsid):
        self.dsid = dsid
        self.auth = base64((serviceid + ":" + str(int(time.time() * 1000))).encode("ascii"))
        self.jar = request.HTTPCookieProcessor()
        self.jar.cookiejar.set_cookie(http.cookiejar.Cookie(
            version=0, name="dsid", value=dsid, path="/", path_specified=True,
            domain=".online.swedbank.se", domain_specified=True, domain_initial_dot=True,
            port=None, port_specified=False, secure=False, expires=None,
            discard=True, comment=None, comment_url=None,
            rest={}, rfc2109=False))
        self.userid = None
        self._accounts = None

    def _req(self, url, data=None, ctype=None, headers={}, method=None, **kws):
        if "dsid" not in kws:
            kws["dsid"] = self.dsid
        kws = {k: v for (k, v) in kws.items() if v is not None}
        url = parse.urljoin(apibase, url + "?" + parse.urlencode(kws))
        if isinstance(data, dict):
            data = json.dumps(data).encode("utf-8")
            ctype = "application/json;charset=UTF-8"
        req = request.Request(url, data=data, method=method)
        for hnam, hval in headers.items():
            req.add_header(hnam, hval)
        if ctype is not None:
            req.add_header("Content-Type", ctype)
        req.add_header("Authorization", self.auth)
        self.jar.https_request(req)
        with request.urlopen(req) as resp:
            if resp.code != 200 and resp.code != 201:
                raise fmterror("Unexpected HTTP status code: " + str(resp.code))
            self.jar.https_response(req, resp)
            return resp.read()

    def _jreq(self, *args, **kwargs):
        headers = kwargs.pop("headers", {})
        headers["Accept"] = "application/json"
        try:
            ret = self._req(*args, headers=headers, **kwargs)
        except urllib.error.HTTPError as e:
            if e.headers.get_content_type() == "application/json":
                raise jsonerror.fromerr(e)
        return json.loads(ret.decode("utf-8"))

    def _postlogin(self):
        auth = self._jreq("v5/user/authenticationinfo")
        uid = auth.get("identifiedUser", "")
        if uid == "":
            raise fmterror("no identified user even after successful authentication")
        self.userid = uid
        prof = self._jreq("v5/profile/")
        if len(prof["banks"]) != 1:
            raise fmterror("do not know the meaning of multiple banks")
        rolesw = linkurl(resolve(prof["banks"][0], ("privateProfile", "links", "next", "uri")))
        self._jreq(rolesw, method="POST")

    def auth_token(self, user, conv=None):
        if conv is None:
            conv = auth.default()
        try:
            data = self._jreq("v5/identification/securitytoken/challenge", data = {
                "userId": user,
                "useEasyLogin": "false",
                "generateEasyLoginId": "false"})
        except jsonerror as e:
            if e.code == 400:
                flds = resolve(e.data, ("errorMessages", "fields"), False)
                if isinstance(flds, list):
                    for fld in flds:
                        if resolve(fld, ("field",), None) == "userId":
                            raise autherror(fld["message"])
            raise
        if data.get("useOneTimePassword"):
            raise fmterror("unexpectedly found useOneTimePassword")
        if data.get("challenge") != "":
            raise fmterror("unexpected challenge: " + str(data.get("challenge")))
        if not isinstance(data.get("imageChallenge"), dict) or resolve(data, ("imageChallenge", "method")) != "GET":
            raise fmterror("invalid image challenge: " + str(data.get("imageChallenge")))
        iurl = linkurl(resolve(data, ("imageChallenge", "uri")))
        vfy = linkurl(resolve(data, ("links", "next", "uri")))
        img = Image.open(io.BytesIO(self._req(iurl)))
        conv.image(img)
        response = conv.prompt("Token response: ", True)
        try:
            data = self._jreq(vfy, data={"response": response})
        except jsonerror as e:
            msgs = resolve(e.data, ("errorMessages", "general"), False)
            if isinstance(msgs, list):
                for msg in msgs:
                    if msg.get("message"):
                        raise autherror(msg.get("message"))
            raise
        if not data.get("authenticationRole", ""):
            raise fmterror("authentication appears to have succeded, but there is no authenticationRole: " + str(data))
        self._postlogin()

    def auth_bankid(self, user, conv=None):
        if conv is None:
            conv = auth.default()
        try:
            data = self._jreq("v5/identification/bankid/mobile", data = {
                "userId": user,
                "useEasyLogin": False,
                "generateEasyLoginId": False})
        except jsonerror as e:
            if e.code == 400:
                flds = resolve(e.data, ("errorMessages", "fields"), False)
                if isinstance(flds, list):
                    for fld in flds:
                        if resolve(fld, ("field",), None) == "userId":
                            raise autherror(fld["message"])
            raise
        st = data.get("status")
        vfy = linkurl(resolve(data, ("links", "next", "uri")))
        fst = None
        while True:
            if st in {"USER_SIGN", "CLIENT_NOT_STARTED"}:
                if st != fst:
                    conv.message("Status: %s" % (st,), auth.conv.msg_info)
                    fst = st
            elif st == "COMPLETE":
                self._postlogin()
                return
            elif st == "CANCELLED":
                raise autherror("authentication cancelled")
            elif st == "OUTSTANDING_TRANSACTION":
                raise autherror("another bankid transaction already in progress")
            else:
                raise fmterror("unexpected bankid status: " + str(st))
            time.sleep(3)
            vdat = self._jreq(vfy)
            st = vdat.get("status")

    def keepalive(self):
        data = self._jreq("v5/framework/clientsession")
        return data["timeoutInMillis"] / 1000

    @property
    def accounts(self):
        if self._accounts is None:
            txndata = self._jreq("v5/engagement/overview")
            crddata = self._jreq("v5/card/creditcard")
            accounts = []
            for acct in resolve(txndata, ("transactionAccounts",)):
                accounts.append(txnaccount(self, resolve(acct, ("id",)), acct))
            for acct in resolve(crddata, ("cardAccounts",)):
                accounts.append(cardaccount(self, resolve(acct, ("id",)), acct))
            self._accounts = accounts
        return self._accounts

    def logout(self):
        if self.userid is not None:
            self._jreq("v5/identification/logout", method="PUT")
            self.userid = None

    def close(self):
        self.logout()
        self._req("v5/framework/clientsession", method="DELETE")

    def __getstate__(self):
        state = dict(self.__dict__)
        state["jar"] = list(state["jar"].cookiejar)
        return state

    def __setstate__(self, state):
        jar = request.HTTPCookieProcessor()
        for cookie in state["jar"]:
            jar.cookiejar.set_cookie(cookie)
        state["jar"] = jar
        self.__dict__.update(state)

    def __enter__(self):
        return self

    def __exit__(self, *excinfo):
        self.close()
        return False

    def __repr__(self):
        if self.userid is not None:
            return "#<fsb.session %s>" % self.userid
        return "#<fsb.session>"

    @classmethod
    def create(cls):
        return cls(getdsid())

    def save(self, filename):
        with open(filename, "wb") as fp:
            pickle.dump(self, fp)

    @classmethod
    def load(cls, filename):
        with open(filename, "rb") as fp:
            return pickle.load(fp)
