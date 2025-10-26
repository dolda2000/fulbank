import json, http.cookiejar, binascii, time, datetime, pickle, urllib.error, io
from PIL import Image
from urllib import request, parse
from bs4 import BeautifulSoup as soup
from . import currency, auth, data
soupify = lambda cont: soup(cont, "html.parser")

apicall = {
    "base": "https://app.swedbank.se/api/",
    "headers": [
        ("X-Api-Key", "x7X8h9nePgYEUHs7"),
        ("X-Client", "fdp-internet-bank/227.1.0"),
    ],
}
tdecall = {
    "base": "https://online.swedbank.se/TDE_DAP_Portal_REST_WEB/api/",
    "headers": [
        ("X-Api-Key", "x7X8h9nePgYEUHs7"),
        ("X-Client", "fdp-internet-bank/227.1.0"),
    ],
    "serviceid": "B7dZHQcY78VRVz9l",
}
loginurl = "https://online.swedbank.se/app/ib/logga-in"

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

def base64(data):
    return binascii.b2a_base64(data).decode("ascii").strip().rstrip("=")

def resolve(d, keys, default=fmterror):
    if isinstance(keys, str):
        keys = [keys]
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

def cktyp(d, typ, name, default=None):
    if d is None:
        d = default
    if not isinstance(d, typ):
        raise fmterror("unexpected type for " + name + ": " + repr(d))
    return d

def tget(d, keys, typ, name, default=None):
    return cktyp(resolve(d, keys), typ, name, default)

def linkurl(ln, method):
    if method is not None:
        mth = tget(ln, "method", str, "link method", "")
        if mth != method:
            raise fmterror("unexpected method for link: " + mth)
    uri = tget(ln, "uri", str, "link target")
    if uri[0] != '/':
        raise fmterror("unexpected link url: " + uri)
    return parse.urljoin(tdecall["base"], uri[1:])

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
            self._data = self.sess._jreq(tdecall, "v5/engagement/account/" + self.id)
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
            data = self.sess._jreq(tdecall, "v5/engagement/transactions/" + self.id, query={"transactionsPerPage": pagesz, "page": page})
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
            self._data = self.sess._jreq(tdecall, "v5/engagement/cardaccount/" + self.id)
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
            data = self.sess._jreq(tdecall, "v5/engagement/cardaccount/" + self.id, query={"transactionsPerPage": pagesz, "page": page})
            txlist = resolve(data, ("transactions",))
            if len(txlist) < 1:
                break
            for tx in txlist:
                yield cardtransaction(self, tx)
            page += 1

class session(data.session):
    def __init__(self):
        self.authtime = time.time()
        self.jar = request.HTTPCookieProcessor()
        self.usertoken = None
        self.engagement = None
        self.userid = None
        self._accounts = None

    def _req(self, reqtype, url, data=None, ctype=None, headers={}, method=None, query=None):
        if query is None:
            query = {}
        query = {k: v for (k, v) in query.items() if v is not None}
        url = parse.urljoin(reqtype["base"], url + "?" + parse.urlencode(query))
        if isinstance(data, dict):
            data = json.dumps(data).encode("utf-8")
            if ctype is None:
                ctype = "application/json"
        req = request.Request(url, data=data, method=method)
        for hnam, hval in reqtype.get("headers", []):
            req.add_header(hnam, hval)
        for hnam, hval in headers.items():
            req.add_header(hnam, hval)
        if ctype is not None:
            req.add_header("Content-Type", ctype)
        if "serviceid" in reqtype:
            req.add_header("Authorization", base64((reqtype["serviceid"] + ":" + str(int(self.authtime * 1000))).encode("ascii")))
        if self.usertoken is not None:
            req.add_header("X-User", self.usertoken)
        if self.engagement is not None:
            req.add_header("X-Engagement", self.engagement)
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
            if e.headers.get_content_type() in {"application/json", "application/problem+json"}:
                raise jsonerror.fromerr(e)
        return json.loads(ret.decode("utf-8"))

    def _postlogin(self):
        aprof = self._jreq(tdecall, "v5/profile/activeprofile")

        prof = self._jreq(tdecall, "v5/profile/")
        if len(prof["banks"]) != 1:
            raise fmterror("do not know the meaning of multiple banks")
        profc = self._jreq(tdecall,
                           linkurl(resolve(prof["banks"][0], ("privateProfile", "links", "next")), "POST"),
                           method="POST")
        self.engagement = tget(profc, ("selectedProfile", "andromedaProfileToken"), str, "engagement token")

        auth = self._jreq(tdecall, "v5/user/authenticationinfo")
        uid = auth.get("identifiedUser", "")
        if uid == "":
            raise fmterror("no identified user even after successful authentication")
        self.userid = uid

    def auth_token(self, user, conv=None):
        if conv is None:
            conv = auth.default()
        try:
            data = self._jreq(apicall, "cross-channel/customer-security/authentication/v1/securitytoken/authentication", data={
                "userId": user,
                "corporateToken": False,
                "generateEasyLogin": False,
                "mockedAuthentication": False,
            })
        except jsonerror as e:
            if e.code == 400:
                for fld in cktyp(resolve(e.data, ("errorMessages", "fields"), None), list, "field messages", []):
                    if resolve(fld, ("field",), None) == "userId":
                        raise autherror(fld["message"])
            raise
        if data.get("type") == "PHOTOTAN":
            aid = tget(data, "authenticationId", str, "authentication id")
            idata = tget(data, "imageData", str, "challenge image-data")
            img = Image.open(io.BytesIO(self._req(apicall, "cross-channel/customer-security/authentication/v1/challenge-image", query={"data": idata, "size": "M"})))
            conv.image(img)
            response = conv.prompt("Token response: ", True)
            try:
                data = self._jreq(apicall, "cross-channel/customer-security/authentication/v1/securitytoken/authentication/" + aid + "/response", data={
                    "verificationCode": response,
                }, method="PUT")
            except jsonerror as e:
                if e.code in {400, 401}:
                    for msg in tget(e.data, ("errorMessages", "general"), list, "error messages", []):
                        if "message" in msg:
                            raise autherror(tget(msg, "message", str, "error message"))
                raise
            self.usertoken = tget(data, "userToken", str, "user token")
        else:
            raise fmterror("unexpected token challenge: type: " + data.get("type"))
        self._postlogin()

    def auth_bankid(self, user, conv=None):
        if conv is None:
            conv = auth.default()
        try:
            data = self._jreq(apicall, "cross-channel/customer-security/authentication/v1/bankid/authentication", data={
                "userId": user,
                "idMethod": "MOBILE_BANKID",
                "generateEasyLogin": False,
                "mockedAuthencation": False,
                "sameDevice": False,
            })
        except jsonerror as e:
            if e.code == 400:
                for fld in cktyp(resolve(e.data, ("errorMessages", "fields"), None), list, "field messages", []):
                    if resolve(fld, ("field",), None) == "userId":
                        raise autherror(fld["message"])
            raise
        aid = tget(data, "authenticationId", str, "authentication id")
        idata = tget(data, "imageData", str, "challenge image data")
        img = Image.open(io.BytesIO(self._req(apicall, "cross-channel/customer-security/authentication/v1/challenge-image", query={"data": idata, "size": "M"})))
        conv.image(img)
        fst = None
        while True:
            data = self._jreq(apicall, "cross-channel/customer-security/authentication/v1/bankid/authentication/" + aid)
            match tget(data, "status", str, "authentication status"):
                case "SUCCESSFUL":
                    self.usertoken = tget(data, "userToken", str, "user token")
                    self._postlogin()
                    return
                case "IN_PROGRESS":
                    st = tget(data, "bankIdStatus", str, "authenticator status")
                    if st != fst:
                        conv.message("Status: %s" % (st,), auth.conv.msg_info)
                        fst = st
                case st:
                    raise fmterror("unexpected authentication status: " + st)
            time.sleep(1)

    def keepalive(self):
        data = self._jreq(tdecall, "v5/framework/clientsession")
        return data["timeoutInMillis"] / 1000

    @property
    def accounts(self):
        if self._accounts is None:
            txndata = self._jreq(tdecall, "v5/engagement/overview")
            crddata = self._jreq(tdecall, "v5/card/creditcard")
            accounts = []
            for acct in resolve(txndata, ("transactionAccounts",)):
                accounts.append(txnaccount(self, resolve(acct, ("id",)), acct))
            for acct in resolve(crddata, ("cardAccounts",)):
                accounts.append(cardaccount(self, resolve(acct, ("id",)), acct))
            self._accounts = accounts
        return self._accounts

    def logout(self):
        if self.userid is not None:
            self._jreq(tdecall, "v5/identification/logout", method="PUT")
            self.usertoken = None
            self.engagement = None
            self.userid = None

    def close(self):
        self.logout()
        self._req(tdecall, "v5/framework/clientsession", method="DELETE")

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
        self = cls()
        self._req(tdecall, loginurl)
        cookies = {cookie.name for cookie in self.jar.cookiejar}
        if "SWBTC" not in cookies:
            raise fmterror("did not get SWBTC cookie from initial request")
        if "dsid" not in cookies:
            raise fmterror("did not get SWBTC cookie from initial request")
        return self
