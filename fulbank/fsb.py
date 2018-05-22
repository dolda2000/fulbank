import json, http.cookiejar, binascii, time
from urllib import request, parse
from bs4 import BeautifulSoup as soup
soupify = lambda cont: soup(cont, "html.parser")

apibase = "https://online.swedbank.se/TDE_DAP_Portal_REST_WEB/api/"
loginurl = "https://online.swedbank.se/app/privat/login"
serviceid = "B7dZHQcY78VRVz9l"

class fmterror(Exception):
    pass

class autherror(Exception):
    pass

def resolve(d, keys, default=fmterror):
    def err():
        if default is fmterror:
            raise fmterror()
        return default
    def rec(d, keys):
        if len(keys) == 0:
            return d
        if isinstance(d, dict):
            if keys[0] not in d:
                return err()
            return rec(d[keys[0]], keys[1:])
        else:
            return err()
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
            if resp.code != 200:
                raise fmterror("Unexpected HTTP status code: " + str(resp.code))
            self.jar.https_response(req, resp)
            return resp.read()

    def _jreq(self, *args, **kwargs):
        headers = kwargs.pop("headers", {})
        headers["Accept"] = "application/json"
        ret = self._req(*args, headers=headers, **kwargs)
        return json.loads(ret.decode("utf-8"))

    def auth_bankid(self, user):
        data = self._jreq("v5/identification/bankid/mobile", data = {
            "userId": user,
            "useEasyLogin": False,
            "generateEasyLoginId": False})
        if data.get("status") != "USER_SIGN":
            raise fmterror("unexpected bankid status: " + str(data.get("status")))
        vfy = linkurl(resolve(data, ("links", "next", "uri")))
        while True:
            time.sleep(3)
            vdat = self._jreq(vfy)
            st = vdat.get("status")
            if st == "USER_SIGN":
                continue
            elif st == "COMPLETE":
                auth = self._jreq("v5/user/authenticationinfo")
                uid = auth.get("identifiedUser", "")
                if uid == "":
                    raise fmterror("no identified user even after successful authentication")
                self.userid = uid
                return
            elif st == "CANCELLED":
                raise autherror("authentication cancelled")
            elif st == "CLIENT_NOT_STARTED":
                raise autherror("authentication client not started")
            else:
                raise fmterror("unexpected bankid status: " + str(st))

    def logout(self):
        if self.userid is not None:
            self._jreq("v5/identification/logout", method="PUT")
            self.userid = None

    def close(self):
        self.logout()
        self._req("v5/framework/clientsession", method="DELETE")

    def __enter__(self):
        return self

    def __exit__(self, *excinfo):
        self.close()
        return False

    @classmethod
    def create(cls):
        return cls(getdsid())
