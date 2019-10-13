import rp from "request-promise";
import http, { Server } from "http";
import { AuthOptions, CookieJar, Cookie } from "request";
import { Url } from "url";
import tough from "tough-cookie";
import CryptoJS from "crypto-js";
import YealinkKey from "./YealinkKey";
import cheerio from 'cheerio';
import { EventEmitter } from "events";
const RSAKey = require("../js/rsa/rsa");


type YealinkProperty = 'status'
  | 'status-wifi' | 'account-register' | 'account-basic' | 'account-codec' | 'account-adv'
  | 'network' | 'network-pcport' | 'network-nat' | 'network-adv' | 'network-wifi' | 'network-diagnosis'
  | 'dsskey'
  | 'features-forward' | 'features-general' | 'features-audio' | 'features-intercom' | 'features-transfer' | 'features-callpickup' | 'features-remotecontrl' | 'features-phonelock' | 'features-acd' | 'features-sms' | 'features-actionurl' | 'features-bluetooth' | 'features-powerled' | 'features-notifypop'
  | 'settings-preference' | 'settings-datetime' | 'settings-calldisplay' | 'settings-upgrade' | 'settings-autop' | 'settings-config' | 'settings-dialplan'
  | 'settings-voice' | 'settings-ring' | 'settings-tones' | 'settings-softkey' | 'settings-tr069' | 'settings-voicemonitoring' | 'settings-sip' | 'settings-powersaving'
  | 'contactsbasic' | 'contacts-remote' | 'contacts-callinfo' | 'contacts-google' | 'contacts-LDAP' | 'contacts-multicastIP' | 'contacts-favorite'
  | 'security' | 'trusted-cert' | 'server-cert';

type YealinkEvents = "AUSetupCompleted" | "AULogOn" | "AULogOff" | "AURegisterFailed" | "AUOffHook" | "AUOnHook" | "AUIncomingCall" | "AUCallOut" | "AUEstablished" | "AUTerminated" | "AUOpenDnd" | "AUCloseDnd" | "AUOpenAlwaysForward" | "AUCloseAlwaysForward" | "AUOpenBusyForward" | "AUCloseBusyForward"
   | "AUOpenNoAnswerForward" | "AUCloseNoAnswerForward" | "AUTransferCall" | "AUBlindTransfer" | "AUAttendedTransfer" | "AUHold" | "AUUnHold" | "AURemoteHold" | "AURemoteUnHold" | "AUMute" | "AUUnMute" | "AUMissedCall" | "AUIpChanged" | "AUBusyToIdle" | "AUIdleToBusy" | "AURejectIncomingCall"
   | "AUAnswerNewInCall" | "AUTransferFailed" | "AUTransferFinished" | "AUForwardIncomingCall" | "AUUCServer" | "AURemoteIP" | "AUAutopFinish" | "AUOpenCallWait" | "AUCloseCallWait" | "AUHeadSet" | "AUHandFree" | "AUCancelCallOut" | "AURemoteBusy" | "AUCallRemoteCanceled" | "AUPeripheralInformation";

function getresultinfo(body: string) {
  var index = body.indexOf('<div id="_RES_INFO_"');
  var result = "";
  if (index > 0) {
    for (; ">" != body[index++] && index < body.length;);
    for (var iter = index; iter + 7 < body.length;) {
      var stopper = body.substr(iter, 6);
      if ("</div>" == stopper) break;
      iter++;
    }
    iter > index &&
      iter + 7 < body.length &&
      (result = body.substring(index, iter));
  }
  return result;
}

const getBodyVar = (body: string, name: string) => {
  const pattern = new RegExp(`var ${name} = "([A-Za-z0-9]+)"`);
  const m = body.match(pattern);
  if (m) {
    return m[1];
  }
  console.error(`fail to find variable ${name}`);
  return "";
};

type YealinkEventEmitterListener = (arg: http.IncomingMessage) => void;

export interface YealinkEventEmitter {
  addListener(event: YealinkEvents, listener: (arg: http.IncomingMessage) => void): this;
  on(event: YealinkEvents, listener: (args: http.IncomingMessage) => void): this;
  once(event: YealinkEvents, listener: (args: http.IncomingMessage) => void): this;
  prependListener(event: YealinkEvents, listener: (args: http.IncomingMessage) => void): this;
  prependOnceListener(event: YealinkEvents, listener: (args: http.IncomingMessage) => void): this;
  removeListener(event: YealinkEvents, listener: (args: http.IncomingMessage) => void): this;
  off(event: YealinkEvents, listener: (args: http.IncomingMessage) => void): this;
  removeAllListeners(event?: YealinkEvents): this;
  listeners(event: YealinkEvents): Function[];
  rawListeners(event: YealinkEvents): Function[];
  emit(event: YealinkEvents, ...args: any[]): boolean;
  listenerCount(type: YealinkEvents): number;

  on(event: 'all', listener: (ev: YealinkEvents, req: http.IncomingMessage) => void): this;
}

/**
 * a yealink instance is connect to a Yealink phone.
 */
export class Yealink extends EventEmitter implements YealinkEventEmitter {
  private ip: string;
  private myIp: string;
  private auth: AuthOptions;
  // private localId: string;
  private jar: CookieJar;
  private theCookie: string;
  private _phonetype = "";
  private _rsa_n = "";
  private _rsa_e = "";
  private account = "Account1";
  private g_strToken = "";

  private objEncrypt = {
    rsa: "",
    key: "",
    aes: { iv: <any>null, mode: <any>null, padding: <any>null },
    data: { key: null, iv: null }
  };

  private accounts = {
    Account1: "0",
    Account2: "0",
    Account3: "0"
  };
  /**
   * server used to recieve events
   */
  private server: Server;

  constructor(ip: string, user: string, pass: string, myIp: string) {
    super();
    this.ip = ip;
    this.myIp = myIp;
    this.auth = { user, pass };
    this.theCookie = "";
    const yealink = this;
    this.jar = {
      setCookie: (
        cookieOrStr: Cookie | string,
        uri: string | Url,
        options?: tough.CookieJar.SetCookieOptions
      ) => (yealink.theCookie = cookieOrStr as string),
      getCookieString: (uri: string | Url): string => yealink.theCookie,
      getCookies: (uri: string | Url): Cookie[] => []
    };
    this.server = http.createServer((req, resp) => {
      const event: string = (req.url as string).substring(1);
      this.emit('all', event, req);
      this.emit(event, req);
      resp.end("OK");
    });
  }

  private InitEncrypt() {
    const rsa = new RSAKey();
    rsa.setPublic(this._rsa_n, this._rsa_e);
    this.objEncrypt.rsa = rsa;
    this.objEncrypt.aes.mode = CryptoJS.mode.CBC;
    this.objEncrypt.aes.padding = CryptoJS.pad.ZeroPadding;
    var r = CryptoJS.MD5(Math.random().toString()).toString();
    this.objEncrypt.data.key = rsa.encrypt(r);
    this.objEncrypt.key = CryptoJS.enc.Hex.parse(r);
    var n = CryptoJS.MD5(Math.random().toString()).toString();
    this.objEncrypt.data.iv = rsa.encrypt(n);
    this.objEncrypt.aes.iv = CryptoJS.enc.Hex.parse(n);
  }

  private Encrypt(message: string) {
    message = message || "";
    var t = `${Math.random()};`;
    const m = this.theCookie.match(/JSESSIONID=(\w+)/);
    if (m) {
      t += m[1] + ";" + message;
    }
    var r = CryptoJS.AES.encrypt(t, this.objEncrypt.key, this.objEncrypt.aes);
    return r.toString();
  }

  public async phonetype() {
    if (this._phonetype) return this._phonetype;
    const q = await rp(`http://${this.ip}/servlet`, {
      jar: this.jar,
      qs: { m: "mod_listener", p: "login", q: "loginForm", jumpto: "status" }
    });
    this._phonetype = getBodyVar(q, "g_phonetype");
    this._rsa_n = getBodyVar(q, "g_rsa_n");
    this._rsa_e = getBodyVar(q, "g_rsa_e");
    return this._phonetype;
  }

  public async login() {
    // RSA KEYS DATA MUST BE LOADED
    if (this.g_strToken) return;
    await this.phonetype();
    let uri = `http://${
      this.ip
      }/servlet?m=mod_listener&p=login&q=login&Rajax=${Math.random()}`;
    this.InitEncrypt();
    const username = this.auth.user;
    const pwd = this.Encrypt(this.auth.pass as string);
    const rsakey = this.objEncrypt.data.key;
    const rsaiv = this.objEncrypt.data.iv;
    const jar = this.jar;
    let q = "";
    let code = "";
    try {
      q = await rp({
        jar,
        uri,
        method: "POST",
        form: { username, pwd, rsakey, rsaiv },
        headers: {}
      });
    } catch (e) {
      code = e;
    }
    code = getresultinfo(q);
    if (code !== '{"authstatus":"done"}')
      throw `Login request should return {"authstatus":"done"}`;
    try {
      q = await rp(`http://${this.ip}/servlet`, {
        jar: this.jar,
        qs: { m: "mod_data", p: "status", q: "load" }
      });
    } catch (e) {
      code = e;
    }
    code = getresultinfo(q);
    const g_dataAccStatus = q.match(
      /var g_dataAccStatus = g_json\.ParseJSON\("(.+)"\)/
    );
    if (g_dataAccStatus) {
      let stuff = g_dataAccStatus[1];
      stuff = stuff.replace(/\\"/g, '"');
      this.accounts = JSON.parse(stuff);
    }
    this.g_strToken = getBodyVar(q, "g_strToken");
  }

  public setAccount(
    account:
      | "Account1"
      | "Account2"
      | "Account3"
      | "Account4"
      | "Account5"
      | "Account6"
      | "Account7"
      | "Account8"
  ) {
    this.account = account;
  }

  private async loadServlet(qs: { m: 'mod_data', p: YealinkProperty }): Promise<string> {
    await this.login();
    try {
      return await rp(`http://${this.ip}/servlet`, {
        jar: this.jar, qs: { ...qs, q: 'load' }
      });
    } catch (e) {
      return e;
    }
  }

  private async dialServlet(number: string, acc: number, type: number): Promise<string> {
    await this.login();
    const form = { num: number, acc, type, token: this.g_strToken };
    try {
      const body = await rp(`http://${this.ip}/servlet?m=mod_account&p=call&q=dial`, {
        method: "POST",
        jar: this.jar,
        form
      });
      const ret = getresultinfo(body);
      if (ret != '1') {
        console.error(`mod_account call return: ${ret}`)
      }
      return ret; // '1' => ok '0' => ko
    } catch (e) {
      return e;
    }
  }

  private async writeServlet(qs: { m: 'mod_data', p: YealinkProperty }, form: any): Promise<string> {
    await this.login();
    form = { ...form, token: this.g_strToken };
    try {
      const body = await rp(`http://${this.ip}/servlet`, {
        method: "POST",
        jar: this.jar,
        qs: { ...qs, q: 'write' },
        form
      });
      const ret = getresultinfo(body);
      if (ret) {
        console.error(`mod_data ${qs.p} return: ${ret}`)
      }
      return ret;
    } catch (e) {
      return e;
    }
  }
  /**
   * call ussing webinterface
   * @param number 
   * @param accountId 
   */
  public async call(number: string, accountId?: number) {
    await this.login();
    number = number.replace(/[^0-9]/g, '');
    accountId = accountId || 0;

    const status = (this.accounts as any)[`Account${accountId + 1}`];
    if (!status.endsWith(':2')) {
      throw Error(`Line ${accountId} is not registred`);
    }
    let ret = await this.dialServlet(number, accountId, 1);
    if (ret !== '1')
      throw 'call servlet should return 1 but return ' + ret;
  }

  public async callOld(number: string, accountId?: number) {
    await this.login();
    number = number.replace(/[^0-9]/g, '');
    const ver = await this.phonetype();
    if (!(this.account in this.accounts))
      throw `can not find account ${this.account}`;
    let outgoing_uri = (this.accounts as any)[this.account] as string;
    if (!outgoing_uri.endsWith(':2')) {
      throw `account ${this.account} is not registed`;
    }
    outgoing_uri = outgoing_uri.substring(0, outgoing_uri.length - 2);
    const q = await rp(`http://${this.ip}/servlet`, {
      jar: this.jar,
      auth: this.auth,
      qs: { key: `number=${number}`, outgoing_uri }
    });
    const code = getresultinfo(q);
    if (!code) return;
    console.log(code);
  }

  public async hangup() {
    await this.login();
    const jar = this.jar;
    let uri = `http://${
      this.ip
      }/servlet?m=mod_account&p=call&q=hangup&Rajax=${Math.random()}`;
    let q = await rp({
      jar,
      uri,
      method: "POST",
      form: { token: this.g_strToken },
      headers: {}
    });
    const code = getresultinfo(q);
    if (!code) return;
    //if (isFail(q)) throw Error("auth Filed");
    // console.log(`hangup return ${code}`);
  }

  /**
   * is for Old T2X(T28P, T26P, T22P, T21P, T20P and T19P)which version is V70.
   */
  public async press(key: YealinkKey) {
    const jar = this.jar;
    const q: string = await rp(`http://${this.ip}/cgi-bin/ConfigManApp.com`, {
      auth: this.auth,
      jar,
      qs: { key }
    });
    const code = getresultinfo(q);
    if (!code) return;
    console.log("code:" + code);
  }

  /**
   * allow IP to remote controle Phone
   */
  public async AllowIP(ips?: string) {
    ips = ips || this.myIp;
    let body = await this.loadServlet({ m: 'mod_data', p: 'features-remotecontrl' });
    const $ = cheerio.load(body);
    const inp = $('input[name="AURILimitIP"]')
    if (!inp.length)
      throw Error('loading Page Error AURILimitIP not found');
    const value = inp[0].attribs['value'];
    if (value !== ips) {
    }
    await this.writeServlet({ m: "mod_data", p: 'features-remotecontrl' }, { AURILimitIP: ips });
  }

  /**
   * return a map extention id to useraccount 
   */
  public async getAccounts(): Promise<{ [key: number]: string }> {
    await this.login();
    const out: { [keys: number]: string } = {}
    for (const key of Object.keys(this.accounts)) {
      const id = Number(key.replace(/[^0-9]/g, ''))
      const value = (this.accounts as any)[key] as string;
      if (!value.endsWith(':2'))
        continue;
      out[id - 1] = value.substring(0, value.length - 2)
    }
    return out;
  }

  /**
   * Register Event listener
   */
  public async register(port: number) {
    let body: string = await this.loadServlet({ m: "mod_data", p: "features-actionurl" })
    const $ = cheerio.load(body);
    let posts = $('[yltype="post"]').toArray();
    let names = posts.map(input => input.attribs['name'])
    let form: { [key: string]: string } = {}
    names.forEach(n => form[n] = `http://${this.myIp}:${port}/${n}`);
    this.server.listen(port, () => console.log("liten to " + port));
    const ret = await this.writeServlet({ m: 'mod_data', p: "features-actionurl" }, form);
  }

  /**
   * unRegister Event listener
   */
  public async unregister() {
    let body: string = await this.loadServlet({ m: "mod_data", p: "features-actionurl" })
    const $ = cheerio.load(body);
    let posts = $('[yltype="post"]').toArray();
    let names = posts.map(input => input.attribs['name'])
    let form: { [key: string]: string } = {} // token: this.g_strToken
    names.forEach(n => form[n] = '');
    const ret = await this.writeServlet({ m: 'mod_data', p: "features-actionurl" }, form);
    this.server.close();
  }
}
