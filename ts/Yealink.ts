import rp from "request-promise";
import http, { Server } from "http";
import { AuthOptions, CookieJar, Cookie } from "request";
import { Url } from "url";
import tough from "tough-cookie";
import CryptoJS from "crypto-js";
import YealinkKey from "./YealinkKey";
import cheerio from 'cheerio';
import { EventEmitter } from "events";
import YealinkVariable from "./YealintVariable";
import YealinkEvents from './YealinkEvents';
import os from 'os';
import IPCIDR from 'ip-cidr';

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

export type EventParams = { [key in YealinkVariable]: string };

interface RegisterOptionsExter {
  external_url: string,
  variables?: Set<YealinkVariable> | Array<YealinkVariable>,
  events?: Set<YealinkEvents> | Array<YealinkEvents>
}

interface RegisterOptionsSelf {
  port: number,
  variables?: Set<YealinkVariable> | Array<YealinkVariable>,
  events?: Set<YealinkEvents> | Array<YealinkEvents>
}

/**
 * @param dest find a local IP on the same range that the destination.
 */
function getlocalIP(dest: string): string {
  const nets = os.networkInterfaces();
  let validIp = '';
  Object.values(nets).forEach(elements => {
    if (!elements)
      return;
    elements.forEach(element => {
      const { cidr, address } = element;
      if (!cidr || !address)
        return;
      const block = new IPCIDR(cidr);
      if (block.contains(dest))
        validIp = address;
    })
  });
  return validIp;
}

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

// type YealinkEventEmitterListener = (arg: http.IncomingMessage) => void;

export interface YealinkEventEmitter {
  addListener(event: YealinkEvents, listener: (params: EventParams) => void): this;
  on(event: YealinkEvents, listener: (params: EventParams) => void): this;
  once(event: YealinkEvents, listener: (params: EventParams) => void): this;
  prependListener(event: YealinkEvents, listener: (params: EventParams) => void): this;
  prependOnceListener(event: YealinkEvents, listener: (params: EventParams) => void): this;
  removeListener(event: YealinkEvents, listener: (params: EventParams) => void): this;
  off(event: YealinkEvents, listener: (params: EventParams) => void): this;
  removeAllListeners(event?: YealinkEvents): this;
  listeners(event: YealinkEvents): Function[];
  rawListeners(event: YealinkEvents): Function[];
  emit(event: YealinkEvents, ...args: any[]): boolean;
  listenerCount(type: YealinkEvents): number;

  on(event: 'all', listener: (ev: YealinkEvents, params: EventParams) => void): this;
}

/**
 * a yealink instance is connect to a Yealink phone.
 */
export class Yealink extends EventEmitter implements YealinkEventEmitter {
  private ip: string;
  private myIp_cache: string;
  private auth: AuthOptions;
  // private localId: string;
  private theCookie: string;
  private _phonetype = "";
  private _rsa_n = "";
  private _rsa_e = "";
  private account = "Account1";
  private g_strToken = "";
  private schema: 'http' | 'https' = 'http';
  private objEncrypt = {
    rsa: "",
    key: "",
    aes: { iv: '', mode: null as CryptoJS.Mode | null, padding: null as CryptoJS.Padding | null } as CryptoJS.CipherOption,
    data: { key: '', iv: '' }
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
  private commonOption: rp.RequestPromiseOptions;
  constructor(ip: string, user: string, pass: string, myIp?: string) {
    super();
    this.ip = ip;
    this.myIp_cache = myIp || '';
    this.auth = { user, pass };
    this.theCookie = "";
    const yealink = this;
    const jar: CookieJar = {
      setCookie: (
        cookieOrStr: Cookie | string,
        uri: string | Url,
        options?: tough.CookieJar.SetCookieOptions
      ) => (yealink.theCookie = cookieOrStr as string),
      getCookieString: (uri: string | Url): string => yealink.theCookie,
      getCookies: (uri: string | Url): Cookie[] => []
    };

    this.commonOption = {
      rejectUnauthorized: false,
      jar,
    }

    this.server = http.createServer((req: http.IncomingMessage, resp: http.ServerResponse) => {
      const { url } = req;
      if (!url) {
        resp.end('500');
        return;
      }
      const parsed = new URL(url, 'http://0.0.0.0');
      const data = {} as { [key in YealinkVariable]: string };
      parsed.searchParams.forEach((value: string, key: string, parent: URLSearchParams) => {
        data[key as YealinkVariable] = value;
      });
      const event = parsed.pathname.substring(1);
      this.emit('all', event, data);
      this.emit(event, data);
      resp.end("OK");
    });
  }

  //  on(event: YealinkEvents, listener: (args: any) => void): this;
  //  on(event: "all", listener: (ev: YealinkEvents, req: any) => void): this;
  //  on(event: any, listener: any) {
  //    return super.on(event, listener);
  //  }

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

  public setSchema(schema: 'http' | 'https') {
    if (schema == 'http') {
      this.schema = 'http';
    } else if (schema == 'https') {
      this.schema = 'https';
    } else {
      throw Error(`invalid schema ${schema} valid values are http, https`);
    }
  }

  public async phonetype() {
    if (this._phonetype) return this._phonetype;
    const q = await rp(`${this.schema}://${this.ip}/servlet`, {
      ...this.commonOption,
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
    let uri = `${this.schema}://${this.ip
      }/servlet?m=mod_listener&p=login&q=login&Rajax=${Math.random()}`;
    this.InitEncrypt();
    const username = this.auth.user;
    const pwd = this.Encrypt(this.auth.pass as string);
    const { key, iv } = this.objEncrypt.data;
    let q = "";
    let code = "";
    try {
      q = await rp({
        ...this.commonOption,
        uri,
        method: "POST",
        form: { username, pwd, rsakey: key, rsaiv: iv },
        headers: {}
      });
    } catch (e) {
      code = `${e}`;
    }
    code = getresultinfo(q);
    if (code !== '{"authstatus":"done"}')
      throw `Login request should return {"authstatus":"done"}`;
    try {
      q = await rp(`${this.schema}://${this.ip}/servlet`, {
        ...this.commonOption,
        qs: { m: "mod_data", p: "status", q: "load" }
      });
    } catch (e) {
      code = `${e}`;
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
      return await rp(`${this.schema}://${this.ip}/servlet`, {
        ...this.commonOption,
        qs: { ...qs, q: 'load' }
      });
    } catch (e) {
      throw e;
    }
  }

  private async dialServlet(number: string, acc: number, type: number): Promise<string> {
    await this.login();
    const form = { num: number, acc, type, token: this.g_strToken };
    try {
      const body = await rp(`${this.schema}://${this.ip}/servlet?m=mod_account&p=call&q=dial`, {
        ...this.commonOption,
        method: "POST",
        form
      });
      const ret = getresultinfo(body);
      if (ret != '1') {
        console.error(`mod_account call return: ${ret}`)
      }
      return ret; // '1' => ok '0' => ko
    } catch (e) {
      throw e;
    }
  }

  private async writeServlet(qs: { m: 'mod_data', p: YealinkProperty }, form: any): Promise<string> {
    await this.login();
    form = { ...form, token: this.g_strToken };
    try {
      const body = await rp(`${this.schema}://${this.ip}/servlet`, {
        ...this.commonOption,
        method: "POST",
        qs: { ...qs, q: 'write' },
        form
      });
      const ret = getresultinfo(body);
      if (ret) {
        console.error(`mod_data ${qs.p} return: ${ret}`)
      }
      return ret;
    } catch (e) {
      throw e;
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
    const q = await rp(`${this.schema}://${this.ip}/servlet`, {
      ...this.commonOption,
      auth: this.auth,
      qs: { key: `number=${number}`, outgoing_uri }
    });
    const code = getresultinfo(q);
    if (!code) return;
    console.log(code);
  }

  public async hangup() {
    await this.login();
    let uri = `${this.schema}://${this.ip}/servlet?m=mod_account&p=call&q=hangup&Rajax=${Math.random()}`;
    let q = await rp({
      ...this.commonOption,
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
    const q: string = await rp(`${this.schema}://${this.ip}/cgi-bin/ConfigManApp.com`, {
      ...this.commonOption,
      auth: this.auth,
      qs: { key }
    });
    const code = getresultinfo(q);
    if (!code) return;
    console.log(`code: ${code}`);
  }


  private getMyIp(): string {
    const { myIp_cache } = this;
    if (myIp_cache)
      return myIp_cache;
    const ip2 = getlocalIP(this.ip);
    if (!ip2)
      throw Error(`Failed to detect a local IP on the same network than ${this.ip}`);
    this.myIp_cache = ip2;
    return ip2;
  }

  /**
   * allow IP to remote controle Phone
   */
  public async AllowIP(ips?: string): Promise<boolean> {
    ips = ips || this.getMyIp();
    let body = await this.loadServlet({ m: 'mod_data', p: 'features-remotecontrl' });
    const $ = cheerio.load(body);
    const inp = $('input[name="AURILimitIP"]').toArray() as cheerio.TagElement[];
    if (!inp.length)
      throw Error('loading Page Error AURILimitIP not found');
    const value = inp[0].attribs['value'];
    if (value === ips) {
      return false;
    }
    await this.writeServlet({ m: "mod_data", p: 'features-remotecontrl' }, { AURILimitIP: ips });
    return true;
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

  private getYltype(body: string): string[] {
    const $ = cheerio.load(body);
    let posts = $('[yltype="post"]').toArray() as cheerio.TagElement[];
    let names = posts.map((input) => input.attribs['name'])
    // as raw string
    // const matches = body.match(/yltype="post" name="[^"]+"/g) || [];
    // let names = matches.map(m => { const m2 = m.match(/name="([^"]+)"/); return m2 ? m2[1] : ''; });
    return names;
  }

  /**
   * Register Event listener
   */
  public async register(options: RegisterOptionsExter | RegisterOptionsSelf) {
    // options = options || {};
    let body: string = await this.loadServlet({ m: "mod_data", p: "features-actionurl" })
    let names = this.getYltype(body);
    let form: { [key: string]: string } = {}
    const { variables, events } = options;
    if (events) {
      const events2 = new Set(events);
      names = names.filter((name) => events2.has(name as YealinkEvents))
    }

    let params = ''
    if (variables) {
      const values = [...variables].map((v: YealinkVariable) => `${v}=$${v}`).join('&');
      params = `${values}`;
    }

    const port = (options as RegisterOptionsSelf).port;
    let external_url = (options as RegisterOptionsExter).external_url;
    if (port) {
      const myIp = this.getMyIp();
      names.forEach(n => form[n] = `http://${myIp}:${port}/${n}?${params}`);
      this.server.listen(port, () => console.log(`litening port ${port}`));
    } else if (external_url) {
      if (~external_url.indexOf('?')) {
        external_url += '&'
      } else {
        external_url += '?'
      }
      names.forEach(n => form[n] = `${external_url}ev=${n}&${params}`);
    } else {
      // reset
      names.forEach(n => form[n] = '');
    }
    await this.writeServlet({ m: 'mod_data', p: "features-actionurl" }, form);
  }

  /**
   * unRegister Event listener
   */
  public async unregister() {
    let body: string = await this.loadServlet({ m: "mod_data", p: "features-actionurl" })
    let names = this.getYltype(body);
    let form: { [key: string]: string } = {} // token: this.g_strToken
    names.forEach(n => form[n] = '');
    const ret = await this.writeServlet({ m: 'mod_data', p: "features-actionurl" }, form);
    this.server.close();
  }
}

export default Yealink;