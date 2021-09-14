# yealink

Control yealink phone with nodejs code.

- Support action URL
- Dial number
- Press keys
- ...

## how it works

This code connect to your phone built-in http server, and give you access to most feature available in it.

```typescript
const ip = '10.10.0.2'// IP to acess your phone
const user = 'username';
const pass = 'password';
const myIp = 'IP that will be use by to the to reach your computer';
const yl = new Yealink(ip, user, pass, myIp);
await yl.login();
// ...
```

## yealink binary script

Set action url in yealink phone feature option.

```bash
yealink action-url -u admin -p admin -s https://track.over.ovh/event/myToken 192.168.1.3
```
