# yealink

control yealink phone with nodejs

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
