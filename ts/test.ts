import Yealink, { EventParams } from "./Yealink";
import YealinkVariable from "./YealintVariable";

async function main () {
    const yl = new Yealink('10.0.0.76', 'admin', 'admin');
    await yl.login();
    const accs = await yl.getAccounts();
    console.log(accs);
    let varaibles: Array<YealinkVariable>;
    varaibles = ['mac', 'ip', 'firmware', 'display_local', 'call_id'];
    varaibles = ['display_local', 'display_remote', 'calledNumber', 'call_id', 'callerID', 'mac', 'cfg_all', 'cfg_local'];
    yl.register(9999, {varaibles});
    yl.on('all', (event: YealinkVariable, data: EventParams) => {
        console.log(event, data);
    });
    return new Promise(()=>{});
}

main();

