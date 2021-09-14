import Yealink from "./Yealink";
import YealinkVariable from "./YealintVariable";
import { Command, Option } from 'commander';

const program = new Command();
const defaultVars = ['display_local', 'display_remote', 'calledNumber', 'call_id', 'callerID', 'mac', 'local', 'remote', 'active_user', 'active_host']
async function configPhone(ip: string, options: ScriptOptions) {
    const { user, password, server } = options;
    const yl = new Yealink(ip, user, password);
    await yl.login();
    const variables = options.variables.split(/[,; ]+/g) as Array<YealinkVariable>;
    await yl.register({ external_url: server, variables });
    console.log(`external_url setted to '${server}' in phone: ${ip}`);
}

interface ScriptOptions {
    user: string;
    password: string;
    server: string;
    variables: string;
}

program.showHelpAfterError('(add --help for additional information)');
program.version('0.1.0')

const serverOpt = new Option('-s, --server <server>', 'choose the event server ex: https://track.over.ovh/event/writeToken')
serverOpt.makeOptionMandatory(true)

program.command('action-url') //  <ips...>
    .description('Update the action URL of a yealink')
    .option('-u, --user [user]', 'Phone username', 'admin')
    .option('-p, --password [password]', 'Phone password', 'admin')
    .addOption(serverOpt)
    .option('-v, variables <variables>', 'Variables to add to action url', defaultVars.join(','))
    .argument('<ips...>', 'One or more Yealink phone IP')
    .action(async (ips: string[], options: ScriptOptions, command: Command) => {
        for (const ip of ips) {
            try {
                await configPhone(ip, options);
            } catch (e) {
                console.error(`configuring phone :${ip} Failed:`, e);
            }
        }
    });
 
program.parse(process.argv);
