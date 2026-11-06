// Invoked by the ignored real-validator lifecycle to exercise the production
// browser exit builder without running an operator HTTP server.
import { prepareLocalSolanaExit } from '../../services/zkapiSolanaExit.mjs';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const { funding, kind, body } = JSON.parse(input);
console.log(JSON.stringify(await prepareLocalSolanaExit(funding, kind, body)));
