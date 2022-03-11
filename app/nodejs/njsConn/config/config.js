//
const fs = require('fs');
const os = require('os');

// 
module.exports.CFG_PATH = {
    CONTRACT_ACTIONS : './../../conf/contract_actions.json', 
}

// Contract Class
module.exports.CONTRACT_ACTIONS_JSON = JSON.parse(fs.readFileSync(this.CFG_PATH.CONTRACT_ACTIONS));
