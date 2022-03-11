print('config.config');

_config = {};

function _config.contractActions()
    local contractActions = _commonUtil.readBinaryFile('./../../conf/contract_actions.json');
    -- print('contractActions : ', contractActions);
    local contractActionsJson = json.parse(contractActions);
    -- print(contractActionsJson['CONTRACT']['DEFAULT']['ADD_USER']);
    -- _commonUtil.prtTable(contractActionsJson['CONTRACT']['DEFAULT']);

    return contractActionsJson;
end
