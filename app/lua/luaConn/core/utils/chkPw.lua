
print('core.utils.chkPw')

_chkPw = {
    blockedWords = {"password", "letmein", "computer"},
    minTypes = 4,
    minLength = 10
};

function _chkPw.chkPwStrength(Username, Password)
    if (Password == nil) then
        print("Password is nil")
        return false
    end

    if string.len(Password) < _chkPw["minLength"] then
        print("Password Length should be larger than ", _chkPw["minLength"])
        return false
    end

    local lowerPassword = string.lower(Password)

    if (Username ~= nil) then
        if Password == Username then
            return false
        end
    end

    for _, value in pairs(_chkPw["blockedWords"]) do
        if lowerPassword == value then
            return false
        end
    end

    local hasDigit = 0
    local hasCaps = 0
    local hasLower = 0
    local hasSpecial = 0

    if string.find(Password, "%d") then
        hasDigit = 1
    end

    if string.find(Password, "[A-Z]") then
        hasCaps = 1
    end

    if string.find(Password, "[a-z]") then
        hasLower = 1
    end

    if string.find(Password, "[^a-zA-Z0-9]") then
        hasSpecial = 1
    end

    local differentTypes = hasDigit + hasCaps + hasLower + hasSpecial

    -- print("hasDigit : ", hasDigit, "hasCaps : ", hasCaps, "hasLower : ", hasLower, "hasSpecial : ", hasSpecial);

    if differentTypes >= _chkPw["minTypes"] then
        return true
    else
        return false
    end
end