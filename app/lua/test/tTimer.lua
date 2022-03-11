print('test.tTimer');

tTimer = {
    myTimerId = 0;
};

function tTimer.myScript()
    if _timer.getTimer(tTimer.myTimerId, nil) == false then
        print('tTimer.myTimerId : ', tTimer.myTimerId);
        tTimer.myTimerId = _timer.setTimer(2000, function () print(utcCurrMS(), "2000"); end);
    end
end

function tTimer.runTimer(cbFunc)
    --
    -- while #_timer.timers > 0 do 
    while true do 
        cbFunc();
        _timer.co();
    end
end

function tTimer.testCase()
    --
    _timer.initTimer();

    --
    tTimer.myTimerId = _timer.setTimer(3000, function () print(utcCurrMS(), "3"); end);
    tTimer.myTimerId = _timer.setTimer(1000, function () print(utcCurrMS(), "1"); end);
    tTimer.myTimerId = _timer.setTimer(2000, function () print(utcCurrMS(), "2"); end);

    -- _timer.clrTimer(tTimer.myTimerId, nil);

    --
    tTimer.runTimer(tTimer.myScript);

    -- --
    -- myTimerId = _timer.setTimer(2000, function () print(utcCurrMS(), "2"); end);

    -- _timer.runTimer();
end