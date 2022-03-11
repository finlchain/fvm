
print('core.utils.timer')

_timer = {
    co = nil;
    timers = {};
    currentTime = 0.0;
    timerId = 0;
};

function _timer.setTimer(time, f) -- time초 후에 f를 실행
    _timer.timerId = _timer.timerId + 1;

    table.insert(_timer.timers, {time = time, onComplete = f, isCompleted = false, id = _timer.timerId});

    -- print('#_timer.timers : ', #_timer.timers);
    -- for tmK, tmV in pairs(_timer.timers) do
    --     print('tmK : ', tmK, 'tmV : ', tmV);
    -- end

    return _timer.timerId;
end

function _timer.clrTimer(myTimerId, f)
    for idx, timer in ipairs(_timer.timers) do
        if (timer.id == myTimerId) then
            print('idx : ', idx);
            table.remove(timers, idx);
            break;
        end
    end

    -- print('#_timer.timers : ', #_timer.timers);
    -- for tmK, tmV in pairs(_timer.timers) do
    --     print('tmK : ', tmK, 'tmV : ', tmV);
    -- end
end

function _timer.updateTime(msec)
    for _, timer in ipairs(_timer.timers) do
        timer.time = timer.time - msec
        if timer.time <= 0 and not timer.isCompleted then
            timer.onComplete();
            timer.isCompleted = true;
        end
    end

    local activeTimers = {}

    for _, timer in ipairs(_timer.timers) do
        if not timer.isCompleted then
            table.insert(activeTimers, timer)
        end
    end

    _timer.timers = activeTimers
    
    _timer.currentTime = _timer.currentTime + msec
end

function _timer.initTimer()
    _timer.co = coroutine.wrap(function ()
        local msec = 1000;
        while true do 
            msleep(msec)
            _timer.updateTime(msec)
            coroutine.yield()
        end
    end)

    return _timer.co;
end

function _timer.getTimer(myTimerId, f)
    for idx, timer in ipairs(_timer.timers) do
        if (timer.id == myTimerId) then
            return true;
        end
    end

    -- print('#_timer.timers : ', #_timer.timers);
    -- for tmK, tmV in pairs(_timer.timers) do
    --     print('tmK : ', tmK, 'tmV : ', tmV);
    -- end

    return false;
end

function _timer.runTimer()
    --
    while #_timer.timers > 0 do 
        _timer.co();
    end
end

function timerTest()
    local myTimerId;

    --
    myTimerId = _timer.setTimer(3000, function () print(utcCurrMS(), "3"); end);
    myTimerId = _timer.setTimer(1000, function () print(utcCurrMS(), "1"); end);
    myTimerId = _timer.setTimer(2000, function () print(utcCurrMS(), "2"); end);

    --
    local dt = 1000
    for t=0, 4, dt do
        msleep(1000)
        _timer.updateTime(dt)
    end
end