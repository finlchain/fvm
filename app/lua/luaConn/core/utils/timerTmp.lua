-------------------------
local timers = {}
local currentTime = 0.0

function setTimer(time, f) -- time초 후에 f를 실행
    table.insert(timers, {time = time, onComplete = f, isCompleted = false})
end

function updateTime(dt)
    for _, timer in ipairs(timers) do
        timer.time = timer.time - dt
        if timer.time <= 0 and not timer.isCompleted then
            print(utcCurrMS());
            timer.onComplete()
            timer.isCompleted = true
        end
  
    end

    local activeTimers = {}

    for _, timer in ipairs(timers) do
        if not timer.isCompleted then
            table.insert(activeTimers, timer)
        end
    end

    timers = activeTimers
    currentTime = currentTime + dt
end
-------------------------
function runCoroutine(f)
    local co = coroutine.wrap(f)

    print("wait 1")
    local wait = function(time)
        print("wait time : ", time)
        setTimer(time, co)
        coroutine.yield()
    end
    print("wait 2")
    co(wait)
end



function setBomb(name, tickInterval, nRepeat)
    runCoroutine(function(wait)
        for i=1, nRepeat do
            print(string.format("%s %.2f %s", name, currentTime, "Tick"))
            -- wait(tickInterval)
        end
        print(string.format("%s %.2f %s", name, currentTime, "Boom!"))
    end)
end