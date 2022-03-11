
print('test.tCoroutine');

tCoroutine = {
    --
};

function tCoroutine.foo()
    print("foo",1);
    coroutine.yield();
    print("foo",2);
end

function tCoroutine.testCase()
    local co = coroutine.create(tCoroutine.foo);
    print(co);
    print(coroutine.status(co));
    coroutine.resume(co);
    print(coroutine.status(co));
    -- coroutine.resume(co);
    -- print(coroutine.status(co));
end
