
print('test.tCallback');

tCallback = {
    --
};

function tCallback.testOutput()
    print( "Hello world.");
end

function tCallback.testCase()
    --
    cb = _cb;

    --
    cb:init();

    cb:setCallback(tCallback.testOutput);
    cb:runCallback();

    --
    cb:remove();
end
