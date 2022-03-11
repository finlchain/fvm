
//
module.exports.signBufferGenerator = (transfer) => {
    return Buffer.from(
        transfer.create_tm
        + transfer.fintech
        + transfer.privacy
        + transfer.fee
        + transfer.from_account
        + transfer.to_account
        + transfer.action
        + JSON.stringify(transfer.contents)
        + transfer.memo
    );
};

