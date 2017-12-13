// 参考：
// https://tools.ietf.org/html/rfc2136
// https://technet.microsoft.com/zh-cn/library/dd197470(v=ws.10).aspx
// 《TCP/IP详解卷1：协议》 第14章 DNS:域名系统
const debug = require('debug')('dns');
const dgram = require('dgram');
const server = dgram.createSocket('udp4');
const _ = require('lodash');

function RR(msg, pos) {
    debug('--------------[RR %d]------------------', pos);
    // Resource Record Name
    let rrName = [];
    debug('pos: %d', msg[pos]);
    while (pos < msg.length && 0 !== (length = msg[pos++])) {
        debug('length: %d, pos: %d, question: %s', length, pos, msg.slice(pos, pos + length).toString('ascii'));
        rrName.push(msg.slice(pos, pos + length).toString('ascii'));
        pos += length;
    }
    debug('rrName: %s', rrName.join('.'));

    // Resource Record Type
    // 16字节 2byte
    let rrType = msg.slice(pos, pos += 2).toString('hex');
    debug('rrType: %s', parseInt(rrType, 16));

    // Resource Record Class
    // 16字节 2byte
    let rrClass = msg.slice(pos, pos += 2).toString('hex');
    debug('rrClass: %s', parseInt(rrClass, 16));

    // Time-to-Live
    let ttl = parseInt(msg.slice(pos, pos += 4).toString('hex'), 16);
    debug('ttl: %d', ttl);

    // Resource Data Length
    let rdl = parseInt(msg.slice(pos, pos += 2).toString('hex'), 16);
    debug('rdl: %d', rdl);
    let rd;
    if (rdl > 0) rd = msg.slice(pos, pos += rdl);

    return {
        rrName,
        rrType,
        rrClass,
        ttl,
        rdl,
        rd,
        pos
    }
}

server.on('error', (err) => {
    debug(`server error:\n${err.stack}`);
    server.close();
});

server.on('message', (msg, rinfo) => {
    debug('msg(hex): %s', msg.toString('hex'));
    let pos = 0;
    let header = msg.slice(pos, pos += 12);
    let headerBits = '';
    for (let byte of header) {
        // debug('origin: %d, bits: %s, pad: %s', byte, byte.toString(2), _.padStart(byte.toString(2), 8, '0'));
        headerBits += _.padStart(byte.toString(2), 8, '0');
    }
    debug('header(bit): %s, header(hex): 0x%s', headerBits, header.toString('hex'));

    // parse header
    let transactionId = headerBits.slice(0, 16);
    debug('transactionId: %s, transactionId(hex): 0x%s', transactionId, parseInt(transactionId, '2').toString(16));

    // flags
    let flags = headerBits.slice(16, 32);
    debug('flags: %s, flags(hex): 0x%s', flags, parseInt(flags, '2').toString(16));
    // QR(Request/response)是1bit字段：0表示查询报文，1表示响应报文。
    let qr = flags.slice(0, 1);
    // opcode是一个4bit字段：通常值为0（标准查询），其他值为1（反向查询）和2（服务器状态请求）。
    let opcode = flags.slice(1, 5);
    // AA(Authoritative answer)是1bit标志，表示“授权回答(authoritative answer)”。该名字服务器是授权于该域的。
    let aa = flags.slice(5, 6);
    // TC(Truncation)是1bit字段，表示“可截断的(truncated)”。使用UDP时，它表示当应答的总长度超过512字节时，只返回前512个字节。
    let tc = flags.slice(6, 7);
    // RD(Recursion desired)是1bit字段表示“期望递归（recursion desired）”。该比特能在一个查询中设置，并在响应中返回。
    // 这个标志告诉名字服务器必须处理这个查询，也称为一个递归查询。
    // 如果该位为0，且被请求的名字服务器没有一个授权回答，它就返回一个能解答该查询的其他名字服务器列表，这称为迭代查询。
    let rd = flags.slice(7, 8);
    // RA(Recursion available)是1bit字段，表示“可用递归”。如果名字服务器支持递归查询，则在响应中将该比特设置为1。
    // 在后面的例子中可看到大多数名字服务器都提供递归查询，除了某些根服务器。
    let ra = flags.slice(8, 9);
    // Reserved 随后的3bit字段必须为0。
    let zero = flags.slice(9, 12);
    // rcode(Return code)是一个4bit的返回码字段。通常的值为0（没有差错）和3（名字差错）。
    // 名字差错只有从一个授权名字服务器上返回，它表示在查询中制定的域名不存在。
    let rcode = flags.slice(12, 16);
    debug('qr: %s, opcode: %s, aa: %s, tc: %s, rd: %s, ra: %s, zero: %s, rcode: %s', qr, opcode, aa, tc, rd, ra, zero, rcode);
    // end flags

    // 随后的4个16 bit字段说明最后4个变长字段中包含的条目数 。
    // 对于查询报文，问题(question)数通常是1，而其他3项则均为0。
    // 类似地，对于应答报文，回答数至少是1，剩下的两项可以是0或非0。
    // Question Resource Record count
    let questionRR = parseInt(headerBits.slice(32, 48).toString('hex'), 16);
    // Answer Resource Record count
    let answerRR = parseInt(headerBits.slice(48, 64).toString('hex'), 16);
    // Authority Resource Record count
    let authorityRR = parseInt(headerBits.slice(64, 80).toString('hex'), 16);
    // Additional Resource Record count
    let additionalRR = parseInt(headerBits.slice(80, 96).toString('hex'), 16);

    debug('questionRR: %s, answerRR: %s, authorityRR: %s, additionalRR: %s', questionRR, answerRR, authorityRR, additionalRR);
    // end header

    // start question
    let length = 0;
    let questions = [];
    for (let i = 0; i < questionRR; i++) {
        debug('----------[start question-%d]-----------', i + 1);
        // Question Name
        let questionName = [];

        while (pos < msg.length && 0 !== (length = msg[pos++])) {
            // debug('length: %d, pos: %d, question: %s', length, pos, msg.slice(pos, pos + length).toString('ascii'));
            questionName.push(msg.slice(pos, pos + length).toString('ascii'));
            pos += length;
        }
        debug('questionName: %s', questionName.join('.'));

        // Question Type
        // 16字节 2byte
        let questionType = msg.slice(pos, pos += 2).toString('hex');
        debug('questionType: %s', parseInt(questionType, 16));
        // Question Class
        // 16字节 2byte
        let questionClass = msg.slice(pos, pos += 2).toString('hex');
        debug('questionClass: %s', parseInt(questionClass, 16));

        questions.push({ questionName, questionType, questionClass });
        debug('-----------[end question-%d]------------', i + 1);
    }
    debug('questions: %O', questions);
    // end question

    // Answer Resource Record 
    let answers = [];
    for (let i = 0; i < answerRR; i++) {
        let rr = RR(msg, pos);
        pos = rr.pos;
        delete rr.pos;
        answers.push(rr);
    }
    debug('answers: %O', answers);

    // Authority Resource Record 
    let authorities = [];
    for (let i = 0; i < authorityRR; i++) {
        let rr = RR(msg, pos);
        pos = rr.pos;
        delete rr.pos;
        authorities.push(rr);
    }
    debug('authorities: %O', authorities);

    // Additional Resource Record
    let additionals = [];
    for (let i = 0; i < additionalRR; i++) {
        let rr = RR(msg, pos);
        pos = rr.pos;
        delete rr.pos;
        additionals.push(rr);
    }
    debug('additionals: %O', additionals);

    debug('msg: %s, pos: %d', msg.length, pos);

    // debug(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
});
server.on('listening', () => {
    const address = server.address();
    debug(`server listening ${address.address}:${address.port}`);
});

server.bind(53);