// 参考：
// https://tools.ietf.org/html/rfc2136
// https://technet.microsoft.com/zh-cn/library/dd197470(v=ws.10).aspx
// 《TCP/IP详解卷1：协议》 第14章 DNS:域名系统
const _ = require('lodash');
const debug = require('debug')('dns');
const dgram = require('dgram');
const server = dgram.createSocket('udp4');

function pkgHeader(transactionId, flags, questionRRC, answerRRC, authorityRRC, additionalRRC) {
    debug('--------------[pkgHeader %d]------------------', transactionId);
    // check flags
    // transactionId
    let transactionIdBuf = Buffer.alloc(2);
    transactionIdBuf.writeUInt16BE(transactionId);

    // flags
    let flagsBuf = Buffer.alloc(2);
    flagsBuf.writeUInt16BE(parseInt(flags.qr + flags.opcode + flags.aa + flags.tc + flags.rd + flags.ra + flags.zero + flags.rcode, 2));

    // questionRRC 16bit
    let questionRRCBuf = Buffer.alloc(2);
    questionRRCBuf.writeUInt16BE(questionRRC);
    // answerRRC 16bit
    let answerRRCBuf = Buffer.alloc(2);
    answerRRCBuf.writeUInt16BE(answerRRC);
    // authorityRRC 16bit
    let authorityRRCBuf = Buffer.alloc(2);
    authorityRRCBuf.writeUInt16BE(authorityRRC);
    // additionalRRC 16bit
    let additionalRRCBuf = Buffer.alloc(2);
    additionalRRCBuf.writeUInt16BE(additionalRRC);

    return Buffer.concat([transactionIdBuf, flagsBuf, questionRRCBuf, answerRRCBuf, authorityRRCBuf, additionalRRCBuf]);
}

function unpkgHeader(msg) {
    debug('--------------[unpkgHeader %s]------------------', msg.toString('hex'));
    // check
    // msg.length 12 byte
    let offset = 0;
    let transactionId = msg.readUInt16BE(offset);
    offset += 2;
    debug('transactionId: %d, transactionId(hex): 0x%s', transactionId, transactionId.toString(16));

    let flags = {};
    let flagsDecimal = msg.readUInt16BE(offset);
    offset += 2;
    let flagsBits = _.padStart(flagsDecimal.toString(2), 16, '0');
    debug('flagsBits: %s', flagsBits);
    // QR(Request/response)是1bit字段：0表示查询报文，1表示响应报文。
    flags.qr = flagsBits.slice(0, 1);
    // opcode是一个4bit字段：通常值为0（标准查询），其他值为1（反向查询）和2（服务器状态请求）。
    flags.opcode = flagsBits.slice(1, 5);
    // AA(Authoritative answer)是1bit标志，表示“授权回答(authoritative answer)”。该名字服务器是授权于该域的。
    flags.aa = flagsBits.slice(5, 6);
    // TC(Truncation)是1bit字段，表示“可截断的(truncated)”。使用UDP时，它表示当应答的总长度超过512字节时，只返回前512个字节。
    flags.tc = flagsBits.slice(6, 7);
    // RD(Recursion desired)是1bit字段表示“期望递归（recursion desired）”。该比特能在一个查询中设置，并在响应中返回。
    // 这个标志告诉名字服务器必须处理这个查询，也称为一个递归查询。
    // 如果该位为0，且被请求的名字服务器没有一个授权回答，它就返回一个能解答该查询的其他名字服务器列表，这称为迭代查询。
    flags.rd = flagsBits.slice(7, 8);
    // RA(Recursion available)是1bit字段，表示“可用递归”。如果名字服务器支持递归查询，则在响应中将该比特设置为1。
    // 在后面的例子中可看到大多数名字服务器都提供递归查询，除了某些根服务器。
    flags.ra = flagsBits.slice(8, 9);
    // Reserved 随后的3bit字段必须为0。
    flags.zero = flagsBits.slice(9, 12);
    // rcode(Return code)是一个4bit的返回码字段。通常的值为0（没有差错）和3（名字差错）。
    // 名字差错只有从一个授权名字服务器上返回，它表示在查询中制定的域名不存在。
    flags.rcode = flagsBits.slice(12, 16);
    debug('flags %o', flags);
    // end flags

    // 随后的4个16 bit字段说明最后4个变长字段中包含的条目数 。
    // 对于查询报文，问题(question)数通常是1，而其他3项则均为0。
    // 类似地，对于应答报文，回答数至少是1，剩下的两项可以是0或非0。
    // Question Resource Record count
    let questionRRC = msg.readUInt16BE(offset);
    offset += 2;
    // Answer Resource Record count
    let answerRRC = msg.readUInt16BE(offset);
    offset += 2;
    // Authority Resource Record count
    let authorityRRC = msg.readUInt16BE(offset);
    offset += 2;
    // Additional Resource Record count
    let additionalRRC = msg.readUInt16BE(offset);

    debug('questionRRC: %s, answerRRC: %s, authorityRRC: %s, additionalRRC: %s', questionRRC, answerRRC, authorityRRC, additionalRRC);
    // end header

    return {
        transactionId,
        flags,
        questionRRC,
        answerRRC,
        authorityRRC,
        additionalRRC
    }
}

function pkgQuestion(question, type, clazz) {
    debug('--------------[pkgQuestion (%s, %d, %d)]------------------', question, type, clazz);
    // check
    // question name.length < 63
    // check type 
    // check clazz

    // example.com [7][e][x][a][m][p][l][e][3][c][o][m][0]
    let questionBuf = Buffer.alloc(question.length + 2, 0, 'ascii');
    let names = question.split('.');
    let offset = 0;
    for (let name of names) {
        questionBuf.writeUInt8(name.length, offset);
        offset++;
        questionBuf.write(name, offset);
        offset += name.length;
    }
    questionBuf.writeUInt8(0, offset);

    let typeBuf = Buffer.alloc(2);
    typeBuf.writeUInt16BE(type);

    let clazzBuf = Buffer.alloc(2);
    clazzBuf.writeUInt16BE(clazz);

    return Buffer.concat([questionBuf, typeBuf, clazzBuf]);
}

function unpkgQuestion(msg, offset) {
    debug('--------------[unpkgQuestion %d]------------------', offset);
    let pointer = offset;
    let _length = 0;
    // Question Name
    let names = [];
    while (offset < msg.length && 0 !== (_length = msg[offset++])) {
        names.push(msg.slice(offset, offset + _length).toString('ascii'));
        offset += _length;
    }

    debug('name: %s', names.join('.'));

    // Question Type 16字节 2byte
    let type = msg.readUInt16BE(offset);
    offset += 2;
    debug('type: %d, type(hex): 0x%s', type, type.toString(16));

    // Question Class 16字节 2byte
    let clazz = msg.readUInt16BE(offset);
    offset += 2;
    debug('class: %d, class(hex): 0x%s', clazz, clazz.toString(16));

    return { names, type, clazz, pointer, offset, name: names.join('.') };
}

function pkgRR(questions, ttl, rdd, encoding = 'utf8') {
    debug('--------------[pkgRR]------------------');

    // answers
    let questionBufs = [];
    // 可以采用压缩形式 c0 0c 1100000000001100 前两位11表示压缩，后14位的二进制数表示指针位置(00000000001100 十进制形式12，头部长12)
    for (let question of questions) {
        questionBufs.push(pkgQuestion(question.name, question.type, question.clazz));
    }

    // ttl 
    let ttlBuf = Buffer.alloc(4);
    ttlBuf.writeUInt32BE(ttl);

    if (typeof rdd === 'string') rdd = Buffer.from(rdd, encoding);

    // rdl
    let rdlBuf = Buffer.alloc(2);
    rdlBuf.writeUInt16BE(rdd.length);

    return Buffer.concat([...questionBufs, ttlBuf, rdlBuf, rdd]);
}

function unpkgRR(msg, offset) {
    debug('--------------[unpkgRR %d]------------------', offset);
    // Resource Record Name
    let rrName = [];
    let _length = 0;
    // 首字母00表示压缩
    if ((msg.readUInt8(offset) & 0b11000000) === 0b11000000) {
        let _offset = msg.readUInt16BE(offset) & 0b00111111;
        while (_offset < msg.length && 0 !== (_length = msg[_offset++])) {
            rrName.push(msg.slice(_offset, _offset + _length).toString('ascii'));
            _offset += _length;
        }
        offset += 2;
    } else {
        while (offset < msg.length && 0 !== (_length = msg[offset++])) {
            rrName.push(msg.slice(offset, offset + _length).toString('ascii'));
            offset += _length;
        }
    }
    debug('rrName: %s', rrName.join('.'));

    // Resource Record Type
    // 16字节 2byte
    let rrType = msg.readUInt16BE(offset);
    // msg.slice(offset, offset += 2).toString('hex');
    offset += 2;
    debug('rrType: %s', rrType);

    // Resource Record Class
    // 16字节 2byte
    let rrClass = msg.readUInt16BE(offset);
    offset += 2;
    debug('rrClass: %s', rrClass);

    // Time-to-Live
    let ttl = msg.readUInt32BE(offset);
    offset += 4;
    debug('ttl: %d', ttl);

    // Resource Data Length
    let rdl = msg.readUInt16BE(offset);
    offset += 2;
    debug('rdl: %d', rdl);

    let rd;
    if (rdl > 0) {
        rd = msg.slice(offset, offset += rdl);
        // TODO 解析不同类型的RR数据
        // A 地址
        if (rrType === 1) {
            debug('rdd: %s', `${rd.readUInt8(0)}.${rd.readUInt8(1)}.${rd.readUInt8(2)}.${rd.readUInt8(3)}`)
        } if (rrType === 5) {
            
        } else {
            debug('rdd: %s', rd.toString('ascii'));
        }
    }

    return {
        rrName,
        rrType,
        rrClass,
        ttl,
        rdl,
        rd,
        offset
    }
}

function unpkgdns(msg) {
    debug('--------------[unpkgdns %s]------------------', msg.toString('hex'));

    let header = unpkgHeader(msg.slice(0, 12));
    // start question
    let offset = 12;
    let questions = [];
    for (let i = 0; i < header.questionRRC; i++) {
        let question = unpkgQuestion(msg, offset);
        offset = question.offset;
        questions.push(question);
    }
    debug('questions: %o', questions);
    // end question

    // Answer Resource Record 
    let answers = [];
    for (let i = 0; i < header.answerRRC; i++) {
        let rr = unpkgRR(msg, offset);
        offset = rr.offset;
        answers.push(rr);
    }
    debug('answers: %o', answers);

    // Authority Resource Record 
    let authorities = [];
    for (let i = 0; i < header.authorityRRC; i++) {
        let rr = unpkgRR(msg, offset);
        offset = rr.offset;
        authorities.push(rr);
    }
    debug('authorities: %o', authorities);

    // Additional Resource Record
    let additionals = [];
    for (let i = 0; i < header.additionalRRC; i++) {
        let rr = unpkgRR(msg, offset);
        offset = rr.offset;
        additionals.push(rr);
    }
    debug('additionals: %o', additionals);

    return { header, questions, answers, authorities, additionals };
}

server.on('error', (err) => {
    debug(`server error:\n${err.stack}`);
    server.close();
});

server.on('message', (msg, rinfo) => {
    let { header, questions, answers, authorities, additionals } = unpkgdns(msg);

    // -------------------------------------

    // Transaction ID
    let resTransactionId = header.transactionId;
    let resflags = _.merge(header.flags, { qr: '1', tc: 0 });
    let resQuestionRRC = header.questionRRC;
    let resAnswerRRC = 1;
    let resAuthorityRRC = 0;
    let resAdditionalRRC = 0;
    let resHeader = pkgHeader(resTransactionId, resflags, resQuestionRRC, resAnswerRRC, resAuthorityRRC, resAdditionalRRC);

    // questions
    // TODO 记录question name pointer
    let resQuestions = [];
    for (let question of questions) {
        resQuestions.push(pkgQuestion(question.name, question.type, question.clazz));
    }

    let resAnswers = [];
    for (let i = 0; i < resAnswerRRC; i++) {
        resAnswers.push(pkgRR(questions, 30, Buffer.from([110, 110, 110, i])))
    }

    let resAuthorities = [];
    for (let i = 0; i < resAuthorityRRC; i++) {
        // TODO
    }

    let resAdditionals = [];
    for (let i = 0; i < resAdditionalRRC; i++) {
        // TODO
    }

    let res = Buffer.concat([resHeader, ...resQuestions, ...resAnswers, ...resAuthorities, ...resAdditionals]);
    server.send(res, rinfo.port, rinfo.address);
});

server.on('listening', () => {
    const address = server.address();
    debug('server listening %s:%d', address.address, address.port);
});

// server.bind(53);

let msg = Buffer.from('15a9818000010003000000010377777705626169647503636f6d0000010001c00c000500010000045e000f0377777701610673686966656ec016c02b00010001000000da0004b4958497c02b00010001000000da0004b49583620000291000000000000000', 'hex');
console.log('msg: %O', unpkgdns(msg));
