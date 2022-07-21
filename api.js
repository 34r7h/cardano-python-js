var fs = require('fs')
var http = require('http')
var https = require('https')
const express = require('express')
const app = express()
const cors = require('cors');
var bodyParser = require('body-parser');
const { exec } = require("child_process")
let { PythonShell } = require('python-shell')
const crypto = require("crypto-js");
app.use(cors())
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
let dev = process.env.PORT && true
const port = process.env.PORT || 80
const portssl = 443
const format = {
    stringify(cipherParams) {
        // create json object with ciphertext
        var jsonObj = { ct: cipherParams.ciphertext.toString(crypto.enc.Hex) };

        // optionally add iv or salt
        if (cipherParams.iv) {
            jsonObj.iv = cipherParams.iv.toString();
        }

        if (cipherParams.salt) {
            jsonObj.s = cipherParams.salt.toString();
        }
        // stringify json object
        return jsonObj.ct + '_' + jsonObj.iv + '_' + jsonObj.s;
    },
    parse(jsonStr) {
        // parse json string
        let encarray = jsonStr.split('_')
        // console.log('parsing it out', encarray);
        // var jsonObj = JSON.parse(jsonStr);

        // extract ciphertext from json object, and create cipher params object
        var cipherParams = crypto.lib.CipherParams.create({
            ciphertext: crypto.enc.Hex.parse(encarray[0])
        });

        // optionally extract iv or salt

        if (encarray[1]) {
            cipherParams.iv = crypto.enc.Hex.parse(encarray[1]);
        }

        if (encarray[2]) {
            cipherParams.salt = crypto.enc.Hex.parse(encarray[2]);
        }
        return cipherParams;
    }
}

const methods = {
    encryptphrase(phrase, pass) {
        if (!pass) { const pass = fs.readFileSync(`./keys/encryptedkeys.secret`, { encoding: 'utf8', flag: 'r' }) }
        const encrypted = crypto.AES.encrypt(phrase, pass, { format });
        // fs.writeFileSync('./crypto.hash', encrypted.toString())
        return encrypted.toString();
    },
    decryptphrase(emsg, pass) {
        if (!pass) { const pass = fs.readFileSync(`./keys/encryptedkeys.secret`, { encoding: 'utf8', flag: 'r' }) }
        // console.log('wait', {emsg, pass});
        const decrypted = crypto.AES.decrypt(emsg, pass, { format });
        // console.log({d: decrypted.toString(crypto.enc.Utf8)});
        return decrypted.toString(crypto.enc.Utf8);
    },

}

console.log('must arrange endpoints, describe required data structures, etc ')
app.get('/', (req, res) => {
    let obj = '<ul>'
    // Object.entries(docs).map(z => {
    //     obj += `<li style=" align-items:center;"><b>${z[0]}</b><br><br>`
    //     obj += '<div style="overflow-wrap: anywhere;">Example<br><a href="' + encodeURI(z[1].example) + '">' + z[1].example + '</a></div><br>'
    //     obj += Object.keys(api).includes(z[0].replace('-', '')) ? `Code<br><code style="font: 12px mono; white-space: pre-wrap; background: rgba(0,0,0,.03); padding: 8px">` + api[z[0].replace('-', '')].toString() + `</code><br>` : ''
    //     obj += '<br></li>'
    // })

    let ret
    // PythonShell.runString('x=1+10;print(x)', null, function (err, resp) {
    // if (err) throw err;
    // console.log('finished', resp);
    // ret = resp
    // console.log('connecting python serialization with js / json api', ret)
    // return ret
    // });

    // working example
    // let pyshell = new PythonShell('python/api.py');
    // pyshell.send('getaddress')
    // pyshell.on('message', (msg, err)=>{
    //     console.log('incoming message from api.py', err, msg, typeof msg);
    //     return res.send(msg)
    // })
    // return pyshell.end(function (err,code,signal) {
    //     if (err) throw err;
    //     console.log('The exit code was: ' + code);
    //     console.log('The exit signal was: ' + signal);
    //     console.log('finished');
    //   });
    // console.log({pyshell});
    // 
    // return PythonShell.run('python/api.py', null, function (err, resp) {
    // if (err) throw err;
    // console.log('finished', resp);
    const API = {
        'create keys': '/createkeys?password=swordfish',
        'get address': 'getaddress'
    }
    apistring = ''
    Object.entries(API).forEach(x => apistring = apistring + `<div><a href="${x[1]}">${x[0]}</a><div>`)

    return res.send(`
    ${apistring}
    <h1>OK start api again</h1>
    <div>Let's be realistic this time and only expose what's useful and necessary!</div>
    <p>First, about keys.. currently we have hard keys on the server. We need to encrypt these with a symmetrical key delivered from the cloud server.</p>
    <ol>
        <li>QR Codes </li>
        <li>Minting NFT</li>
        <li>Listing NFT</li>
        <li>Selling NFT</li>
        <li>Create Transaction</li>
        <li>Submit Transaction</li>
        <li>Encrypt Message</li>
        <li>Decrypt Message</li>
        <li>Sign Message</li>
        <li>Verify Message</li>
    </ol>`)
    // `+ resp)
    // });

})
app.get('/network-info', (req, res) => {
    console.log('network-info');
    return res.send('ok')
})
app.post('/updateapp', (req, res) => {
    console.log('WARNING: Dangerously exposing git pull for dev convenience.. e.g. VSCode remote SSH is still Microsoft. Please remove for production.');
    const { exec } = require('child_process');

    exec('git pull', (err, stdout, stderr) => {
        // handle err, stdout & stderr
        console.log({ err, stdout, stderr })
    });
})
app.post('/createkeys', (req, res) => {
    // REQUIRES: req.body.passhash
    console.log('creating keys crypto', { body: req.body });
    return PythonShell.run('python/createkeys.py', null, function (err, resp) {
        dev && console.log({ resp, err });
        let keys = JSON.parse(resp[0].replace(/'/g, '"'))
        const stakevkey = keys.stake.signing.cborHex
        // TODO revisit encryption scheme.. why using stake signing key?
        const encryptedkeys = methods.encryptphrase(JSON.stringify(keys), req.body.passhash + stakevkey)
        var hash = crypto.SHA256(req.body.passhash + stakevkey);
        return fs.writeFile(`./keys/${hash}.secret`, encryptedkeys, function (err) {
            if (err) {
                return console.log(err);
            }
            dev && console.log("The file was saved!");
            dev && console.log('returning', { encryptedkeys, verification: stakevkey + '' });
            return res.send({ encryptedkeys, verification: stakevkey + '' })
        });
    })
})
app.post('/getaddress', (req, res) => {
    // REQUIRES: req.query.password
    console.log('getaddress crypto', req.body);
    const fs = require('fs');
    let secret
    var hash = crypto.SHA256(req.body.passhash + req.body.key);
    console.log({ hash: hash + '' });
    fs.readFile(`./keys/${hash + ''}.secret`, 'utf8', (err, data) => {
        console.log({ data, err });
        if (err) {
            console.error(err);
            return;
        }
        secret = methods.decryptphrase(data, req.body.passhash + req.body.key)
        // console.log({ data, secret }, typeof JSON.parse(secret));
        const options = {
            args: secret
        }
        // console.log({secret});
        return PythonShell.run('python/getaddress.py', options, function (err, resp) {
            // console.log({ resp, err });
            return res.send(resp[0])
        })
        // return res.send('ok')
    });
})

app.get('/test', (req, res) => {
    console.log('testing');
    let pyshell = new PythonShell('python/test.py');
    const options = {
        args: ['value1', 'value2', 'value3']
    }
    PythonShell.run('python/test.py', options, function (err, resp) {
        console.log({ resp });
        JSON.parse(resp[0]).map(x => console.log(x))
        return res.send('ok ' + JSON.parse(resp[0]));
    })
    return pyshell.end(function (err, code, signal) {
        if (err) throw err;
        console.log('The exit code was: ' + code);
        console.log('The exit signal was: ' + signal);
        console.log('finished');
    });
})
app.get('/encrypt', (req, res) => {
    let enc = methods.encryptphrase(JSON.stringify(req.query.msg), req.query.password)
    return res.send(enc);
})
app.get('/decrypt', (req, res) => {
    let dec = methods.decryptphrase(JSON.parse(req.query.msg), req.query.password)
    return res.send(dec);
})
app.post('/mint', (req, res) => {
    console.log({ minting: req.body });
    const fs = require('fs');
    let secret
    var hash = crypto.SHA256(req.body.passhash + req.body.key);
    fs.readFile(`./keys/${hash + ''}.secret`, 'utf8', (err, data) => {
        // console.log({ data, err });
        if (err) {
            console.error(err);
            return;
        }
        secret = methods.decryptphrase(data, req.body.passhash + req.body.key)
        // console.log({ secret }, typeof JSON.parse(secret));
        const options = {
            args: [secret, req.body.data, req.body.bf]
        }
        // console.log('\n\n',JSON.stringify(options), '\n\n')
        let bodydata = JSON.parse(req.body.data)
        return PythonShell.run('python/mint.py', options, function (err, resp) {
            console.log(typeof bodydata.submit, bodydata.submit,'Crypto API Return', { resp, err });
            return res.send((resp && resp[0]) || err)
        })
    });
    
    
    
    // fs.readFile('./keys/encryptedkeys.secret', 'utf8', (err, data) => {
    //     if (err) {
    //         console.error(err);
    //         return;
    //     }
    //     if (!req.query.password) {
    //         req.query.password = 'swordfish'
    //     }

    //     secret = methods.decryptphrase(data, req.query.password)
    //     console.log({ data, secret }, typeof JSON.parse(secret));
    //     const options = {
    //         args: [req.query.address, req.query.data, req.query.bf]
    //     }
    //     return PythonShell.run('python/mint.py', options, function (err, resp) {
    //         console.log({ resp });
    //         return res.send(resp);
    //     })
    // });
})
app.post('/createtx', (req, res) => {
    console.log('creating tx', req.body);
    const fs = require('fs');
    let secret
    var hash = crypto.SHA256(req.body.passhash + req.body.key);
    fs.readFile(`./keys/${hash + ''}.secret`, 'utf8', (err, data) => {
        // console.log({ data, err });
        if (err) {
            console.error(err);
            return;
        }
        secret = methods.decryptphrase(data, req.body.passhash + req.body.key)
        // console.log({ secret }, typeof JSON.parse(secret));
        const options = {
            args: [secret, req.body.data, req.body.bf]
        }
        console.log('\n\n',JSON.stringify(options), '\n\n')
        let bodydata = JSON.parse(req.body.data)
        return PythonShell.run('python/tx.py', options, function (err, resp) {
            console.log(typeof bodydata.submit, bodydata.submit,'Crypto API Return', { resp, err });
            if (!bodydata.submit) {
                console.log('No Submit', typeof resp[0], JSON.parse(resp[0]));
                const returnarray = JSON.parse(resp[0])
                const encryptedtx = methods.encryptphrase(returnarray[1], req.body.passhash)
                let ret = [returnarray[0], encryptedtx]
                return res.send(JSON.stringify(ret) || err)
            } else {
                return res.send((resp && resp[0]) || err)
            }
        })
    });
})

app.post('/sign', (req, res) => {
    console.log('signing');
    return PythonShell.run('python/sign.py', null, function (err, resp) {
        return res.send('ok ' + resp);
    })
})
app.post('/validate', (req, res) => {
    console.log('validating');
    return PythonShell.run('python/validate.py', null, function (err, resp) {
        return res.send('ok ' + resp);
    })
})
app.post('/submit', (req, res) => {
    // {cbor, bf, passhash}
    console.log('submit');
    tx = methods.decryptphrase(req.body.cbor, req.body.passhash)
    const options = {
        args: [tx, req.body.bf]
    }
    console.log({options});
    return PythonShell.run('python/submit.py', options, function (err, resp) {
        console.log({resp});
        return res.send(resp);
    })
})
http.createServer(app).listen(port, () => {
    console.log(`Example app listening at http://shwifty.io/`)
})
exports.api = () => 'api js'
