var fs = require('fs')
var http = require('http')
var https = require('https')
const express = require('express')
const app = express()
var cors = require('cors')
var bodyParser = require('body-parser');
const { exec } = require("child_process")
let {PythonShell} = require('python-shell')
app.use(cors())
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
const port = 80
const portssl = 443

console.log('must arrange endpoints, describe required data structures, etc ')
app.get('/', (req, res) => {
    let obj = '<ul>'
    // Object.entries(docs).map(z => {
    //     obj += `<li style=" align-items:center;"><b>${z[0]}</b><br><br>`
    //     obj += '<div style="overflow-wrap: anywhere;">Example<br><a href="' + encodeURI(z[1].example) + '">' + z[1].example + '</a></div><br>'
    //     obj += Object.keys(api).includes(z[0].replace('-', '')) ? `Code<br><code style="font: 12px mono; white-space: pre-wrap; background: rgba(0,0,0,.03); padding: 8px">` + api[z[0].replace('-', '')].toString() + `</code><br>` : ''
    //     obj += '<br></li>'
    // })
    let pyshell = new PythonShell('python/api.py');
    pyshell.send('hello')
    pyshell.on('message', ()=>{
        return 'ok message hello'
    })

    let ret
    PythonShell.runString('x=1+10;print(x)', null, function (err, resp) {
    if (err) throw err;
    console.log('finished', resp);
    ret = resp
    console.log('connecting python serialization with js / json api', ret)
    return ret
    });
    return  ('python/api.py', null, function (err, resp) {
    if (err) throw err;
    console.log('finished', resp);
    return res.send(`
    <h1>OK start api again</h1>
    <div>Let's be realistic this time and only expose what's useful and necessary!</div>
    <ol>
        <li>QR Codes</li>
        <li>Minting NFT</li>
        <li>Listing NFT</li>
        <li>Selling NFT</li>
        <li>Create Transaction</li>
        <li>Submit Transaction</li>
        <li>Encrypt Message</li>
        <li>Decrypt Message</li>
        <li>Sign Message</li>
        <li>Verify Message</li>
    </ol>
    `+ resp)
    });
    
})
app.post('/mint', (req, res) => {
    console.log('minting');
    return PythonShell.run('python/mint.py', null, function (err, resp) {
        return res.send('ok ' + resp);
    })
})
app.post('/createtx', (req, res) => {
    console.log('creating tx');
    return PythonShell.run('python/createtx.py', null, function (err, resp) {
        return res.send('ok ' + resp);
    })
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
http.createServer(app).listen(port, () => {
    console.log(`Example app listening at http://shwifty.io/`)
})
exports.api = () => 'api js'
