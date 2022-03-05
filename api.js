var fs = require('fs')
var http = require('http')
var https = require('https')
const express = require('express')
const app = express()
var cors = require('cors')
var bodyParser = require('body-parser');
const { exec } = require("child_process")
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
    `)
})
http.createServer(app).listen(port, () => {
    console.log(`Example app listening at http://shwifty.io/`)
})
exports.api = () => 'api js'
