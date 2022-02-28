'use strict';

const api = require('./api.js')
let ret
let {PythonShell} = require('python-shell')
PythonShell.runString('x=1+10;print(x)', null, function (err, res) {
  if (err) throw err;
  console.log('finished', res);
  ret = res
  console.log('connecting python serialization with js / json api', api.api(), ret)
  return ret
});
PythonShell.run('api.py', null, function (err, res) {
  if (err) throw err;
  console.log('finished', res);
});
