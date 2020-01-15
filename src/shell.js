const exec = require('child_process').exec
const debug = require('debug')('shell')
const verbose = require('debug')('verbose.shell')



/**
 * Result of exec
 * @typedef {Object} ExecResult
 * @property {string} stdout Stdout content
 * @property {string} stderr Stderr content
 */

exports.exec = async function(cmd, opts={encoding: 'buffer', maxBuffer: 1024*1024*512}, input){
  debug('exec -', cmd)
  let promise = await new Promise((resolve,reject)=>{


    let child = exec(cmd, opts, (err, stdout, stderr)=>{
      debug('err', err)
      verbose('stderr', stderr)
      verbose('stdout', stdout)

      if(err){
        err.stdout = stdout
        err.stderr = stderr
        
        reject(err)
        return
      }

      resolve({ stdout, stderr })
    })
    
    verbose('exec input', input)
    child.stdin.end(input)
    
  })
  .catch(err=>{throw err})

  return promise
}