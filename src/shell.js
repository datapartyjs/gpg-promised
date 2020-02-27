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
    
    if(input){
      if(input instanceof Buffer){
        child.stdin.end(input)
      }
      else{
          
        verbose('exec input', input)
        let inputs = input.split('\n')

        if(inputs[inputs.length-1] == null){
          inputs = inputs.slice(0, inputs.length-1)
        }
        if(inputs.length == 0 && input.indexOf('\n') < 0 ){
          inputs = [input]
        }

        for(let i of inputs){
          debug('writing -', i)
          child.stdin.write(i+'\n')  
        }

        child.stdin.end()
      }
    }
    else{
      child.stdin.end()
    }
    
    
  })
  .catch(err=>{throw err})

  return promise
}