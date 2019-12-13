const fork = require('child_process').fork
const exec = require('child_process').exec
const debug = require('debug')('shell')
const verbose = require('debug')('verbose.shell')

exports.fork = async function(path, args, opts={}){
  debug('fork -', args)
  let promise = await new Promise((resolve,reject)=>{


    let child = fork(path, args)

    child.on('message', (msg)=>{resolve(msg)} )

    
  })
  .catch(err=>{throw err})

  return await promise
}

exports.exec = async function(cmd, opts={}, input){
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