const {exec, spawn} = require('child_process')
const debug = require('debug')('shell')
const verbose = require('debug')('verbose.shell')
const kill = require('tree-kill')

class GpgAgent {
  constructor(homedir){
    this.stopped = false
    this.homedir = homedir
    this.cmd = 'gpg-agent' //, /*'--use-standard-socket',*/ '--supervised']

    this.realpid = null

    this._waitForPid = null

    this.args = []

    if(this.homedir){
      this.args.push('--homedir')
      this.args.push(this.homedir)
    }

    this.args.push('--no-detach')
    this.args.push('--daemon')
    this.args.push('--batch')

    //this.cmd = this.cmd.join(' ')
    this.child = null
  }

  isRunning(){
    return this.child != null && !this.stopped
  }


  async waitForPid(){
    if(this.realpid != null){
      return
    }

    return this._waitForPid
  }

  async start(){

    if(this.child != null){
      throw new Error('already started')
    }

    debug('starting gpg-agent [',this.cmd,']')

    this.child = spawn(this.cmd, this.args, {
      detached: false,
      //stdio: 'inherit'
    } /*{
      encoding: 'buffer',
      maxBuffer: 1024*1024*512
    }, (err,stdout, stderr)=>{
      debug('gpg-agent stopped')
      debug(stdout.toString())
      debug(stderr.toString())
      this.stopped = true
    }*/)

    this._waitForPid = new Promise((resolve, reject)=>{

      let handleEarlyClose = ()=>{
        this.stopped = true
        reject(new Error('closed early, before pid'))
      }

      let handleErrorOutput = (data)=>{
        let lines = data.toString().trim().split('\n')
    
        for(let line of lines){
  
          if(line.indexOf('gpg-agent[')!=-1 && line.indexOf('start')!=-1){
            let start = line.indexOf('[')
            let end = line.indexOf(']')
  
            let pidString = line.substring(start+1, end)
  
            this.realpid = parseInt(pidString)
  
            debug('gpg-agent pid -', pidString)
            
            this.child.stderr.off('data', handleErrorOutput)
            this.child.off('close', handleEarlyClose)
            resolve()
            break
          }
        }
      }
  
      this.child.stderr.on('data', handleErrorOutput)
      this.child.on('close', handleEarlyClose)
    })

    this.child.stdout.on('data',(data)=>{
      debug('gpg-agent-out', data.toString())
    })

    

    this.child.once('close', ()=>{
      debug('stopped')
      this.stopped = true
    })

    return this._waitForPid

    /*return new Promise((resolve, reject)=>{

      setTimeout(()=>{
        if(this.stopped){
          reject()
        } else {

          debug('running')
          //this.child.unref()

          resolve()
        }

      }, 500)
    })*/
  }

  async stop(){

    debug('stopping gpg-agent')

    if(this.stopped){
      return
    }

    
    return new Promise((resolve,reject)=>{
      
      this.child.once('close', ()=>{
        
        debug('closed')
        this.stopped = true
        //resolve()
      })
      
      debug('killing', this.child.pid)
      
      kill(this.realpid, (err)=>{
        if(err){
          reject(err)
        } else {
          resolve()
        }
      })


    })

  }
}

exports.GpgAgent = GpgAgent


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

        if(inputs[inputs.length-1] == ''){
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