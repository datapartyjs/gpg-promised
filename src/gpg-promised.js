const GPG = require('gpg')
const GPGParser = require('./gpg-prarser')
const util = require('util')
const Address = require('email-addresses')
const debug = require('debug')('gpg-promised')

const exec = require('./shell').exec

class GPGPromised {
  constructor(homedir){
    this.homedir = homedir
  }
 

  async open(){

  }
  

  async call(input, args){
    return new Promise((resolve, reject)=>{

      GPG.call(input, args, (err, stdout, stderr)=>{
        if(err){ return reject(err) }

        resolve({
          stdout,
          stderr
        })
      })

    })
  }

  //callStreaming(){}

  async whoami(){
    const primary = await this.listSecretKeys(true)

    const handles = primary.map(rec=>{
      return rec.uid.email
    })

    if(handles.length < 1 || !handles[0]){
      throw new Error('no primary identity')
    }

    return handles
  }

  async listSecretKeys(ultimate=true){
    const command = ['--list-secret-keys', '--with-colons', '--with-fingerprint']
    const list = (await this.call('', command)).stdout.toString()

    return GPGParser.parseColons(list).filter((record)=>{
      return record.type == 'sec' && (!ultimate ? true : ( record.validity == 'u' ))
    })
  }

  async listPublicKeys(ultimate=false){
    const command = ['--list-public-keys', '--with-colons', '--with-fingerprint']
    const list = (await this.call('', command)).stdout.toString()

    return GPGParser.parseColons(list).filter((record)=>{
      return record.type == 'pub' && (!ultimate ? true : ( record.validity == 'u' ))
    })
  }

  async tar({cwd, outputPath, to, sign, encrypt, decrypt, extractPath, inputPaths}){
    
    const command = ['gpgtar']

    if(sign){ command.push('-s') }
    if(encrypt){ command.push('-e') }
    if(decrypt){
      command.push('-d')
      if(extractPath){ command.push(' --directory ' + extractPath) }
    }

    if(outputPath){ command.push(' --output ' + outputPath) }

    if(to){
      if(Array.isArray(to)){ command.push( to.map(t=>{return '-r '+t}).join(' ') ) }
      else{ command.push('-r '+to) }

      command.push( inputPaths.join(' ') )
    }

    const cmdStr = command.join(' ')

    debug('gpgtar - [', cmdStr, ']')
    return await exec(cmdStr, {cwd})
  }
}
