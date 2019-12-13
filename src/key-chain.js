const fs = require('fs')
const tmp = require('tmp')
const path = require('path')
const mkdirp = require('mkdirp')
const Hoek = require('@hapi/hoek')

const GPGParser = require('./gpg-parser')
const KeyServerClient = require('./key-server-client')

const debug = require('debug')('gpg-promised.KeyChain')

const DEFAULT_AGENT_CONFIG=`enable-ssh-support
default-cache-ttl 1800
max-cache-ttl 7200
`

const exec = require('./shell').exec

class KeyChain {
  constructor(homedir){
    this.homedir = homedir
    this.temp = null
  }


  async open(){

    if(!this.homedir){
      //use temp directory
      this.temp = tmp.dirSync()
      this.homedir = this.temp.name
      debug('using temp directory -', this.temp.name)
    }

    if(!path.isAbsolute(this.homedir)){
      throw new Error('path must be absolute')
    }

    if(!fs.existsSync(this.homedir)){
      debug('creating dir -', this.homedir)
      //create directory

      mkdirp.sync(this.homedir, '0700' )
    }

    if(!fs.existsSync(this.homedir + '/gpg-agent.conf')){
      debug('write default gpg-agent.conf')
      fs.writeFileSync(this.homedir + '/gpg-agent.conf', DEFAULT_AGENT_CONFIG)
    }
  }

  async hasCard(){
    
    try{
      const cardStatus = await this.cardStatus()
    }
    catch(err){
      return false
    }

    return true
  }

  async isCardTrusted(){
    
    if(! (await this.hasCard()) ){
      throw new Error('Insert card')
    }

    const cardStatus = await this.cardStatus()
    const fingerprint = (cardStatus.fpr[0] || '').toLowerCase()

    debug('cardStatus',cardStatus)

    const secrets = await this.listSecretKeys(true)
    debug(JSON.stringify( secrets, null, 2) )

    const cardKey = KeyChain.getKeyBySubKeyId(secrets, fingerprint)
    debug('cardKey', cardKey)

    if(!cardKey){
      return false
    }

    const match = KeyChain.isKeyFromCard(cardKey, cardStatus)

    if(!match){
      throw new Error('Card does not match secret key')
    }

    return true
  }

  async trustCard(){
    
    if(await this.isCardTrusted()){
      debug('card already trusted')
      return
    }

    const cardStatus = await this.cardStatus()
    const subFingerprint = (cardStatus.fpr[0] || '').toLowerCase()

    debug('card status', cardStatus)
    debug('sub fpr', subFingerprint)

    await this.recvKey(subFingerprint)

    const publics = await this.listPublicKeys()
    const cardKey = KeyChain.getKeyBySubKeyId(publics, subFingerprint, 'sub')

    if(!cardKey){ throw new Error('Card key not found') }

    const fingerprint = Hoek.reach(cardKey.fpr, '0.user_id')

    if(!fingerprint){ throw new Error('Could not find key by subkey fingerprint', subFingerprint) }

    debug('fpr', fingerprint)

    await this.trustKey(fingerprint, '6')

  }

  async trustKey(keyId, level){
    debug('trust', keyId, level)
    const command = ['--import-ownertrust', ]

    const existingTrust = (await this.call('', ['--export-ownertrust'])).stdout.toString()

    const trust = '' + existingTrust + keyId+':' +level+ ':\n'

    const list = (await this.call(trust, command)).stdout.toString()

    
    debug(list)

    debug('trust = ', trust)
  }

  async lookupKey(text){
    const hkpClient = new KeyServerClient()
    
    const result = await hkpClient.search(text)

    if(result.length > 1 && result[0].type == 'info'){
      return result[1]
    }

    return result
  }

  async recvKey(fingerprint){
    const command = ['--keyserver', 'hkps://keyserver.ubuntu.com:443', '--recv-keys', fingerprint]
    const list = (await this.call('', command)).stdout.toString()

    const status = GPGParser.parseReaderColons(list)
    debug('recv data', status)
  }

  async cardStatus(){
    const command = ['--card-status', '--with-colons', '--with-fingerprint']
    const list = (await this.call('', command)).stdout.toString()

    const status = GPGParser.parseReaderColons(list)
    debug('card status', status)
    return status
  }

  async call(input, args, nonbatch=false){
    const gpgArgs = ['--homedir', this.homedir, (nonbatch!=true) ? '--batch' : undefined  ].concat(args)

    debug('call -', gpgArgs)
    const result = await exec('gpg '+gpgArgs.join(' '), undefined, input)

    return result
  }

  async encrypt(input, to, from, trust='pgp'){
    const command = ['--encrypt', '--sign', '--armor', '--trust-model', trust]

    if(from){
      command.push('--local-user')
      command.push(from)
    }

    if(to && to.length>0){
      to.map( id=>{
        command.push('--recipient')
        command.push(id)
      })
    }


    const result = (await this.call(input, command)).stdout.toString()

    debug('enc data', result)
    return result
  }

  async decrypt(input){
    const command = ['--decrypt']

    const result = (await this.call(input, command)).stdout.toString()

    debug('enc data', result)
    return result
  }

  async verify(input, sender){
    throw new Error('not implemented')
    //const command = ['--logger-fd', '1', '--verify']
    const command = ['--list-packets']

    const result = (await this.call(input, command, true)).stdout.toString()

    debug('verify data', result)
    return result
  }

  async whoami(){
    const primary = await this.listSecretKeys(true)

    const handles = primary.map(rec=>{
      return Hoek.reach(rec, 'uid.email')
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
    return await exec(cmdStr, {
      cwd,
      env: {
        GNUPGHOME: this.homedir
      }
    })
  }



  static getKeyBySubKeyId(list, sub_key_id, subField = 'ssb'){
    debug('getKeyBySubKeyId', sub_key_id)
    let result = null
    list.map( key => {

      let subKeys = key[subField]

      if(!Array.isArray(subKeys)){
        subKeys = [subKeys]
      }

      subKeys.map( subkey => {

        const keyIdLen = subkey.keyid.length
        const matchIdx = sub_key_id.toLowerCase().indexOf(subkey.keyid.toLowerCase())
        const matchLen = (matchIdx > -1) ? sub_key_id.length - matchIdx : 0

        if( keyIdLen == matchLen ){
          result = key
        }
      })
    } )

    return result
  }

  static getKeyByField(list, field, value){
    let result = []
    list.map( key => {

      const fieldVal = Hoek.reach(key, field)

      if(fieldVal == value){
        result.push(key)
      }
    })

    return result
  }
  
  static isKeyFromCard(key, cardInfo){
    debug('isKeyFromCard', key, cardInfo)
    let snMatch = false

    const cardSN = cardInfo.Reader[ cardInfo.Reader.length - 3 ]

    debug('cardSN', cardSN)

    key.ssb.map( subkey =>{
      const sn = subkey.token_sn

      if(sn == cardSN){
        snMatch = true
      }
    })

    return snMatch

  }


  static getSubKeyIdByCapability(key, cap, subField='ssb'){
    debug('getSubKeyIdByCapability', key, cap, subField)
    const ids = []
    const subKeys = key[subField]

    subKeys.map( subkey => {
      if(subkey.key_cap == cap){
        ids.push(subkey.keyid)
      }
    })

    return ids
  }
}

module.exports = KeyChain