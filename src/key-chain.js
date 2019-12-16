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

  /**
   * A GPG keychain
   * @class
   * @constructor
   * @param {string} homedir Path to use as GPG homedir. Defaults to a tmp directory. See {@link https://github.com/raszi/node-tmp/blob/master/README.md|node-tmp} for more info on temp folder creation.
   */

  constructor(homedir){
    this.homedir = homedir
    this.temp = null
  }

  /**
   * Open or create the GPG keychain
   * @method
   */

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


  /**
   * Call a GPG command
   * @method
   * @param {string} input STDIN input text
   * @param {Array(string)} args Command line arguments
   * @param {boolean} nonbatch Do not use the `--batch` flag
   * @returns {ExecResult}
   */
  async call(input, args, nonbatch=false){
    const gpgArgs = ['--homedir', this.homedir, (nonbatch!=true) ? '--batch' : undefined  ].concat(args)

    debug('call -', gpgArgs)
    const result = await exec('gpg '+gpgArgs.join(' '), undefined, input)

    return result
  }

  /**
   * Check if a secure card is inserted
   * @method
   * @returns {boolean}
   */
  async hasCard(){
    
    try{
      const cardStatus = await this.cardStatus()
    }
    catch(err){
      return false
    }

    return true
  }

  /**
   * Is the inserted secure card set to owner trust
   * @method
   * @returns {boolean}
   */
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

  /**
   * Retrieve secure card metadata
   * @method
   * @returns {Object}
   */
  async cardStatus(){
    const command = ['--card-status', '--with-colons', '--with-fingerprint']
    const list = (await this.call('', command)).stdout.toString()

    const status = GPGParser.parseReaderColons(list)
    debug('card status', status)
    return status
  }

  /**
   * Trust the currently inserted secure card
   * @method
   */
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

  /**
   * Import the supplied key with owner trust
   * @method
   * @param {string} keyId Fingerprint/grip/email of desired key
   * @param {string} level Trust level code
   */
  async trustKey(keyId, level){
    debug('trust', keyId, level)
    const command = ['--import-ownertrust', ]

    const existingTrust = (await this.call('', ['--export-ownertrust'])).stdout.toString()

    const trust = '' + existingTrust + keyId+':' +level+ ':\n'

    const list = (await this.call(trust, command)).stdout.toString()

    
    debug(list)

    debug('trust = ', trust)
  }

  /**
   * Lookup keys. This uses the {@link KeyServerClient} rather than GPG to ensure we don't accidently modify the keychain
   * @method 
   * @param {string} text Search text {@link HKPIndexSchema}
   * @param {boolean} exact Exact matches only
   * @param {string} [server=KeyServerClient.Addresses.ubuntu]
   * @returns {string} Parsed csv-to-json search results
   */
  async lookupKey(text, exact=false, keyserver=KeyServerClient.Addresses.ubuntu){
    const hkpClient = new KeyServerClient(keyserver)
    
    const result = await hkpClient.search(text)

    if(result.length > 1 && result[0].type == 'info'){
      return result[1]
    }

    return result
  }

  /**
   * Recieve key specified by fingerprint
   * @method
   * @param {string} fingerprint Fingerpint/email/grip of key to recieve
   * @param {string} [server=hkps://keyserver.ubuntu.com:443]
   */
  async recvKey(fingerprint, server='hkps://keyserver.ubuntu.com:443'){
    const command = ['--keyserver', server, '--recv-keys', fingerprint]
    const list = (await this.call('', command)).stdout.toString()

    const status = GPGParser.parseReaderColons(list)
    debug('recv data', status)
  }

  /**
   * Transmit 
   * @param {string} [server=hkps://keyserver.ubuntu.com:443]
   * @param {string} fpr 
   */
  async sendKeys(fpr, server='hkps://keyserver.ubuntu.com:443'){
    const command = ['--keyserver', server, '--send-keys']

    if(fpr){
      command.push(fpr)
    }

    await this.call('', command)
    return
  }

  /**
   * Refresh keyring public keys from specified server
   * @param {string} [server=hkps://keyserver.ubuntu.com:443]
   */
  async refreshKeys(server='hkps://keyserver.ubuntu.com:443'){
    const command = ['--keyserver', server, '--refresh-keys']

    await this.call('', command)
    return
  }

  /**
   * Sign a key
   * @param {string} to 
   * @param {string} from 
   */
  async signKey(to, from){
    const command = ['--edit-key', to, 'sign']

    if(from){
      command.push('--local-user')
      command.push(from)
    }

    await this.call('', command)
    return
  }


  /**
   * Create public/private key pair
   * @method
   * @param {Object} options
   * @param {string} options.email
   * @param {string} options.name
   * @param {string} options.expire
   * @param {string} options.passphrase
   * @param {string} [options.keyType=RSA]
   * @param {string} [options.keySize=4096]
   * @param {string} [options.unattend=false]
   */
  async generateKey({email, name, expire=0, passphrase, keyType='RSA', keySize=4096, unattend=false}){
    const command = ['--generate-key']

    //! https://www.gnupg.org/documentation/manuals/gnupg/Unattended-GPG-key-generation.html
    let statements = 'Key-Type: ' + keyType + '\n' +
      'Key-Length: ' + keySize + '\n' +
      'Name-Real: ' + name + '\n' +
      'Name-Email: ' + email + '\n' +
      'Expire-Date: ' + expire + '\n'

    if (passphrase && passphrase.length > 0 && !unattend) {

      statements += 'Passphrase: ' + passphrase + '\n'

    } else if (unattend && !passphrase) {

      statements += '%no-protection' + '\n'

    } else {
      throw new Error('unsupported passphrase/unattend setting')
    }

    statements += '%commit' + '\n' + '%echo done' + '\n'

    const result = (await this.call(statements, command)).stdout.toString()

    debug('genkey', result)
  }

  /**
   * Encrypt, sign, and armor input
   * @method
   * @param {string} input 
   * @param {Array(string)} to 
   * @param {string} from 
   * @param {string} [trust=pgp]
   * @returns {string} ciphertext
   */
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

  /**
   * Decrypt cipher text
   * @method
   * @param {string} input 
   */
  async decrypt(input){
    const command = ['--decrypt']

    const result = (await this.call(input, command)).stdout.toString()

    debug('enc data', result)
    return result
  }

  /**
   * @method
   * @param {string} input 
   * @param {string} sender 
   */
  async verify(input, sender){
    throw new Error('not implemented')
    //const command = ['--logger-fd', '1', '--verify']
    const command = ['--list-packets']

    const result = (await this.call(input, command, true)).stdout.toString()

    debug('verify data', result)
    return result
  }

  /**
   * List of `uid.email` for every secret key with owner trust
   * @returns {Array(string)}
   */
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

  /**
   * List of secret keys
   * @param {boolean} ultimate Only list keys with owner trust
   * @returns {Array(Objects)} Parsed gpg output packets
   */
  async listSecretKeys(ultimate=true){
    const command = ['--list-secret-keys', '--with-colons', '--with-fingerprint']
    const list = (await this.call('', command)).stdout.toString()

    return GPGParser.parseColons(list).filter((record)=>{
      return record.type == 'sec' && (!ultimate ? true : ( record.validity == 'u' ))
    })
  }

  /**
   * List of public keys
   * @param {boolean} ultimate Only list keys with owner trust
   * @returns {Array(Objects)} Parsed gpg output packets
   */
  async listPublicKeys(ultimate=false){
    const command = ['--list-public-keys', '--with-colons', '--with-fingerprint']
    const list = (await this.call('', command)).stdout.toString()

    return GPGParser.parseColons(list).filter((record)=>{
      return record.type == 'pub' && (!ultimate ? true : ( record.validity == 'u' ))
    })
  }

  /**
   * Encrypt/decrypt gpgtar files
   * @param {Object} options
   * @property {string} cwd
   * @property {string} outputPath
   * @property {string} to
   * @property {string} sign
   * @property {string} encrypt
   * @property {string} decrypt
   * @property {string} extractPath
   * @property {string} inputPaths
   * @Returns {ExecResult}
   */
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



  /**
   * Find a key based on id of a sub-key
   * @param {Array(Object)} list List of parsed GPG output packets
   * @param {string} sub_key_id Sub key id to search for
   * @param {*} subField Subkey field (typically ssb or sub)
   * @returns {Object} Parsed key from GPG output packets
   */
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

  /**
   * Find a key by a field value
   * @param {Array(Object)} list List of parsed GPG output packets
   * @param {string} field Name/path to field
   * @param {string} value
   * @returns {Object} Parsed key from GPG output packets
   */
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
  
  /**
   * Check if the specified secure card matches the supplied key
   * @param {Object} key A parsed key with ssb field
   * @param {Object} cardInfo Card info from {@link KeyChain.cardStatus}
   */
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


  /**
   * Find a subkey id with specific capabilities
   * @param {Object} key 
   * @param {string} cap Capabilities (a, c, e, d)
   * @param {string} subField Field name/path
   * @returns {Array(string)} List of subkey ids
   */
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